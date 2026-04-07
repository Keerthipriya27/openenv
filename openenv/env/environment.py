from __future__ import annotations
from datetime import datetime, timedelta
from random import Random
from typing import Any

from pydantic import BaseModel, Field, field_validator


class Observation(BaseModel):
	event_type: str
	user: str
	ip_address: str
	status: str
	timestamp: str
	anomaly_score: float = Field(ge=0.0, le=1.0)


class Action(BaseModel):
	action_type: str

	@field_validator("action_type")
	@classmethod
	def validate_action_type(cls, value: str) -> str:
		allowed = {"flag", "ignore", "monitor", "block_ip"}
		if value not in allowed:
			raise ValueError(f"action_type must be one of {sorted(allowed)}")
		return value


class Reward(BaseModel):
	value: float


class CyberEnv:
	def __init__(self, num_logs: int = 120, seed: int | None = None) -> None:
		self.history = []
		self.num_logs = max(10, num_logs)
		self._rng = Random(seed)

		self._users = [
			"alice",
			"bob",
			"charlie",
			"dana",
			"eve",
			"frank",
			"grace",
			"heidi",
			"svc_backup",
			"admin",
		]
		self._normal_ips = [
			"10.0.2.14",
			"10.0.2.18",
			"10.0.3.22",
			"10.1.10.5",
			"172.16.4.9",
			"172.16.4.21",
			"192.168.1.45",
			"192.168.1.77",
		]
		self._suspicious_ips = [
			"45.33.12.91",
			"89.144.67.203",
			"103.21.244.12",
			"185.220.101.7",
			"198.51.100.63",
			"203.0.113.188",
		]

		self.logs: list[Observation] = []
		self.current_step: int = 0
		self.done: bool = False
		self._initialized: bool = False
		self._current_observation: Observation | None = None
		self.episode_id: int = 0

		self._ip_failed_attempts: dict[str, int] = {}
		self._user_failed_attempts: dict[str, int] = {}

	def reset(self) -> Observation:
		self.history = []
		self.episode_id += 1
		self.logs = self._generate_logs()
		if not self.logs:
			raise RuntimeError("Log generation produced no observations")
		self.current_step = 0
		self.done = False
		self._initialized = True
		self._current_observation = self.logs[0]
		return self._current_observation

	def state(self) -> Observation:
		if not self._initialized:
			return self.reset()
		if self._current_observation is None:
			self._current_observation = self.logs[self.current_step]
		return self._current_observation

	def step(self, action: Action) -> tuple[Observation, float, bool, dict[str, Any]]:
		if not isinstance(action, Action):
			raise TypeError("step(action) expects an Action object")
		if not self._initialized or self._current_observation is None:
			raise RuntimeError("Environment is not initialized. Call reset() before step().")

		previous_step = self.current_step

		if not self.done:
			self.current_step += 1
			if self.current_step >= len(self.logs):
				self.done = True
				self.current_step = len(self.logs) - 1

		self._current_observation = self.logs[self.current_step]
		observation = self._current_observation

		# 🔥 ADD HISTORY (IMPORTANT)
		if not hasattr(self, "history"):
			self.history = []
		self.history.append(action.action_type)

		# 🔥 REWARD LOGIC (MAIN FIX)
		reward = 0.0

		if observation.anomaly_score > 0.7:
			if action.action_type == "flag":
				reward += 2.0
			elif action.action_type == "block_ip":
				reward += 2.5
				self.done = True
			else:
				reward -= 2.0

		elif observation.anomaly_score < 0.3:
			if action.action_type == "ignore":
				reward += 1.0
			else:
				reward -= 1.0

		else:
			if action.action_type == "monitor":
				reward += 0.5
			else:
				reward -= 0.5

		# 🔥 small penalty to avoid loops
		reward -= 0.1

		# 🔥 action effect (keep yours)
		action_effect = "no_effect"
		if observation.anomaly_score > 0.7 and action.action_type == "flag":
			action_effect = "correct_detection"
		elif observation.anomaly_score < 0.3 and action.action_type == "ignore":
			action_effect = "correct_ignore"
		elif action.action_type == "block_ip":
			action_effect = "preventive_action"

		remaining_steps = max(0, len(self.logs) - 1 - self.current_step)

		# 🔥 FINAL SCORE (GRADER)
		final_score = None
		if self.done:
			score = 0.0
			if "flag" in self.history:
				score += 0.3
			if "block_ip" in self.history:
				score += 0.4
			if "monitor" in self.history:
				score += 0.2
			if len(self.history) <= 3:
				score += 0.1
			final_score = min(score, 1.0)

		info = {
			"step": self.current_step,
			"previous_step": previous_step,
			"total_logs": len(self.logs),
			"episode_id": self.episode_id,
			"action_type": action.action_type,
			"action_effect": action_effect,
			"event_type": observation.event_type,
			"status": observation.status,
			"anomaly_score": observation.anomaly_score,
			"remaining_steps": remaining_steps,
			"done": self.done,
			"final_score": final_score
		}

		return observation, reward, self.done, info
	def _generate_logs(self) -> list[Observation]:
		logs: list[Observation] = []
		self._ip_failed_attempts = {}
		self._user_failed_attempts = {}

		current_time = datetime.utcnow() - timedelta(minutes=self.num_logs * 2)
		users = self._users

		for _ in range(self.num_logs):
			current_time += timedelta(seconds=self._rng.randint(20, 180))
			user = self._rng.choice(users)

			ip_pool = self._normal_ips + self._suspicious_ips
			weights = [0.11] * len(self._normal_ips) + [0.02] * len(self._suspicious_ips)
			ip_address = self._rng.choices(ip_pool, weights=weights, k=1)[0]

			roll = self._rng.random()
			if roll < 0.42:
				event_type = "login_success"
				status = "success"
				self._ip_failed_attempts[ip_address] = 0
				self._user_failed_attempts[user] = 0
			elif roll < 0.70:
				event_type = "login_failure"
				status = "failed"
				self._ip_failed_attempts[ip_address] = self._ip_failed_attempts.get(ip_address, 0) + 1
				self._user_failed_attempts[user] = self._user_failed_attempts.get(user, 0) + 1
			elif roll < 0.82:
				event_type = "sensitive_file_access"
				status = "warning"
			else:
				event_type = "suspicious_ip_access"
				status = "alert"

			repeated_failures = self._ip_failed_attempts.get(ip_address, 0)
			if event_type == "login_failure" and repeated_failures >= 3:
				event_type = "brute_force_attempt"
				status = "alert"

			anomaly_score = self._compute_anomaly_score(
				event_type=event_type,
				user=user,
				ip_address=ip_address,
				repeated_failures=repeated_failures,
			)

			logs.append(
				Observation(
					event_type=event_type,
					user=user,
					ip_address=ip_address,
					status=status,
					timestamp=current_time.isoformat() + "Z",
					anomaly_score=anomaly_score,
				)
			)

		return logs

	def _compute_anomaly_score(
		self,
		event_type: str,
		user: str,
		ip_address: str,
		repeated_failures: int,
	) -> float:
		base_scores = {
			"login_success": 0.05,
			"login_failure": 0.30,
			"brute_force_attempt": 0.90,
			"suspicious_ip_access": 0.78,
			"sensitive_file_access": 0.62,
		}
		score = base_scores.get(event_type, 0.10)

		if repeated_failures >= 2:
			score += min(0.20, repeated_failures * 0.04)

		if ip_address in self._suspicious_ips:
			score += 0.12

		high_value_users = {"admin", "svc_backup"}
		if event_type == "sensitive_file_access" and user not in high_value_users:
			score += 0.15

		# Keep scores realistic while avoiding deterministic values.
		score += self._rng.uniform(-0.03, 0.05)

		return max(0.0, min(1.0, round(score, 4)))


__all__ = ["Observation", "Action", "Reward", "CyberEnv"]
