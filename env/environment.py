from copy import deepcopy
from datetime import datetime, timedelta
from random import Random
from typing import Any, Dict, Tuple, Optional
from tasks.tasks import tasks
from tasks.reward import compute_reward
from tasks.grader import grade_task
from models import Action


class CyberSecurityEnv:
    """OpenEnv-compliant cybersecurity simulation environment."""
    
    def __init__(self, task_id: Optional[str] = None, seed: int = 42, debug: bool = False):
        self.task_id = task_id
        self.debug = debug
        self.current_task = None
        self._state = {}
        self.history = []
        self.done = False
        self.step_count = 0
        self.max_steps = 6
        self._task_cursor = 0
        self._rng = Random(seed)
        
    def reset(self) -> Dict[str, Any]:
        """Load a new task and reset environment."""
        if self.task_id:
            self.current_task = next((t for t in tasks if t["id"] == self.task_id), None)
        else:
            self.current_task = tasks[self._task_cursor % len(tasks)]
            self._task_cursor += 1
        
        if not self.current_task:
            raise ValueError(f"Task {self.task_id} not found")
        
        self._state = deepcopy(self.current_task["initial_state"])
        self._state["task_id"] = self.current_task.get("id", "unknown")
        self._state["difficulty"] = self.current_task.get("difficulty", "medium")
        self._state["expected_sequence"] = list(self.current_task.get("expected_sequence", ["detect_threat", "classify_attack", "block_ip"]))
        self._state["threat_level"] = self.current_task.get("threat_level", "medium")
        self._state["attack_type_expected"] = self.current_task.get("attack_type", "Unknown")
        self._state["max_steps"] = int(self.current_task.get("max_steps", self.max_steps))
        self._state["sequence_strict"] = bool(self.current_task.get("sequence_strict", False))
        self._state["allow_sequence_variation"] = bool(self.current_task.get("allow_sequence_variation", False))
        self._state["reward_profile"] = deepcopy(self.current_task.get("reward_profile", self._state.get("reward_profile", {})))

        generated_logs = self._generate_logs_for_task(self.current_task)
        self._state["all_logs"] = generated_logs
        self._state["logs"] = generated_logs
        self._state["current_log_index"] = 0
        self._state["current_log"] = generated_logs[0] if generated_logs else ""
        self._state["hint"] = self.current_task.get("hint", "")

        self.history = []
        self.done = False
        self.step_count = 0
        self.max_steps = self._state["max_steps"]

        return self._build_observation()
    
    def step(self, action: str | Action) -> Tuple[Dict[str, Any], float, bool, Dict[str, Any]]:
        """Execute action and return (observation, reward, done, info)."""
        if self.done or self.current_task is None:
            raise RuntimeError("Environment not initialized. Call reset() first.")

        if isinstance(action, Action):
            action = action.action_type

        valid_actions = {"detect_threat", "classify_attack", "block_ip", "ignore"}
        if action not in valid_actions:
            action = "ignore"
        
        self._state["steps_taken"] = int(self._state.get("steps_taken", 0)) + 1
        self._state["steps"] = self._state["steps_taken"]
        self._state.setdefault("action_history", []).append(action)

        reward, self._state = compute_reward(action, self._state)
        self.history.append(action)
        self.step_count += 1

        self._advance_log_cursor()
        
        # Check termination conditions with step-limit penalty.
        if self._state.get("task_success"):
            self.done = True
        elif self.step_count >= self.max_steps:
            self.done = True
            if not self._state.get("task_success"):
                reward = max(-0.3, reward - 0.2)
                self._state["previous_action_result"] = "episode ended: max steps exceeded"
                self._state["system_status"] = "escalated_to_human"
        
        info = {
            "task_id": self.current_task["id"],
            "step": self.step_count,
            "action": action,
            "threat_detected": self._state.get("threat_detected", False),
            "attack_type": self._state.get("attack_type"),
            "ip_blocked": self._state.get("ip_blocked", False),
            "expected_next": self._expected_next_action(),
            "sequence_progress": self._state.get("sequence_progress", 0),
            "max_steps": self.max_steps,
            "task_success": self._state.get("task_success", False),
        }

        if self.debug:
            info["debug_state"] = self.state()
        
        observation = self._build_observation()
        
        return observation, reward, self.done, info
    
    def state(self) -> Dict[str, Any]:
        """Return full internal state."""
        if self.current_task is None:
            raise RuntimeError("Environment not initialized. Call reset() first.")
        return deepcopy(self._state)
    
    def get_score(self) -> float:
        """Calculate final score for the episode."""
        if not self.current_task:
            return 0.0
        return grade_task(
            self.history,
            expected_sequence=self._state.get("expected_sequence", ["detect_threat", "classify_attack", "block_ip"]),
            max_steps=self.max_steps,
        )

    def _build_observation(self) -> Dict[str, Any]:
        """Observation includes log message, status, previous result, and optional hints."""
        observation = {
            "logs": self._state.get("all_logs", []),
            "log_message": self._state.get("current_log", ""),
            "threat_detected": self._state.get("threat_detected", False),
            "attack_type": self._state.get("attack_type"),
            "ip_blocked": self._state.get("ip_blocked", False),
            "steps": self._state.get("steps_taken", 0),
            "detected": self._state.get("detected", False),
            "classified": self._state.get("classified", False),
            "blocked": self._state.get("blocked", False),
            "action_history": list(self._state.get("action_history", [])),
            "system_status": self._state.get("system_status", "monitoring"),
            "previous_action_result": self._state.get("previous_action_result", "none"),
            "threat_level": self._state.get("threat_level", "unknown"),
            "difficulty": self._state.get("difficulty", "unknown"),
            "task_id": self._state.get("task_id", "unknown"),
        }

        if self.current_task and self.current_task.get("id") == "easy":
            observation["hint"] = self._state.get("hint", "")

        return observation

    def _expected_next_action(self) -> Optional[str]:
        sequence = self._state.get("expected_sequence", [])
        progress = int(self._state.get("sequence_progress", 0))
        if progress < len(sequence):
            return sequence[progress]
        return None

    def _advance_log_cursor(self) -> None:
        logs = self._state.get("all_logs", [])
        if not logs:
            return

        current_idx = int(self._state.get("current_log_index", 0))
        if current_idx < len(logs) - 1:
            current_idx += 1
        self._state["current_log_index"] = current_idx
        self._state["current_log"] = logs[current_idx]

    def _generate_logs_for_task(self, task: Dict[str, Any]) -> list[str]:
        templates = list(task.get("log_templates", []))
        misleading = list(task.get("misleading_templates", []))

        base_time = datetime(2026, 4, 5, 10, 15, 0)
        ip_candidates = [
            "192.168.1.10",
            "185.199.110.153",
            "45.77.23.9",
            "103.21.244.12",
            "198.51.100.63",
        ]
        users = ["admin", "finance", "support", "svc-api", "root"]
        request_types = ["GET", "POST", "PUT"]
        user_agents = ["curl/8.1", "python-requests/2.32", "Mozilla/5.0", "sqlmap/1.7"]
        endpoints = ["/login", "/api/v1/search", "/auth/session", "/checkout", "/admin"]

        src_ip = self._rng.choice(ip_candidates)
        logs = []

        for idx, template in enumerate(templates):
            ts = (base_time + timedelta(seconds=idx * self._rng.randint(25, 70))).strftime("%Y-%m-%d %H:%M:%S")
            rendered = template.format(
                timestamp=ts,
                ip=src_ip,
                user=self._rng.choice(users),
                request_type=self._rng.choice(request_types),
                ua=self._rng.choice(user_agents),
                endpoint=self._rng.choice(endpoints),
                fail_count=self._rng.randint(3, 10),
                rate=self._rng.randint(300, 1400),
            )
            logs.append(rendered)

        if task.get("id") == "hard":
            inserted = []
            for idx, template in enumerate(misleading):
                ts = (base_time + timedelta(seconds=idx * self._rng.randint(20, 50))).strftime("%Y-%m-%d %H:%M:%S")
                inserted.append(template.format(timestamp=ts))

            for entry in inserted:
                pos = self._rng.randint(0, len(logs))
                logs.insert(pos, entry)
        elif misleading:
            ts = (base_time + timedelta(seconds=17)).strftime("%Y-%m-%d %H:%M:%S")
            logs.append(misleading[0].format(timestamp=ts))

        return logs
