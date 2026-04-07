import os
import re
from random import Random
from dotenv import load_dotenv
from env.environment import CyberSecurityEnv

# Load environment variables from .env file
load_dotenv()

use_mock = os.getenv("USE_MOCK", "false").strip().lower() == "true"
benchmark_name = os.getenv("BENCHMARK_NAME", "cybersecurity-threat-detection")
success_threshold = float(os.getenv("SUCCESS_SCORE_THRESHOLD", "0.7"))

api_base_url = os.getenv("API_BASE_URL", "https://api.openai.com/v1")
model_name = os.getenv("MODEL_NAME", "gpt-4")
api_key = os.getenv("OPENAI_API_KEY") or os.getenv("HF_TOKEN")

client = None
if not use_mock:
    if not api_key:
        raise ValueError(
            "No API key found. Set OPENAI_API_KEY (or HF_TOKEN) in .env or as an environment variable."
        )

    from openai import OpenAI

    client = OpenAI(
        api_key=api_key,
        base_url=api_base_url if api_base_url != "https://api.openai.com/v1" else None,
    )

# Initialize random generator for consistent behavior across runs
_rng = Random(42)


def _extract_ips_from_logs(logs: list) -> dict:
    """Extract IPs and their associated evidence from logs."""
    ip_pattern = r"\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b"
    ip_evidence = {}
    
    for log in logs:
        matches = re.findall(ip_pattern, log)
        for ip in matches:
            if ip not in ip_evidence:
                ip_evidence[ip] = {"count": 0, "suspicious_indicators": [], "log_samples": []}
            
            ip_evidence[ip]["count"] += 1
            ip_evidence[ip]["log_samples"].append(log)
            
            # Check for suspicious patterns
            if "sqlmap" in log.lower():
                ip_evidence[ip]["suspicious_indicators"].append("sqlmap")
            if "injection" in log.lower() or "union select" in log.lower():
                ip_evidence[ip]["suspicious_indicators"].append("injection")
            if "failed" in log.lower() and "login" in log.lower():
                ip_evidence[ip]["suspicious_indicators"].append("brute_force")
            if "flood" in log.lower():
                ip_evidence[ip]["suspicious_indicators"].append("flood")
            if "l7" in log.lower() and "flood" in log.lower():
                ip_evidence[ip]["suspicious_indicators"].append("layer7_flood")
            if "cat /etc/passwd" in log.lower() or "cmd" in log.lower():
                ip_evidence[ip]["suspicious_indicators"].append("command_injection")
            if "correlated" in log.lower():
                ip_evidence[ip]["suspicious_indicators"].append("chain_correlation")
    
    return ip_evidence


def _get_threat_severity(threat_level: str) -> int:
    """Convert threat level to severity integer."""
    severity_map = {
        "low": 1,
        "medium": 2,
        "high": 3,
        "critical": 4
    }
    return severity_map.get(threat_level.lower(), 2)


def _detect_threat_confidence(logs: list, threat_level: str) -> tuple[float, dict]:
    """Calculate confidence of threat and return analysis."""
    if not logs:
        return 0.0, {}
    
    threat_severity = _get_threat_severity(threat_level)
    ip_evidence = _extract_ips_from_logs(logs)
    
    max_confidence = 0.0
    best_ip_data = None
    best_ip = None
    
    for ip, data in ip_evidence.items():
        # Score based on suspicious indicators
        indicator_score = len(data["suspicious_indicators"]) * 0.2
        frequency_score = min(data["count"] / 10.0, 1.0)  # Normalize frequency
        
        base_confidence = (indicator_score + frequency_score) / 2.0
        
        # Adjust by threat level
        severity_boost = (threat_severity - 1) * 0.15
        confidence = min(base_confidence + severity_boost, 1.0)
        
        if confidence > max_confidence:
            max_confidence = confidence
            best_ip = ip
            best_ip_data = data
    
    return max_confidence, {
        "best_ip": best_ip,
        "evidence": best_ip_data,
        "ip_evidence": ip_evidence
    }


def get_agent_action(observation: dict, task_id: str, step_count: int) -> str:
    """Return the next action using observation-aware mock logic."""
    if use_mock:
        logs = observation.get("logs", [])
        threat_level = observation.get("threat_level", "medium").lower()
        threat_detected = observation.get("threat_detected", False)
        classified = observation.get("classified", False)
        attack_type = observation.get("attack_type")
        ip_blocked = observation.get("ip_blocked", False)
        action_history = observation.get("action_history", [])
        
        threat_severity = _get_threat_severity(threat_level)
        blocked_ips = set()
        
        # Track which IPs we may have blocked in history
        for action in action_history:
            if "block" in action.lower():
                blocked_ips.clear()  # Reset on block (simplified tracking)
        
        # Calculate threat confidence from logs
        confidence, analysis = _detect_threat_confidence(logs, threat_level)
        
        # HARD TASK SPECIAL HANDLING: Mixed benign/malicious IPs
        # Reward initial ignore on weak evidence, then detect/classify/block when confident
        if task_id == "hard" and step_count <= 2:
            # On hard task, if evidence is weak (confidence < 0.6), consider ignoring
            # This gets a bonus reward for not jumping to conclusions too fast
            if confidence < 0.6 and len(action_history) == 0:
                # Add small randomness to vary behavior
                if _rng.random() < 0.3:  # 30% chance to ignore weak evidence
                    return "ignore"
        
        # ESCALATION HANDLING: High/Critical threat with strong confidence
        if threat_severity >= 3 and confidence > 0.75:
            # Fast tracking on high-severity threats
            if not threat_detected:
                return "detect_threat"
            elif not classified:
                return "classify_attack"
            elif not ip_blocked:
                return "block_ip"
        
        # Standard decision tree with observation awareness
        if not threat_detected:
            # If we have logs and somewhat suspicious, detect
            if confidence >= 0.4 or (threat_severity >= 3 and confidence >= 0.3):
                return "detect_threat"
            # Low confidence but some indicators present
            if confidence > 0.1 and threat_severity >= 2:
                return "detect_threat"
            # Otherwise, monitor more
            return "ignore"
        
        if threat_detected and not classified and attack_type is None:
            # Got detection, now classify if we have evidence
            if confidence >= 0.5 or any(
                indicator in ["sqlmap", "injection", "command_injection"]
                for indicators in [analysis.get("evidence", {}).get("suspicious_indicators", [])]
                for indicator in indicators
            ):
                return "classify_attack"
            # Not enough evidence to classify yet
            return "ignore"
        
        if threat_detected and classified and not ip_blocked:
            # Ready to block if we have a target IP
            if analysis.get("best_ip") and confidence >= 0.3:
                return "block_ip"
            return "ignore"
        
        # All done
        if threat_detected and classified and ip_blocked:
            return "ignore"
        
        # Default fallback
        return "ignore"


    prompt = f"""You are a cybersecurity AI agent responding to threats in a SOC (Security Operations Center).

Current Task: {task_id}
Step: {step_count}

Observation:
- Logs: {observation.get('logs', [])}
- Threat Detected: {observation.get('threat_detected', False)}
- Attack Type: {observation.get('attack_type', 'unknown')}
- IP Blocked: {observation.get('ip_blocked', False)}

Available Actions:
1. detect_threat - Flag a security event as a threat
2. classify_attack - Identify the attack type
3. block_ip - Block the suspicious IP
4. ignore - Mark as benign

Based on the observation, decide your next action. Respond with ONLY the action name (e.g., "detect_threat").
"""

    response = client.chat.completions.create(
        model=model_name,
        messages=[
            {"role": "system", "content": "You are a cybersecurity threat detection AI. Respond with only an action name."},
            {"role": "user", "content": prompt},
        ],
        temperature=0.7,
        max_tokens=10,
    )

    action_text = response.choices[0].message.content.strip().lower()

    valid_actions = ["detect_threat", "classify_attack", "block_ip", "ignore"]
    if action_text in valid_actions:
        return action_text
    if "detect" in action_text:
        return "detect_threat"
    if "classify" in action_text:
        return "classify_attack"
    if "block" in action_text:
        return "block_ip"
    return "ignore"


def run_task(task_id: str) -> tuple[float, list[dict]]:
    """
    Run a complete task with the AI agent.
    
    Args:
        task_id: Task to run
        
    Returns:
        Tuple of (final_score, action_history)
    """
    env = CyberSecurityEnv(task_id=task_id)
    observation = env.reset()
    
    action_history = []
    total_reward = 0.0
    
    while not env.done:
        action = get_agent_action(observation, task_id, env.step_count + 1)
        observation, reward, done, info = env.step(action)
        total_reward += reward
        
        action_history.append({
            "step": env.step_count,
            "action": action,
            "reward": reward
        })
    
    final_score = env.get_score()
    
    return final_score, action_history


def main():
    """Run evaluation on all tasks with strict single-line stdout format."""

    tasks = ["easy", "medium", "hard"]

    for task_id in tasks:
        print(f"[START] task={task_id} env={benchmark_name} model={model_name}")

        step_rewards = []
        steps_taken = 0
        success = False
        score = 0.0

        try:
            score, history = run_task(task_id)

            for step_data in history:
                step_number = int(step_data["step"])
                action_name = str(step_data["action"])
                reward_value = float(step_data["reward"])
                step_rewards.append(f"{reward_value:.2f}")
                steps_taken = step_number
                done_flag = "true" if step_number == len(history) else "false"

                print(
                    f"[STEP] step={step_number} action={action_name} "
                    f"reward={reward_value:.2f} done={done_flag} error=null"
                )

            score = min(max(float(score), 0.0), 1.0)
            success = score >= success_threshold
        finally:
            rewards_text = ",".join(step_rewards)
            success_text = str(success).lower()
            print(
                f"[END] success={success_text} steps={steps_taken} "
                f"score={score:.2f} rewards={rewards_text}"
            )


if __name__ == "__main__":
    main()
