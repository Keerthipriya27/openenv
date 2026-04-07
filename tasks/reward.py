import re


def _clamp(value, low, high):
    return max(low, min(high, value))


def _extract_ips(text):
    return set(re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", text or ""))


def _context_flags(current_log, real_attacker_ip, benign_ip):
    log_attention = current_log.lower()
    suspicious_signals = [
        "sql",
        "command injection",
        "brute-force",
        "flood",
        "401",
        "repeated",
        "exploitation",
        "credential stuffing",
        "union select",
    ]
    weak_signals = [
        "backup",
        "cdn",
        "scheduled",
        "probe",
        "health",
        "cache",
        "helpdesk reset",
        "batch report",
    ]

    current_ips = _extract_ips(current_log)
    current_contains_real = bool(real_attacker_ip and real_attacker_ip in current_ips)
    current_contains_benign = bool(benign_ip and benign_ip in current_ips)
    suspicious_context = any(token in log_attention for token in suspicious_signals)
    weak_context = any(token in log_attention for token in weak_signals)
    ambiguous_context = weak_context or (current_contains_benign and not current_contains_real)
    strong_context = current_contains_real and suspicious_context

    return {
        "current_ips": current_ips,
        "current_contains_real": current_contains_real,
        "current_contains_benign": current_contains_benign,
        "suspicious_context": suspicious_context,
        "weak_context": weak_context,
        "ambiguous_context": ambiguous_context,
        "strong_context": strong_context,
    }


def compute_reward(action, state):
    """
    Advanced reward shaping.
    - Correct step: +0.2 to +0.4
    - Wrong step: -0.1 to -0.3
    - Repeated useless action: extra penalty
    - Correct sequence bonus: +0.5
    - Final success: +1.0
    - Early completion bonus: +0.2
    - Final cumulative reward is tracked as capped [0.0, 1.0]
    """
    expected_sequence = state.get("expected_sequence", ["detect_threat", "classify_attack", "block_ip"])
    reward_profile = state.get("reward_profile", {})
    difficulty = state.get("difficulty", "medium").lower() if isinstance(state.get("difficulty", "medium"), str) else "medium"
    sequence_strict = bool(state.get("sequence_strict", False))
    allow_variation = bool(state.get("allow_sequence_variation", False))
    sequence_progress = int(state.get("sequence_progress", 0))
    max_steps = int(state.get("max_steps", 6))
    current_step = int(state.get("steps_taken", 0))
    history = list(state.get("action_history", []))
    current_log = str(state.get("current_log", ""))
    real_attacker_ip = state.get("real_attacker_ip")
    benign_ip = state.get("benign_ip")
    identified_target_ip = state.get("identified_target_ip")
    memory_required = bool(state.get("memory_required", difficulty == "hard"))

    context = _context_flags(current_log, real_attacker_ip, benign_ip)
    current_ips = context["current_ips"]
    current_contains_real = context["current_contains_real"]
    current_contains_benign = context["current_contains_benign"]
    suspicious_context = context["suspicious_context"]
    ambiguous_context = context["ambiguous_context"]
    strong_context = context["strong_context"]

    expected_next = None
    if sequence_progress < len(expected_sequence):
        expected_next = expected_sequence[sequence_progress]

    reward = 0.0
    action_is_correct_step = action == expected_next
    repeated_action = len(history) >= 2 and history[-1] == history[-2]
    wrong_order = action in expected_sequence and not action_is_correct_step

    correct_reward = float(reward_profile.get("correct", 0.35))
    wrong_reward = float(reward_profile.get("wrong", -0.2))
    repeat_penalty = float(reward_profile.get("repeat", -0.15))
    wrong_order_penalty = float(reward_profile.get("wrong_order", -0.18))
    sequence_bonus = float(reward_profile.get("sequence_bonus", 0.5))
    success_bonus = float(reward_profile.get("success_bonus", 1.0))
    early_bonus = float(reward_profile.get("early_bonus", 0.2))
    step_limit_penalty = float(reward_profile.get("step_limit_penalty", -0.2))
    efficiency_bonus = float(reward_profile.get("efficiency_bonus", 0.1))
    weak_detect_penalty = float(reward_profile.get("weak_detect_penalty", -0.05))
    wrong_target_penalty = float(reward_profile.get("wrong_target_penalty", -0.15))
    context_ignore_penalty = float(reward_profile.get("context_ignore_penalty", -0.05))
    memory_miss_penalty = float(reward_profile.get("memory_miss_penalty", -0.04))
    initial_ignore_bonus = float(reward_profile.get("initial_ignore_bonus", 0.0))
    confirmed_target_bonus = float(reward_profile.get("confirmed_target_bonus", 0.0))

    if action_is_correct_step:
        reward += correct_reward
        state["sequence_progress"] = sequence_progress + 1

        if action == "detect_threat":
            state["detected"] = True
            state["threat_detected"] = True
            state["previous_action_result"] = "threat detected"
            state["system_status"] = "under_investigation"
        elif action == "classify_attack":
            state["classified"] = True
            state["attack_type"] = state.get("attack_type_expected") or state.get("attack_type") or "identified"
            if current_contains_real:
                state["identified_target_ip"] = real_attacker_ip
                reward += confirmed_target_bonus
            elif current_ips:
                state["identified_target_ip"] = next(iter(current_ips))
            state["previous_action_result"] = "attack classified"
            state["system_status"] = "incident_confirmed"
        elif action == "block_ip":
            state["blocked"] = True
            state["ip_blocked"] = True
            blocked_target = state.get("identified_target_ip") or identified_target_ip or next(iter(current_ips), None)
            if not state.get("classified", False):
                reward += wrong_target_penalty
            elif blocked_target and real_attacker_ip and blocked_target != real_attacker_ip:
                reward += wrong_target_penalty
            elif current_contains_benign and not current_contains_real:
                reward += wrong_target_penalty
            elif current_contains_real:
                reward += confirmed_target_bonus
            state["previous_action_result"] = "source blocked"
            state["system_status"] = "contained"
    else:
        reward += wrong_reward
        if wrong_order:
            if sequence_strict:
                reward += wrong_order_penalty
            elif allow_variation:
                reward += wrong_order_penalty / 2
        if action == "ignore":
            if difficulty == "hard" and sequence_progress == 0 and ambiguous_context and not suspicious_context:
                reward += initial_ignore_bonus
                state["previous_action_result"] = "ignored weak evidence"
                state["system_status"] = "monitoring"
            elif suspicious_context:
                reward += context_ignore_penalty
                state["previous_action_result"] = "ignored suspicious context"
                state["system_status"] = "risk_increased"
            else:
                reward -= 0.05
                state["previous_action_result"] = "no-op ignore"
                state["system_status"] = "monitoring"
        else:
            state["previous_action_result"] = "out-of-order or incorrect action"

    if difficulty == "hard":
        if action == "detect_threat" and ambiguous_context and not strong_context and not action_is_correct_step:
            reward += weak_detect_penalty
            state["previous_action_result"] = "premature detection on weak evidence"

        if action == "block_ip" and state.get("sequence_progress", 0) < 2:
            reward += wrong_target_penalty
            state["previous_action_result"] = "blocked before confirming target"
            state["system_status"] = "wrong_target_high_risk"

        if action == "block_ip" and not state.get("classified", False):
            reward += wrong_target_penalty
            state["previous_action_result"] = "blocked without classification"

        if action == "classify_attack" and memory_required and not action_is_correct_step:
            if ambiguous_context and not strong_context:
                reward += memory_miss_penalty

        if memory_required and action == "classify_attack" and not state.get("detected", False):
            reward += memory_miss_penalty

        if action == "classify_attack" and sequence_progress == 0:
            reward += wrong_order_penalty * 1.2

        if action == "block_ip" and current_step == 1:
            reward += wrong_order_penalty * 1.5

    if repeated_action:
        reward += repeat_penalty
        state["previous_action_result"] = "repeated useless action"

    if state.get("sequence_progress", 0) >= len(expected_sequence) and not state.get("sequence_completed", False):
        state["sequence_completed"] = True
        reward += sequence_bonus

    if state.get("sequence_completed", False) and state.get("blocked", False):
        if not state.get("task_success", False):
            reward += success_bonus
            state["task_success"] = True

            if current_step <= max(len(expected_sequence) + 1, 4):
                reward += early_bonus

    if action not in expected_sequence and action != "ignore":
        reward += -0.05 if not sequence_strict else -0.1

    if current_step >= max_steps:
        reward += step_limit_penalty
        if difficulty == "hard":
            reward += -0.05
        elif difficulty == "medium":
            reward += -0.03

    if current_step <= len(expected_sequence):
        reward += efficiency_bonus * 0.25

    if sequence_strict and current_step > len(expected_sequence):
        reward += -0.08
    elif allow_variation and current_step > len(expected_sequence):
        reward += -0.03

    reward = _clamp(reward, -0.3, 1.0)

    reward_total = float(state.get("reward_total", 0.0)) + reward
    state["reward_total"] = reward_total
    state["reward_total_capped"] = _clamp(reward_total, 0.0, 1.0)

    return reward, state