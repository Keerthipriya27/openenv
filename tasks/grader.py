def _clamp(value, low, high):
    return max(low, min(high, value))


def _ordered_match_count(history, expected_sequence):
    idx = 0
    for action in history:
        if idx < len(expected_sequence) and action == expected_sequence[idx]:
            idx += 1
    return idx


def grade_task(history, expected_sequence=None, max_steps=6):
    """
    Deterministic score in [0.0, 1.0] based on:
    - correctness of actions
    - order of actions
    - efficiency (fewer steps is better)
    Partial credit is provided for correct actions in wrong order.
    """
    if expected_sequence is None:
        expected_sequence = ["detect_threat", "classify_attack", "block_ip"]

    if max_steps <= 5:
        difficulty = "easy"
    elif max_steps == 6:
        difficulty = "medium"
    else:
        difficulty = "hard"

    history = list(history or [])
    expected_set = set(expected_sequence)
    unique_history = []
    for action in history:
        if action not in unique_history:
            unique_history.append(action)

    correct_unique = sum(1 for action in expected_set if action in history)
    correctness_score = correct_unique / len(expected_sequence)

    ordered_matches = _ordered_match_count(history, expected_sequence)
    order_score = ordered_matches / len(expected_sequence)

    if difficulty == "medium" and ordered_matches < len(expected_sequence) and correctness_score >= 2 / len(expected_sequence):
        order_score *= 0.9
    elif difficulty == "hard" and ordered_matches < len(expected_sequence):
        order_score *= 0.65

    if len(history) > len(expected_sequence):
        if difficulty == "easy":
            correctness_score *= 0.96
        elif difficulty == "medium":
            correctness_score *= 0.90
        else:
            correctness_score *= 0.82

    steps_taken = max(1, len(history))
    baseline = len(expected_sequence)
    if steps_taken <= baseline:
        efficiency_score = 1.0
    else:
        overflow = steps_taken - baseline
        efficiency_score = _clamp(1.0 - (overflow / max(1, max_steps)), 0.0, 1.0)
        if difficulty == "hard":
            efficiency_score *= 0.85
        elif difficulty == "medium":
            efficiency_score *= 0.92

    redundant_actions = max(0, steps_taken - len(unique_history))
    if difficulty == "easy":
        redundancy_penalty = min(0.08, 0.02 * redundant_actions)
    elif difficulty == "medium":
        redundancy_penalty = min(0.14, 0.035 * redundant_actions)
    else:
        redundancy_penalty = min(0.22, 0.05 * redundant_actions)

    wrong_order_penalty = 0.0
    if ordered_matches < len(expected_sequence):
        if difficulty == "easy":
            wrong_order_penalty = 0.03 if len(history) <= len(expected_sequence) + 1 else 0.05
        elif difficulty == "medium":
            wrong_order_penalty = 0.06 if len(history) <= len(expected_sequence) + 1 else 0.10
        else:
            wrong_order_penalty = 0.12 if len(history) <= len(expected_sequence) + 1 else 0.18

    step_limit_penalty = 0.0
    if steps_taken >= max_steps:
        if difficulty == "easy":
            step_limit_penalty = 0.04
        elif difficulty == "medium":
            step_limit_penalty = 0.08
        else:
            step_limit_penalty = 0.14

    if difficulty == "easy":
        total = (
            (0.42 * correctness_score)
            + (0.28 * order_score)
            + (0.24 * efficiency_score)
            - redundancy_penalty
            - wrong_order_penalty
            - step_limit_penalty
        )
    elif difficulty == "medium":
        total = (
            (0.34 * correctness_score)
            + (0.36 * order_score)
            + (0.20 * efficiency_score)
            - redundancy_penalty
            - wrong_order_penalty
            - step_limit_penalty
        )
    else:
        exact_sequence = history[: len(expected_sequence)] == expected_sequence
        compact_bonus = 0.08 if exact_sequence and len(history) == len(expected_sequence) else 0.0
        late_action_penalty = 0.0
        if steps_taken > len(expected_sequence):
            late_action_penalty = min(0.18, 0.04 * (steps_taken - len(expected_sequence)))
        total = (
            (0.32 * correctness_score)
            + (0.50 * order_score)
            + (0.18 * efficiency_score)
            - redundancy_penalty
            - wrong_order_penalty
            - step_limit_penalty
            - late_action_penalty
            + compact_bonus
        )
    return round(_clamp(total, 0.0, 1.0), 4)