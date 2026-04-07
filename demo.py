from tasks.tasks import tasks
from tasks.reward import compute_reward
from tasks.grader import grade_task

actions = ["detect_threat", "classify_attack", "block_ip", "ignore"]

for task in tasks:
    state = task["initial_state"].copy()
    history = []

    print("\nTask:", task["id"], "-", task["goal"])
    print("-" * 40)

    for action in actions:
        reward, state = compute_reward(action, state)
        history.append(action)

        print("Action:", action, "| Reward:", reward)

        # 🔥 FIX: use ip_blocked (your state)
        if state.get("ip_blocked"):
            print("✅ Attack blocked")
            break

    score = grade_task(history)

    print("🏁 Final Score:", score)
    print("=" * 40)