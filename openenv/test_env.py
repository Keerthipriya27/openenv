from env.environment import CyberSecurityEnv


def smoke_run(task_id: str) -> None:
    env = CyberSecurityEnv(task_id=task_id)
    obs = env.reset()
    print(f"Task: {task_id} | Initial status: {obs.get('system_status')}")

    for action in ["detect_threat", "classify_attack", "block_ip"]:
        obs, reward, done, info = env.step(action)
        print(f"Action={action} Reward={reward:.3f} Done={done} Status={obs.get('system_status')}")
        if done:
            break

    print(f"Final score: {env.get_score():.2f}")


if __name__ == "__main__":
    smoke_run("easy")