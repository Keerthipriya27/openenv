import os
import re
import subprocess
import sys
from pathlib import Path

START_RE = re.compile(r"^\[START\] task=([^\s]+) env=([^\s]+) model=(.+)$")
STEP_RE = re.compile(
    r"^\[STEP\] step=(\d+) action=([^\s]+) reward=(-?\d+\.\d{2}) done=(true|false) error=(.+)$"
)
END_RE = re.compile(
    r"^\[END\] success=(true|false) steps=(\d+) score=(\d+\.\d{2}) rewards=(-?\d+\.\d{2}(?:,-?\d+\.\d{2})*)$"
)


def run_inference() -> list[str]:
    root = Path(__file__).resolve().parents[1]
    env = os.environ.copy()
    env.setdefault("USE_MOCK", "true")

    proc = subprocess.run(
        [sys.executable, "inference.py"],
        cwd=root,
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    if proc.returncode != 0:
        print("[FAIL] inference.py exited with non-zero code")
        print(proc.stderr.strip())
        sys.exit(1)

    lines = [line.strip() for line in proc.stdout.splitlines() if line.strip()]
    return lines


def validate(lines: list[str]) -> None:
    if not lines:
        print("[FAIL] inference.py produced no stdout")
        sys.exit(1)

    i = 0
    episodes = 0
    while i < len(lines):
        start_match = START_RE.match(lines[i])
        if not start_match:
            print(f"[FAIL] Invalid START line: {lines[i]}")
            sys.exit(1)

        i += 1
        step_count = 0
        step_numbers = []
        rewards = []

        while i < len(lines):
            step_match = STEP_RE.match(lines[i])
            if not step_match:
                break
            step_no = int(step_match.group(1))
            reward = step_match.group(3)
            done = step_match.group(4)
            error_value = step_match.group(5)

            if error_value == "":
                print(f"[FAIL] Empty error field in STEP line: {lines[i]}")
                sys.exit(1)

            step_count += 1
            step_numbers.append(step_no)
            rewards.append(reward)

            # done=true is only valid for the last step in an episode
            if done == "true":
                # We allow line parser to continue; END must follow next
                pass

            i += 1

        if step_count == 0:
            print("[FAIL] Episode has no STEP lines")
            sys.exit(1)

        if i >= len(lines):
            print("[FAIL] Missing END line")
            sys.exit(1)

        end_match = END_RE.match(lines[i])
        if not end_match:
            print(f"[FAIL] Invalid END line: {lines[i]}")
            sys.exit(1)

        end_steps = int(end_match.group(2))
        end_score = float(end_match.group(3))
        end_rewards = end_match.group(4).split(",")

        if end_steps != step_count:
            print(f"[FAIL] END steps={end_steps} does not match STEP count={step_count}")
            sys.exit(1)

        if not (0.0 <= end_score <= 1.0):
            print(f"[FAIL] END score out of range [0,1]: {end_score}")
            sys.exit(1)

        if end_rewards != rewards:
            print("[FAIL] END rewards list does not match STEP rewards")
            sys.exit(1)

        if step_numbers != list(range(1, step_count + 1)):
            print(f"[FAIL] STEP numbers are not sequential from 1: {step_numbers}")
            sys.exit(1)

        episodes += 1
        i += 1

    if episodes < 3:
        print(f"[FAIL] Expected at least 3 episodes, found {episodes}")
        sys.exit(1)

    print(f"[OK] Strict stdout format valid across {episodes} episodes")


if __name__ == "__main__":
    output_lines = run_inference()
    validate(output_lines)
