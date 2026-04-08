---
title: Openenv
emoji: "🦀"
colorFrom: gray
colorTo: yellow
sdk: docker
pinned: false
---

# OpenEnv CyberSecurity Environment

An OpenEnv-ready cyber incident response simulator designed for AI agent evaluation. The environment emulates Security Operations Center (SOC) workflows where an agent must detect, classify, and contain attacks under noisy and time-limited conditions.

## Real-World Motivation

SOC teams handle thousands of alerts per day. Many are noisy, some are decoys, and only a subset are true incidents requiring action. This project simulates that operational reality so agents can learn:

- Signal extraction from mixed benign and malicious telemetry
- Correct sequencing of analyst actions
- Efficient response under strict step limits
- Robust decisions when logs include misleading events

## Task Design

The environment includes three escalating tasks with realistic logs and expected action sequences.

### EASY

- Objective: basic threat detection and response flow
- Log style: repeated failed logins and credential abuse indicators
- Hint support: enabled
- Expected sequence: detect_threat -> classify_attack -> block_ip
- Step budget: 5

### MEDIUM

- Objective: detect and classify SQLi campaign before containment
- Log style: API gateway traces, DB audit anomalies, IDS signatures
- Hint support: disabled
- Expected sequence: detect_threat -> classify_attack -> block_ip
- Step budget: 6

### HARD

- Objective: solve multi-stage intrusion with decoys and confusing evidence
- Log style: blended brute-force/exploitation/flood signals + benign noise
- Hint support: disabled
- Misleading logs: multiple decoys intentionally inserted
- Expected sequence: detect_threat -> classify_attack -> block_ip (exact order needed for max score)
- Step budget: 7

## Observation Design

Each step returns structured observations with dynamic updates:

- log_message: currently focused log line
- logs: full scenario log timeline
- system_status: monitoring, under_investigation, incident_confirmed, contained, escalated_to_human
- previous_action_result: outcome text for the latest action
- detected/classified/blocked: internal workflow state flags
- threat_detected/attack_type/ip_blocked: compatibility state keys
- action_history and steps: execution trace
- hint: included only for easy mode

## Reward Strategy

Reward shaping is sequence-aware and non-binary:

- Correct next action: +0.35
- Wrong/out-of-order action: -0.2
- Ignore during incident context: additional -0.1
- Repeated useless action: additional -0.15
- Correct full sequence completion bonus: +0.5
- Final success bonus: +1.0
- Early completion bonus: +0.2
- Step reward clamp: [-0.3, 1.0]
- Cumulative final reward tracked and capped into [0.0, 1.0]

This creates a meaningful training signal for intermediate behavior, not just terminal success/failure.

## Grading Logic

Deterministic grading in [0.0, 1.0] combines:

- Action correctness (did agent pick required actions)
- Sequence order (did it execute in the right order)
- Efficiency (fewer steps scores higher)
- Redundancy penalty for repeated non-progress actions

Agents receive partial credit when they choose correct actions in wrong order.

## Controlled Randomization

Episode logs vary slightly by timestamp spacing and selected fields (IP, request type, user agent), while remaining reproducible using a fixed random seed.

## Step Limits

Each task enforces max_steps. If exceeded before containment:

- Episode ends
- Additional penalty is applied
- Status changes to escalated_to_human

## Debug Mode

Environment supports debug mode:

- CyberSecurityEnv(debug=True)
- Adds debug_state snapshot in step() info for inspection

## Run Locally

1. Activate environment and install deps.
2. Configure required variables: API_KEY, MODEL_NAME, API_BASE_URL.
3. For free local runs, set USE_MOCK=true.
4. For submission baseline with OpenAI client, set USE_MOCK=false.
3. Run:

```bash
python inference.py
```

## Required Environment Variables (Hackathon)

- API_KEY: OpenAI-compatible API key injected by the hackathon proxy
- MODEL_NAME: model identifier used by inference.py
- API_BASE_URL: OpenAI-compatible API endpoint injected by the hackathon proxy
- USE_MOCK: set "true" for offline mock runs, "false" for real client runs

## Service Endpoints (HF/Docker Runtime)

When running app.py (default Docker command), the service exposes:

- GET /health -> 200 readiness check
- POST /reset -> reset environment and return initial observation
- POST /step -> apply action and return transition
- GET /state -> current environment state snapshot

## Pre-Submission Validation

```bash
pip install -r requirements.txt
openenv validate
docker build .
```

Validate strict inference stdout format:

```bash
python scripts/check_inference_output.py
```

If port 7860 is busy locally, start server on another port:

```powershell
powershell -ExecutionPolicy Bypass -File scripts/run_server.ps1 -Port 7861
```

If running baseline scoring with real API:

```bash
python inference.py
```

## Example Run (Output Contract)

Inference output should follow this strict single-line key=value format:

```text
[START] task=easy env=cybersecurity-threat-detection model=gemini-2.0-flash
[STEP] step=1 action=detect_threat reward=0.35 done=false error=null
[STEP] step=2 action=classify_attack reward=0.35 done=false error=null
[STEP] step=3 action=block_ip reward=1.00 done=true error=null
[END] success=true steps=3 score=0.94 rewards=0.35,0.35,1.00
```

No additional logging should be emitted by the environment itself.

## OpenEnv Compliance Summary

- reset(): returns initial observation dict
- step(action): returns (observation, reward, done, info)
- state(): returns full internal state
- deterministic grader and bounded score
- reusable tasks sourced from tasks/tasks.py
