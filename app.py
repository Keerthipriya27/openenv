from flask import Flask, jsonify, redirect, render_template, request, url_for

from env.environment import CyberSecurityEnv
from inference import run_task


app = Flask(__name__)
TASK_IDS = ["easy", "medium", "hard"]
WEB_ENV = None


def _get_or_create_env(task_id: str = "easy"):
    global WEB_ENV
    if WEB_ENV is None or WEB_ENV.task_id != task_id:
        WEB_ENV = CyberSecurityEnv(task_id=task_id)
    return WEB_ENV


@app.get("/")
def index():
    return render_template("index.html", selected="easy")


@app.get("/run")
def legacy_run_redirect():
    return redirect(url_for("index"))


@app.get("/health")
def health():
    return jsonify({"status": "ok"}), 200


@app.post("/reset")
def reset_env():
    payload = request.get_json(silent=True) or {}
    task_id = payload.get("task", "easy")
    if task_id not in TASK_IDS:
        task_id = "easy"

    env = _get_or_create_env(task_id)
    observation = env.reset()
    return jsonify(
        {
            "task": task_id,
            "observation": observation,
            "done": env.done,
            "step": env.step_count,
        }
    )


@app.post("/step")
def step_env():
    global WEB_ENV
    if WEB_ENV is None:
        WEB_ENV = CyberSecurityEnv(task_id="easy")
        WEB_ENV.reset()

    payload = request.get_json(silent=True) or {}
    action = payload.get("action", "ignore")
    observation, reward, done, info = WEB_ENV.step(action)
    return jsonify(
        {
            "observation": observation,
            "reward": reward,
            "done": done,
            "info": info,
        }
    )


@app.get("/state")
def state_env():
    global WEB_ENV
    if WEB_ENV is None:
        WEB_ENV = CyberSecurityEnv(task_id="easy")
        WEB_ENV.reset()
    return jsonify({"state": WEB_ENV.state(), "step": WEB_ENV.step_count, "done": WEB_ENV.done})


@app.post("/agent/run")
def run_agent():
    task_id = request.json.get("task", "easy") if request.is_json else "easy"
    if task_id not in TASK_IDS:
        task_id = "easy"

    score, history = run_task(task_id)
    return jsonify({"task": task_id, "score": score, "history": history})


if __name__ == "__main__":
    app.run(host="127.0.0.1", port=5000, debug=True)
