import os
import sys
from pathlib import Path

from fastapi import FastAPI
from pydantic import BaseModel

ROOT_DIR = Path(__file__).resolve().parents[1]
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from env.environment import CyberSecurityEnv


app = FastAPI(title="OpenEnv CyberSecurity Service", version="1.0.0")
WEB_ENV = CyberSecurityEnv(task_id="easy")
WEB_ENV.reset()


class ResetRequest(BaseModel):
    task: str = "easy"


class StepRequest(BaseModel):
    action: str


@app.get("/")
def root():
    return {"status": "ok", "service": "openenv-cybersecurity"}


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/reset")
def reset_env(payload: ResetRequest):
    global WEB_ENV
    WEB_ENV = CyberSecurityEnv(task_id=payload.task)
    observation = WEB_ENV.reset()
    return {
        "task": payload.task,
        "observation": observation,
        "done": WEB_ENV.done,
        "step": WEB_ENV.step_count,
    }


@app.post("/step")
def step_env(payload: StepRequest):
    observation, reward, done, info = WEB_ENV.step(payload.action)
    return {
        "observation": observation,
        "reward": reward,
        "done": done,
        "info": info,
    }


@app.get("/state")
def state_env():
    return {"state": WEB_ENV.state(), "step": WEB_ENV.step_count, "done": WEB_ENV.done}


def main() -> None:
    import uvicorn

    port = int(os.getenv("PORT", "7860"))
    uvicorn.run("server.app:app", host="0.0.0.0", port=port)


if __name__ == "__main__":
    main()
