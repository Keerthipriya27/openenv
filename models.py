from pydantic import BaseModel, Field
from typing import Optional, Dict, Any


class Observation(BaseModel):
    """Observation model containing threat information, logs, and system state."""
    logs: list[str] = Field(..., description="List of security logs")
    threat_detected: bool = Field(default=False, description="Whether a threat has been detected")
    attack_type: Optional[str] = Field(default=None, description="Type of attack detected")
    ip_blocked: bool = Field(default=False, description="Whether the IP has been blocked")
    steps: int = Field(default=0, description="Number of steps taken")


class Action(BaseModel):
    """Action model for agent decisions."""
    action_type: str = Field(..., description="Type of action: detect_threat, classify_attack, block_ip, or ignore")
    
    class Config:
        json_schema_extra = {
            "example": {"action_type": "detect_threat"}
        }


class Reward(BaseModel):
    """Reward model with float value between 0.0 and 1.0."""
    value: float = Field(..., ge=-2.0, le=2.0, description="Reward value")


class TaskInfo(BaseModel):
    """Task information."""
    task_id: str = Field(..., description="Unique task identifier")
    goal: str = Field(..., description="Goal of the task")
    difficulty: str = Field(..., description="Difficulty level: easy, medium, or hard")


class StepResult(BaseModel):
    """Result of a step in the environment."""
    observation: Observation
    reward: float = Field(..., ge=-2.0, le=2.0)
    done: bool
    info: Dict[str, Any]
