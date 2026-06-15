from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlalchemy import Column, String
from sqlmodel import Field, SQLModel, select
from api.database import session_ctx

def utcnow(): return datetime.now(timezone.utc)
class AgentTask(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    title: str
    agent_name: str
    status: str = "queued"
    target_id: Optional[str] = None
    scan_id: Optional[str] = None
    risk_level: str = "low"
    progress: int = 0
    summary: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
    updated_at: datetime = Field(default_factory=utcnow)
    completed_at: Optional[datetime] = None
class AgentEvent(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    task_id: str = Field(foreign_key="agenttask.id")
    level: str = "info"
    message: str
    metadata_json: Optional[str] = Field(default=None, sa_column=Column("metadata", String))
    created_at: datetime = Field(default_factory=utcnow)
class AgentArtifact(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    task_id: str = Field(foreign_key="agenttask.id")
    artifact_type: str
    name: str
    path_or_url: str
    metadata_json: Optional[str] = Field(default=None, sa_column=Column("metadata", String))
    created_at: datetime = Field(default_factory=utcnow)
def create_task(title: str, agent_name: str, **kwargs) -> AgentTask:
    with session_ctx() as s:
        task = AgentTask(title=title, agent_name=agent_name, **kwargs); s.add(task); s.commit(); s.refresh(task); return task
def log_task_event(task_id: str, message: str, level: str = "info", metadata: str | None = None):
    with session_ctx() as s:
        s.add(AgentEvent(task_id=task_id, message=message, level=level, metadata_json=metadata)); s.commit()
def update_task(task_id: str, **kwargs):
    with session_ctx() as s:
        task = s.get(AgentTask, task_id)
        if not task: return None
        for k, v in kwargs.items(): setattr(task, k, v)
        task.updated_at = utcnow()
        if task.status in {"completed","failed","cancelled"} and not task.completed_at: task.completed_at = utcnow()
        s.add(task); s.commit(); s.refresh(task); return task
