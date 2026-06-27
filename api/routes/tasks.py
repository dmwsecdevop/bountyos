from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from typing import List, Dict, Any
from api.database import get_session
from api.services.agent_tasks import AgentTask, AgentEvent, AgentArtifact, update_task

router = APIRouter(prefix="/tasks", tags=["agent-tasks"])


@router.get("/")
def tasks(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """Retrieve all agent tasks ordered by creation date (newest first)."""
    result = session.exec(select(AgentTask).order_by(AgentTask.created_at.desc())).all()
    return [x.model_dump() for x in result]


@router.get("/{task_id}")
def task(task_id: str, session: Session = Depends(get_session)) -> Dict[str, Any]:
    """Retrieve a specific agent task by ID."""
    task_obj = session.get(AgentTask, task_id)
    if not task_obj:
        raise HTTPException(status_code=404, detail="Task not found")
    return task_obj.model_dump()


@router.get("/{task_id}/events")
def events(task_id: str, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """Retrieve all events for a specific task."""
    result = session.exec(select(AgentEvent).where(AgentEvent.task_id == task_id)).all()
    return [x.model_dump() for x in result]


@router.get("/{task_id}/artifacts")
def artifacts(task_id: str, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """Retrieve all artifacts for a specific task."""
    result = session.exec(select(AgentArtifact).where(AgentArtifact.task_id == task_id)).all()
    return [x.model_dump() for x in result]


@router.post("/{task_id}/cancel")
def cancel(task_id: str) -> Dict[str, Any]:
    """Cancel a running task."""
    task_obj = update_task(
        task_id,
        status="cancelled",
        progress=100,
        summary="Cancelled by operator"
    )
    if not task_obj:
        raise HTTPException(status_code=404, detail="Task not found")
    return task_obj.model_dump()
