from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from api.database import get_session
from api.services.agent_tasks import AgentTask, AgentEvent, AgentArtifact, update_task
router=APIRouter(prefix="/tasks", tags=["agent-tasks"])
@router.get("/")
def tasks(session: Session=Depends(get_session)): return [x.model_dump() for x in session.exec(select(AgentTask).order_by(AgentTask.created_at.desc())).all()]
@router.get("/{task_id}")
def task(task_id: str, session: Session=Depends(get_session)):
    t=session.get(AgentTask, task_id)
    if not t: raise HTTPException(404,"Task not found")
    return t.model_dump()
@router.get("/{task_id}/events")
def events(task_id: str, session: Session=Depends(get_session)): return [x.model_dump() for x in session.exec(select(AgentEvent).where(AgentEvent.task_id==task_id)).all()]
@router.get("/{task_id}/artifacts")
def artifacts(task_id: str, session: Session=Depends(get_session)): return [x.model_dump() for x in session.exec(select(AgentArtifact).where(AgentArtifact.task_id==task_id)).all()]
@router.post("/{task_id}/cancel")
def cancel(task_id: str):
    t=update_task(task_id,status="cancelled",progress=100,summary="Cancelled by operator")
    if not t: raise HTTPException(404,"Task not found")
    return t.model_dump()
