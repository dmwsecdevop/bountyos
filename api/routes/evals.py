from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session, select
from typing import List, Dict, Any
from api.database import get_session, session_ctx
from api.services.agent_revisions import AgentRevision, AgentEvalResult, run_basic_evals

router = APIRouter(prefix="/evals", tags=["evals"])


class RevisionIn(BaseModel):
    """Schema for creating a new agent revision."""
    agent_name: str
    version: str
    model: str
    prompt_hash: str
    tools_allowed: str | None = None
    notes: str | None = None


@router.get("/revisions")
def revisions(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """Retrieve all agent revisions ordered by creation date (newest first)."""
    result = session.exec(select(AgentRevision).order_by(AgentRevision.created_at.desc())).all()
    return [x.model_dump() for x in result]


@router.post("/revisions")
def create_revision(body: RevisionIn) -> Dict[str, Any]:
    """Create a new agent revision."""
    with session_ctx() as s:
        revision = AgentRevision(**body.model_dump())
        s.add(revision)
        s.commit()
        s.refresh(revision)
        return revision.model_dump()


@router.get("/results")
def results(session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """Retrieve all evaluation results ordered by creation date (newest first)."""
    result = session.exec(select(AgentEvalResult).order_by(AgentEvalResult.created_at.desc())).all()
    return [x.model_dump() for x in result]


@router.post("/run-basic")
def run_basic() -> Dict[str, Any]:
    """Run basic agent evaluations."""
    return run_basic_evals(True)
