from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlmodel import Session, select
from api.database import get_session, session_ctx
from api.services.agent_revisions import AgentRevision, AgentEvalResult, run_basic_evals
router=APIRouter(prefix="/evals", tags=["evals"])
class RevisionIn(BaseModel):
    agent_name: str; version: str; model: str; prompt_hash: str; tools_allowed: str|None=None; notes: str|None=None
@router.get("/revisions")
def revisions(session: Session=Depends(get_session)): return [x.model_dump() for x in session.exec(select(AgentRevision).order_by(AgentRevision.created_at.desc())).all()]
@router.post("/revisions")
def create_revision(body: RevisionIn):
    with session_ctx() as s:
        r=AgentRevision(**body.model_dump()); s.add(r); s.commit(); s.refresh(r); return r.model_dump()
@router.get("/results")
def results(session: Session=Depends(get_session)): return [x.model_dump() for x in session.exec(select(AgentEvalResult).order_by(AgentEvalResult.created_at.desc())).all()]
@router.post("/run-basic")
def run_basic(): return run_basic_evals(True)
