from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select
from api.database import get_session, session_ctx
from api.services.browser_agent import BrowserSession, capabilities
router=APIRouter(prefix="/browser", tags=["browser-agent"])
class SessionIn(BaseModel): url: str; target_id: str|None=None; notes: str|None=None
@router.get("/capabilities")
def caps(): return capabilities()
@router.get("/sessions")
def sessions(session: Session=Depends(get_session)): return [x.model_dump() for x in session.exec(select(BrowserSession)).all()]
@router.post("/sessions")
def create(body: SessionIn):
    with session_ctx() as s:
        row=BrowserSession(url=body.url,target_id=body.target_id,notes=body.notes); s.add(row); s.commit(); s.refresh(row); return row.model_dump()
@router.get("/sessions/{session_id}")
def get(session_id: str, session: Session=Depends(get_session)):
    row=session.get(BrowserSession, session_id)
    if not row: raise HTTPException(404,"Browser session not found")
    return row.model_dump()
