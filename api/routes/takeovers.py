from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from api.database import get_session, session_ctx
from api.services.takeover_monitor import TakeoverCandidate, scan_target_metadata_only, takeover_enabled, verify_tls
router=APIRouter(prefix="/takeovers", tags=["takeovers"])
@router.get("/")
def all(session: Session=Depends(get_session)): return [x.model_dump() for x in session.exec(select(TakeoverCandidate)).all()]
@router.get("/open")
def open_items(session: Session=Depends(get_session)): return [x.model_dump() for x in session.exec(select(TakeoverCandidate).where(TakeoverCandidate.status.in_(["candidate","verified","claimed"]))).all()]
@router.post("/scan/{target_id}")
def scan(target_id: str): return {"enabled":takeover_enabled(),"verify_tls":verify_tls(),"result":scan_target_metadata_only(target_id)}
@router.post("/{candidate_id}/resolve")
def resolve(candidate_id: str):
    with session_ctx() as s:
        c=s.get(TakeoverCandidate,candidate_id)
        if not c: raise HTTPException(404,"Candidate not found")
        c.status="resolved"; s.add(c); s.commit(); s.refresh(c); return c.model_dump()
@router.post("/{candidate_id}/false-positive")
def fp(candidate_id: str):
    with session_ctx() as s:
        c=s.get(TakeoverCandidate,candidate_id)
        if not c: raise HTTPException(404,"Candidate not found")
        c.status="false_positive"; c.confirmed=False; s.add(c); s.commit(); s.refresh(c); return c.model_dump()
