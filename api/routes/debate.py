from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlmodel import Session, select

from api.database import get_session, session_ctx
from api.models import Finding, Scan
from api.services.debate_engine import DebateRecord, DebateSession, debate_enabled, debate_model

router = APIRouter(prefix="/debate", tags=["debate"])


@router.get("/records/{finding_id}")
def get_records(finding_id: str, session: Session = Depends(get_session)):
    records = session.exec(
        select(DebateRecord)
        .where(DebateRecord.finding_id == finding_id)
        .order_by(DebateRecord.created_at.desc())
    ).all()
    return [record.model_dump() for record in records]


@router.post("/findings/{finding_id}/run")
async def run_debate_finding(
    finding_id: str,
    force: bool = Query(False, description="Force debate even if BOUNTYOS_DEBATE_ENABLED is false"),
):
    if not debate_enabled() and not force:
        return {
            "enabled": False,
            "detail": "Debate engine is disabled. Set BOUNTYOS_DEBATE_ENABLED=true or pass force=true.",
            "model": debate_model(),
        }

    with session_ctx() as session:
        finding = session.get(Finding, finding_id)
        if not finding:
            raise HTTPException(status_code=404, detail="Finding not found")
        scan_id = finding.scan_id

    record_id = await DebateSession(force=force).debate_finding(finding_id, scan_id=scan_id)
    return {"enabled": True, "finding_id": finding_id, "record_id": record_id, "model": debate_model()}


@router.post("/scans/{scan_id}/run")
async def run_debate_scan(
    scan_id: str,
    force: bool = Query(False, description="Force debate even if BOUNTYOS_DEBATE_ENABLED is false"),
):
    if not debate_enabled() and not force:
        return {
            "enabled": False,
            "detail": "Debate engine is disabled. Set BOUNTYOS_DEBATE_ENABLED=true or pass force=true.",
            "model": debate_model(),
        }

    with session_ctx() as session:
        scan = session.get(Scan, scan_id)
        if not scan:
            raise HTTPException(status_code=404, detail="Scan not found")

    record_ids = await DebateSession(force=force).debate_all_findings(scan_id)
    return {"enabled": True, "scan_id": scan_id, "record_ids": record_ids, "count": len(record_ids), "model": debate_model()}
