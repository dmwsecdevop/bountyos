from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from typing import List, Optional
from sqlmodel import Session, select

from api.database import get_session
from api.services.debate_engine import DebateRecord, DebateSession, debate_enabled
from api.models import Finding, Scan

router = APIRouter(prefix="/debate", tags=["debate"])


@router.get("/records/{finding_id}")
def get_records(finding_id: str, session: Session = Depends(get_session)):
    rows = session.exec(select(DebateRecord).where(DebateRecord.finding_id == finding_id)).all()
    return [r.dict() for r in rows]


@router.post("/findings/{finding_id}/run")
async def run_debate_finding(
    finding_id: str,
    force: bool = Query(False, description="Force debate even if BOUNTYOS_DEBATE_ENABLED is false"),
):
    if not debate_enabled() and not force:
        raise HTTPException(400, "Debate engine is disabled (set BOUNTYOS_DEBATE_ENABLED=true or use force=true)")

    # Check finding exists
    from api.database import session_ctx
    with session_ctx() as s:
        f = s.get(Finding, finding_id)
        if not f:
            raise HTTPException(404, "Finding not found")
        scan_id = f.scan_id

    ds = DebateSession()
    # Run in background
    import asyncio

    asyncio.create_task(ds.debate_finding(finding_id, scan_id=scan_id))
    return {"detail": "debate started", "finding_id": finding_id}


@router.post("/scans/{scan_id}/run")
async def run_debate_scan(scan_id: str, force: bool = Query(False, description="Force debate even if disabled")):
    if not debate_enabled() and not force:
        raise HTTPException(400, "Debate engine is disabled (set BOUNTYOS_DEBATE_ENABLED=true or use force=true)")

    # Check scan exists
    from api.database import session_ctx
    with session_ctx() as s:
        sc = s.get(Scan, scan_id)
        if not sc:
            raise HTTPException(404, "Scan not found")

    ds = DebateSession()
    import asyncio

    asyncio.create_task(ds.debate_all_findings(scan_id))
    return {"detail": "debate started for scan", "scan_id": scan_id}
