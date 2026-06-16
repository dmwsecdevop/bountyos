from __future__ import annotations

import asyncio
from typing import Optional, List

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, Query
from sqlmodel import Session, select

from api.database import get_session, session_ctx
from api.models import Finding, ScanEvent
from api.services.debate_engine import (
    debate_finding, debate_all_findings, DebateRecord, debate_enabled as _debate_enabled, debate_model as _debate_model
)

router = APIRouter(prefix="/debate", tags=["debate-engine"])


@router.get("/records/{finding_id}")
def get_records(finding_id: str, session: Session = Depends(get_session)):
    records = session.exec(select(DebateRecord).where(DebateRecord.finding_id == finding_id)).all()
    return [r.dict() for r in records]


@router.post("/findings/{finding_id}/run")
async def run_debate_for_finding(
    finding_id: str,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    force: bool = Query(False, description="Force debate even if engine disabled or already debated"),
):
    if not _debate_enabled() and not force:
        raise HTTPException(403, "Debate engine is disabled (set BOUNTYOS_DEBATE_ENABLED=true to enable) ")

    f = session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")

    # enqueue background job
    def _bg_run(fid: str, sid: str, fr: bool):
        try:
            asyncio.run(debate_finding(fid, sid, force=fr))
        except Exception as e:
            with session_ctx() as s:
                s.add(ScanEvent(scan_id=sid, phase="vulnscan", tool="debate-engine", level="error", message=f"Debate background error: {e}"))
                s.commit()

    background_tasks.add_task(_bg_run, finding_id, f.scan_id, force)
    return {"detail": "Debate started", "finding_id": finding_id, "model": _debate_model()}


@router.post("/scans/{scan_id}/run")
async def run_debate_for_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    force: bool = Query(False, description="Force debate even if engine disabled"),
):
    if not _debate_enabled() and not force:
        raise HTTPException(403, "Debate engine is disabled (set BOUNTYOS_DEBATE_ENABLED=true to enable) ")

    # Kick off background task to debate all findings
    def _bg_run(sid: str, fr: bool):
        try:
            asyncio.run(debate_all_findings(sid, force=fr))
        except Exception as e:
            with session_ctx() as s:
                s.add(ScanEvent(scan_id=sid, phase="vulnscan", tool="debate-engine", level="error", message=f"Debate scan background error: {e}"))
                s.commit()

    background_tasks.add_task(_bg_run, scan_id, force)
    return {"detail": "Debate for scan scheduled", "scan_id": scan_id, "model": _debate_model()}
