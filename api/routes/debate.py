from __future__ import annotations

import asyncio
from typing import Optional, List, Dict, Any

from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException, Query
from sqlmodel import Session, select

from api.database import get_session, session_ctx
from api.models import Finding, ScanEvent
from api.services.debate_engine import (
    debate_finding,
    debate_all_findings,
    DebateRecord,
    debate_enabled as _debate_enabled,
    debate_model as _debate_model,
)

router = APIRouter(prefix="/debate", tags=["debate-engine"])


@router.get("/records/{finding_id}")
def get_records(finding_id: str, session: Session = Depends(get_session)) -> List[Dict[str, Any]]:
    """Retrieve all debate records for a specific finding."""
    records = session.exec(
        select(DebateRecord).where(DebateRecord.finding_id == finding_id)
    ).all()
    return [r.model_dump() for r in records]


@router.post("/findings/{finding_id}/run")
async def run_debate_for_finding(
    finding_id: str,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    force: bool = Query(
        False, description="Force debate even if engine disabled or already debated"
    ),
) -> Dict[str, Any]:
    """Run debate engine for a specific finding."""
    if not _debate_enabled() and not force:
        raise HTTPException(
            status_code=403,
            detail="Debate engine is disabled (set BOUNTYOS_DEBATE_ENABLED=true to enable)",
        )

    finding_obj = session.get(Finding, finding_id)
    if not finding_obj:
        raise HTTPException(status_code=404, detail="Finding not found")

    # Enqueue background job
    def _bg_run(fid: str, sid: str, fr: bool) -> None:
        """Background task to run debate finding."""
        try:
            asyncio.run(debate_finding(fid, sid, force=fr))
        except Exception as e:
            with session_ctx() as s:
                s.add(
                    ScanEvent(
                        scan_id=sid,
                        phase="vulnscan",
                        tool="debate-engine",
                        level="error",
                        message=f"Debate background error: {e}",
                    )
                )
                s.commit()

    background_tasks.add_task(_bg_run, finding_id, finding_obj.scan_id, force)
    return {
        "detail": "Debate started",
        "finding_id": finding_id,
        "model": _debate_model(),
    }


@router.post("/scans/{scan_id}/run")
async def run_debate_for_scan(
    scan_id: str,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
    force: bool = Query(False, description="Force debate even if engine disabled"),
) -> Dict[str, Any]:
    """Run debate engine for all findings in a scan."""
    if not _debate_enabled() and not force:
        raise HTTPException(
            status_code=403,
            detail="Debate engine is disabled (set BOUNTYOS_DEBATE_ENABLED=true to enable)",
        )

    # Kick off background task to debate all findings
    def _bg_run(sid: str, fr: bool) -> None:
        """Background task to run debate for all findings."""
        try:
            asyncio.run(debate_all_findings(sid, force=fr))
        except Exception as e:
            with session_ctx() as s:
                s.add(
                    ScanEvent(
                        scan_id=sid,
                        phase="vulnscan",
                        tool="debate-engine",
                        level="error",
                        message=f"Debate scan background error: {e}",
                    )
                )
                s.commit()

    background_tasks.add_task(_bg_run, scan_id, force)
    return {
        "detail": "Debate for scan scheduled",
        "scan_id": scan_id,
        "model": _debate_model(),
    }
