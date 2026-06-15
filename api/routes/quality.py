"""Agent Quality Loop API routes."""
from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from api.database import get_session
from api.quality import quality_engine, retry_manager
from api.realtime import publish_sync, set_agent_state

router = APIRouter(prefix="/quality", tags=["agent-quality-loop"])


class EvaluateRequest(BaseModel):
    replace_existing: bool = True
    task_types: Optional[list[str]] = None


@router.get("/capabilities")
def capabilities():
    return {
        "engine": "Agent Quality Loop",
        "evaluates": ["hypotheses", "plans", "validation results", "reports"],
        "checks": [
            "evidence quality", "accuracy", "reproducibility", "impact confidence",
            "efficiency", "safety", "confidence calibration", "secret redaction",
        ],
        "decisions": ["accepted", "accepted_with_warnings", "retry", "rejected"],
        "retry_policy": "At most two controlled retries. Active validation is never auto-executed.",
    }


@router.post("/scans/{scan_id}/evaluate")
def evaluate_scan(scan_id: str, req: EvaluateRequest, session: Session = Depends(get_session)):
    set_agent_state(status="reasoning", stage="evaluate", model_expert="quality_critic", last_action="evaluate_agent_work")
    publish_sync("quality.evaluation.started", {"scan_id": scan_id})
    try:
        result = quality_engine.evaluate_scan(session, scan_id, req.task_types, req.replace_existing)
        publish_sync("quality.evaluation.finished", {"scan_id": scan_id, "summary": result["summary"]})
        return result
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    finally:
        set_agent_state(status="idle", stage="observe")


@router.get("/scans/{scan_id}")
def scan_quality(scan_id: str, session: Session = Depends(get_session)):
    return {
        "scan_id": scan_id,
        "summary": quality_engine.summary(session, scan_id),
        "evaluations": quality_engine.list(session, scan_id),
    }


@router.get("/evaluations")
def evaluations(scan_id: Optional[str] = None, status: Optional[str] = None,
                session: Session = Depends(get_session)):
    return {
        "summary": quality_engine.summary(session, scan_id),
        "evaluations": quality_engine.list(session, scan_id, status),
    }


@router.post("/evaluations/{evaluation_id}/retry")
def retry(evaluation_id: str, session: Session = Depends(get_session)):
    try:
        result = retry_manager.retry(session, evaluation_id)
        publish_sync("quality.retry", {"evaluation_id": evaluation_id, **result})
        return result
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.get("/performance")
def performance(session: Session = Depends(get_session)):
    return quality_engine.performance(session)
