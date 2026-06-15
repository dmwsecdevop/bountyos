"""Full Hacker Mindset / Hunter workflow API."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from pydantic import BaseModel
from sqlmodel import Session, select

from api.database import get_session
from api.models import (
    BountyReport, BugHypothesis, Finding, PlannerDecision, Scan, ScanEvent, ScanPhase,
    Severity, Target, ValidationAttempt,
)
from api.intelligence import attack_graph, hypothesis_engine, adaptive_planner, shared_memory
from api.validation import validation_engine, evidence_store
from api.reporting import report_agent
from api.learning import experience_store
from api.quality import quality_engine
from api.labs import list_scenarios, get_scenario
from api.realtime import publish_sync, set_agent_state

router = APIRouter(prefix="/hunter", tags=["hunter-workflow"])


class WorkflowRequest(BaseModel):
    reset_graph: bool = False
    replace_hypotheses: bool = False
    replace_plans: bool = False


class ValidationRequest(BaseModel):
    decision_id: str


class ApprovalRequest(BaseModel):
    approved: bool = True


class ExecuteRequest(BaseModel):
    dry_run: bool = True


class ReportRequest(BaseModel):
    finding_id: Optional[str] = None
    validation_attempt_id: Optional[str] = None


class LabRequest(BaseModel):
    target_name: Optional[str] = None


def _serialize_hyp(h: BugHypothesis) -> Dict[str, Any]:
    return hypothesis_engine.serialize(h)


def _serialize_plan(p: PlannerDecision) -> Dict[str, Any]:
    return p.model_dump(mode="json")


@router.get("/capabilities")
def capabilities():
    return {
        "workflow": [
            "attack-surface graph", "shared specialist memory", "expert hypotheses",
            "adaptive expected-value planner", "controlled validation and approvals",
            "redacted evidence with SHA-256 integrity", "experience/utility learning",
            "bounty-ready Markdown/JSON/HTML report exports", "synthetic digital-twin labs",
        ],
        "specialists": [
            "program opportunity", "recon", "API", "web", "cloud", "bug hunter brain",
            "adaptive planner", "validation", "evidence", "report", "experience learner",
        ],
        "lifecycle": "Observe -> Graph -> Hypothesize -> Plan -> Approve -> Validate -> Evidence -> Report -> Learn",
    }


@router.post("/scans/{scan_id}/run")
def run_workflow(scan_id: str, req: WorkflowRequest, session: Session = Depends(get_session)):
    if not session.get(Scan, scan_id):
        raise HTTPException(404, "Scan not found")
    set_agent_state(status="reasoning", stage="graph", model_expert="bug_reasoning_expert", last_action="full_hunter_workflow")
    publish_sync("hunter.workflow.started", {"scan_id": scan_id})
    try:
        graph = attack_graph.build(session, scan_id, reset=req.reset_graph)
        publish_sync("hunter.graph.built", {"scan_id": scan_id, "summary": graph["summary"]})
        hypotheses = hypothesis_engine.generate(session, scan_id, replace=req.replace_hypotheses)
        publish_sync("hunter.hypotheses.generated", {"scan_id": scan_id, "count": len(hypotheses)})
        # Refresh graph so hypothesis nodes and edges are included.
        graph = attack_graph.build(session, scan_id, reset=False)
        plans = adaptive_planner.plan(session, scan_id, replace=req.replace_plans)
        publish_sync("hunter.plan.created", {"scan_id": scan_id, "count": len(plans)})
        quality = quality_engine.evaluate_scan(
            session, scan_id, task_types=["hypothesis", "plan"], replace_existing=True
        )
        publish_sync("quality.evaluation.finished", {"scan_id": scan_id, "summary": quality["summary"]})
        return {
            "ok": True, "scan_id": scan_id,
            "summary": {
                "graph": graph["summary"], "hypotheses": len(hypotheses),
                "plans": len(plans), "top_action": plans[0] if plans else None,
                "quality": quality["summary"],
            },
            "graph": graph, "hypotheses": hypotheses, "plans": plans,
            "quality": quality,
            "memory": shared_memory.summary(session, scan_id),
        }
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    finally:
        set_agent_state(status="idle", stage="observe")
        publish_sync("hunter.workflow.finished", {"scan_id": scan_id})


@router.get("/scans/{scan_id}/snapshot")
def snapshot(scan_id: str, session: Session = Depends(get_session)):
    if not session.get(Scan, scan_id):
        raise HTTPException(404, "Scan not found")
    hypotheses = session.exec(
        select(BugHypothesis).where(BugHypothesis.scan_id == scan_id)
        .order_by(BugHypothesis.priority_score.desc())
    ).all()
    plans = session.exec(
        select(PlannerDecision).where(PlannerDecision.scan_id == scan_id)
        .order_by(PlannerDecision.expected_value.desc())
    ).all()
    attempts = session.exec(
        select(ValidationAttempt).where(ValidationAttempt.scan_id == scan_id)
        .order_by(ValidationAttempt.created_at.desc())
    ).all()
    reports = session.exec(
        select(BountyReport).where(BountyReport.scan_id == scan_id)
        .order_by(BountyReport.created_at.desc())
    ).all()
    return {
        "scan_id": scan_id,
        "graph": attack_graph.snapshot(session, scan_id),
        "priority_paths": attack_graph.priority_paths(session, scan_id),
        "hypotheses": [_serialize_hyp(h) for h in hypotheses],
        "plans": [_serialize_plan(p) for p in plans],
        "validations": [validation_engine.serialize(a) for a in attempts],
        "evidence": evidence_store.list(session, scan_id),
        "reports": [report_agent.serialize(r) for r in reports],
        "quality": {
            "summary": quality_engine.summary(session, scan_id),
            "evaluations": quality_engine.list(session, scan_id),
        },
        "memory": shared_memory.summary(session, scan_id),
        "experience": experience_store.list(session, scan_id, 100),
    }


@router.post("/scans/{scan_id}/graph")
def build_graph(scan_id: str, reset: bool = False, session: Session = Depends(get_session)):
    try:
        result = attack_graph.build(session, scan_id, reset=reset)
        publish_sync("hunter.graph.built", {"scan_id": scan_id, "summary": result["summary"]})
        return result
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.get("/scans/{scan_id}/graph")
def get_graph(scan_id: str, session: Session = Depends(get_session)):
    return attack_graph.snapshot(session, scan_id)


@router.get("/scans/{scan_id}/paths")
def get_paths(scan_id: str, session: Session = Depends(get_session)):
    return {"scan_id": scan_id, "paths": attack_graph.priority_paths(session, scan_id)}


@router.post("/scans/{scan_id}/hypotheses")
def generate_hypotheses(scan_id: str, replace: bool = False, session: Session = Depends(get_session)):
    try:
        rows = hypothesis_engine.generate(session, scan_id, replace=replace)
        attack_graph.build(session, scan_id)
        publish_sync("hunter.hypotheses.generated", {"scan_id": scan_id, "count": len(rows)})
        return {"scan_id": scan_id, "hypotheses": rows}
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.get("/scans/{scan_id}/hypotheses")
def list_hypotheses(scan_id: str, session: Session = Depends(get_session)):
    rows = session.exec(select(BugHypothesis).where(BugHypothesis.scan_id == scan_id).order_by(BugHypothesis.priority_score.desc())).all()
    return {"scan_id": scan_id, "hypotheses": [_serialize_hyp(h) for h in rows]}


@router.post("/scans/{scan_id}/plan")
def create_plan(scan_id: str, replace: bool = False, session: Session = Depends(get_session)):
    try:
        rows = adaptive_planner.plan(session, scan_id, replace=replace)
        publish_sync("hunter.plan.created", {"scan_id": scan_id, "count": len(rows)})
        return {"scan_id": scan_id, "plans": rows}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get("/scans/{scan_id}/plan")
def list_plan(scan_id: str, session: Session = Depends(get_session)):
    rows = session.exec(select(PlannerDecision).where(PlannerDecision.scan_id == scan_id).order_by(PlannerDecision.expected_value.desc())).all()
    return {"scan_id": scan_id, "plans": [_serialize_plan(p) for p in rows]}


@router.post("/validations")
def create_validation(req: ValidationRequest, session: Session = Depends(get_session)):
    try:
        result = validation_engine.create_attempt(session, req.decision_id)
        publish_sync("hunter.validation.prepared", result)
        return result
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.post("/validations/{attempt_id}/approval")
def approve_validation(attempt_id: str, req: ApprovalRequest, session: Session = Depends(get_session)):
    try:
        result = validation_engine.approve(session, attempt_id, req.approved)
        publish_sync("hunter.validation.approval", {"attempt_id": attempt_id, "approved": req.approved})
        return result
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.post("/validations/{attempt_id}/execute")
def execute_validation(attempt_id: str, req: ExecuteRequest, session: Session = Depends(get_session)):
    try:
        result = validation_engine.execute(session, attempt_id, dry_run=req.dry_run)
        attempt = session.get(ValidationAttempt, attempt_id)
        evaluation = quality_engine.evaluate_validation(session, attempt)
        result["quality_evaluation"] = evaluation
        publish_sync("hunter.validation.result", result)
        publish_sync("quality.evaluation.finished", {"scan_id": attempt.scan_id, "evaluation": evaluation})
        return result
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.post("/scans/{scan_id}/reports")
def generate_report(scan_id: str, req: ReportRequest, session: Session = Depends(get_session)):
    try:
        result = report_agent.generate(session, scan_id, req.finding_id, req.validation_attempt_id)
        report = session.get(BountyReport, result["id"])
        evaluation = quality_engine.evaluate_report(session, report)
        result["quality_evaluation"] = evaluation
        publish_sync("hunter.report.generated", {"scan_id": scan_id, "report_id": result["id"], "quality_score": result["quality_score"]})
        publish_sync("quality.evaluation.finished", {"scan_id": scan_id, "evaluation": evaluation})
        return result
    except ValueError as exc:
        raise HTTPException(404, str(exc))


@router.get("/scans/{scan_id}/reports")
def list_reports(scan_id: str, session: Session = Depends(get_session)):
    rows = session.exec(select(BountyReport).where(BountyReport.scan_id == scan_id).order_by(BountyReport.created_at.desc())).all()
    return {"scan_id": scan_id, "reports": [report_agent.serialize(r) for r in rows]}


@router.get("/reports/{report_id}/download/{fmt}")
def download_report(report_id: str, fmt: str, session: Session = Depends(get_session)):
    report = session.get(BountyReport, report_id)
    if not report:
        raise HTTPException(404, "Report not found")
    paths = report_agent.write_exports(report)
    if fmt not in paths:
        raise HTTPException(400, "Format must be markdown, json, or html")
    path = Path(paths[fmt])
    media = {"markdown": "text/markdown", "json": "application/json", "html": "text/html"}[fmt]
    return FileResponse(path, media_type=media, filename=path.name)


@router.get("/scans/{scan_id}/memory")
def memory(scan_id: str, kind: Optional[str] = None, agent: Optional[str] = None,
           session: Session = Depends(get_session)):
    return {"scan_id": scan_id, "memory": shared_memory.list(session, scan_id, kind, agent)}


@router.get("/experience")
def experience(scan_id: Optional[str] = None, session: Session = Depends(get_session)):
    return {"summary": experience_store.summary(session), "records": experience_store.list(session, scan_id)}


@router.get("/labs")
def labs():
    return {"scenarios": list_scenarios()}


@router.post("/labs/{scenario_id}/create")
def create_lab(scenario_id: str, req: LabRequest, session: Session = Depends(get_session)):
    try:
        scenario = get_scenario(scenario_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc))
    target = Target(
        name=req.target_name or scenario["name"],
        domain=f"{scenario_id}.bountyos-lab.local",
        scope=f"*.{scenario_id}.bountyos-lab.local",
        notes="Synthetic digital-twin lab. No external network target.",
    )
    session.add(target); session.commit(); session.refresh(target)
    scan = Scan(target_id=target.id, status="done", phase=ScanPhase.RECON, mode="passive", config=json.dumps({"lab": scenario_id}))
    session.add(scan); session.commit(); session.refresh(scan)
    for signal in scenario["signals"]:
        session.add(ScanEvent(scan_id=scan.id, phase=ScanPhase.RECON, tool="digital-twin", level="info", message=f"Synthetic signal: {signal}"))
    lab_findings = {
        "saas_api": ("Synthetic BOLA evidence in order API", Severity.HIGH, "/api/orders/{order_id}", "SYNTHETIC LAB ONLY: Account B received a simulated HTTP 200 response for Account A's order object."),
        "exposure": ("Synthetic public configuration artifact", Severity.MEDIUM, "/.env", "SYNTHETIC LAB ONLY: A simulated public response contained redacted configuration keys."),
        "agentic_support": ("Synthetic recovery authorization state bypass", Severity.HIGH, "/support/recovery", "SYNTHETIC LAB ONLY: The recovery workflow accepted an account-change transition without the expected deterministic identity check."),
    }
    if scenario_id in lab_findings:
        title, severity, url, evidence = lab_findings[scenario_id]
        session.add(Finding(scan_id=scan.id, title=title, severity=severity, url=url, tool="digital-twin", evidence=evidence,
                            description="Synthetic evidence used to exercise the complete Hunter and Report workflow."))
    session.commit()
    result = run_workflow(scan.id, WorkflowRequest(), session)
    result["lab"] = scenario
    publish_sync("hunter.lab.created", {"scenario": scenario_id, "scan_id": scan.id})
    return result
