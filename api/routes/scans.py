"""
BountyOS - Scans routes
Supports passive and aggressive scan modes.
"""

from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlmodel import Session, select
from typing import List, Dict, Any
import json
from datetime import datetime

from api.database import get_session, session_ctx
from api.models import (
    Scan, ScanCreate, ScanStatus, ScanPhase, ScanMode,
    ScanEvent, Target, Finding, Approval
)
from api.tools.discovery import (
    discover_all_tools, get_passive_tools, get_aggressive_tools, ALL_TOOLS
)
from api.realtime import publish_sync
from api.services.scan_orchestrator import ScanOrchestrator

router = APIRouter(prefix="/scans", tags=["scans"])

_active_scans: set = set()
_cancelled_scans: set = set()


def _log(
    scan_id: str,
    msg: str,
    phase: ScanPhase = ScanPhase.RECON,
    level: str = "info",
) -> None:
    """Log a scan event."""
    with session_ctx() as s:
        s.add(ScanEvent(
            scan_id=scan_id, phase=phase, tool="runner",
            level=level, message=msg,
        ))
        s.commit()
    publish_sync("scan.event", {
        "scan_id": scan_id, "phase": str(phase), "tool": "runner",
        "level": level, "message": msg
    })


async def _update_status(
    scan_id: str,
    status: ScanStatus,
    phase: ScanPhase = None,
) -> None:
    """Update scan status and phase."""
    with session_ctx() as s:
        scan = s.get(Scan, scan_id)
        if scan:
            scan.status = status
            if phase:
                scan.phase = phase
            if status == ScanStatus.RUNNING and not scan.started_at:
                scan.started_at = datetime.utcnow()
            if status in (ScanStatus.DONE, ScanStatus.FAILED):
                scan.finished_at = datetime.utcnow()
            s.add(scan)
            s.commit()
            publish_sync("scan.status", {
                "scan_id": scan_id, "status": str(status), "phase": str(scan.phase)
            })


def _persist_event(scan_id: str, ev: dict, phase: ScanPhase) -> None:
    """Persist a scan event to database."""
    with session_ctx() as s:
        s.add(ScanEvent(
            scan_id=scan_id, phase=phase,
            tool=ev.get("tool", "?"),
            level=ev.get("level", "info"),
            message=ev["message"],
            raw=ev.get("raw"),
        ))
        s.commit()
    publish_sync("scan.event", {
        "scan_id": scan_id, "phase": str(phase),
        "tool": ev.get("tool", "?"), "level": ev.get("level", "info"),
        "message": ev.get("message"), "raw": ev.get("raw")
    })


def _infer_severity(msg: str) -> str:
    """Infer severity level from message."""
    m = msg.upper()
    if "CRITICAL" in m:
        return "critical"
    if "HIGH" in m:
        return "high"
    if "MEDIUM" in m:
        return "medium"
    if "LOW" in m:
        return "low"
    return "info"


def _persist_finding(scan_id: str, ev: dict) -> None:
    """Persist a finding to database."""
    with session_ctx() as s:
        finding = Finding(
            scan_id=scan_id,
            title=ev["message"][:200],
            severity=_infer_severity(ev["message"]),
            tool=ev.get("tool"),
            evidence=ev.get("raw"),
        )
        s.add(finding)
        s.commit()
        s.refresh(finding)
        payload = finding.model_dump(mode="json")
    publish_sync("finding.created", payload)


def _run_hunter_postprocess(scan_id: str, auto_report: bool = True) -> None:
    """Build the full Hunter intelligence layer after a scan completes."""
    try:
        from api.intelligence import attack_graph, hypothesis_engine, adaptive_planner
        from api.reporting import report_agent
        from api.quality import quality_engine
        with session_ctx() as s:
            graph = attack_graph.build(s, scan_id)
            hypotheses = hypothesis_engine.generate(s, scan_id)
            graph = attack_graph.build(s, scan_id)
            plans = adaptive_planner.plan(s, scan_id)
            findings = s.exec(
                select(Finding)
                .where(Finding.scan_id == scan_id)
                .where(Finding.false_positive == False)  # noqa: E712
            ).all()
            report_id = None
            if auto_report and findings:
                report = report_agent.generate(s, scan_id, finding_id=findings[0].id)
                report_id = report.get("id")
            quality = quality_engine.evaluate_scan(s, scan_id, replace_existing=True)
        publish_sync("hunter.postprocess.complete", {
            "scan_id": scan_id, "graph": graph.get("summary", {}),
            "hypotheses": len(hypotheses), "plans": len(plans),
            "report_id": report_id, "quality": quality.get("summary", {}),
        })
        avg_score = quality['summary']['average_score']
        _log(
            scan_id,
            f"🧠 Hunter post-processing complete: {len(hypotheses)} hypotheses, "
            f"{len(plans)} ranked actions, quality {avg_score}/100"
        )
    except Exception as exc:
        _log(scan_id, f"Hunter post-processing warning: {exc}", level="warn")


# ─── Passive scan pipeline ────────────────────────────────────────────────────

async def _run_passive_scan(
    scan_id: str,
    target_domain: str,
    config: dict,
    target: Target,
) -> None:
    """Run a passive security scan."""
    _active_scans.add(scan_id)
    try:
        await _update_status(scan_id, ScanStatus.RUNNING, ScanPhase.RECON)
        _log(scan_id, f"🕵️ PASSIVE MODE — Zero-touch OSINT scan starting on {target_domain}")
        _log(scan_id, f"Available passive tools: {list(get_passive_tools().keys())}")

        # Run passive-safe recon tools
        from api.tools.discovery import RECON_TOOLS, refresh_remote_tools
        refresh_remote_tools()
        enabled = config.get("recon_tools", list(RECON_TOOLS.keys()))
        passive = get_passive_tools()

        for tname in enabled:
            if scan_id in _cancelled_scans:
                break
            tool = passive.get(tname)
            if not tool:
                continue
            async for ev in tool.run(
                scan_id,
                target_domain,
                execution_mode=config.get("execution_mode"),
                runner_id=config.get("runner_id")
            ):
                _persist_event(scan_id, ev, ScanPhase.RECON)
                if ev.get("level") == "finding":
                    _persist_finding(scan_id, ev)
                if scan_id in _cancelled_scans:
                    break

        if scan_id in _cancelled_scans:
            await _update_status(scan_id, ScanStatus.FAILED)
            return

        # Passive AI Agent
        await _update_status(scan_id, ScanStatus.RUNNING, ScanPhase.EXPLOIT)
        if not config.get("skip_ai", False):
            from api.agents.passive_agent import run_passive_agent
            await run_passive_agent(
                scan_id=scan_id,
                target_domain=target_domain,
                scope=target.scope,
                out_of_scope=target.out_of_scope,
                max_iterations=config.get("ai_max_iterations", 20),
            )

        await _update_status(scan_id, ScanStatus.DONE)
        if not config.get("skip_hunter", False):
            _run_hunter_postprocess(scan_id, auto_report=config.get("auto_report", True))

    except Exception as e:
        _log(scan_id, f"Passive scan error: {e}", level="error")
        await _update_status(scan_id, ScanStatus.FAILED)
    finally:
        _active_scans.discard(scan_id)
        _cancelled_scans.discard(scan_id)


# ─── Aggressive scan pipeline ─────────────────────────────────────────────────

async def _run_aggressive_scan(
    scan_id: str,
    target_domain: str,
    config: dict,
    target: Target,
) -> None:
    """Run an aggressive security scan."""
    _active_scans.add(scan_id)
    try:
        await _update_status(scan_id, ScanStatus.RUNNING, ScanPhase.RECON)
        _log(scan_id, f"⚔️ AGGRESSIVE MODE — Full offensive scan starting on {target_domain}")
        _log(scan_id, f"Total available tools: {len(ALL_TOOLS)}")

        from api.tools.discovery import RECON_TOOLS, refresh_remote_tools
        refresh_remote_tools()
        enabled_recon = config.get("recon_tools", list(RECON_TOOLS.keys()))
        for tname in enabled_recon:
            if scan_id in _cancelled_scans:
                break
            tool = ALL_TOOLS.get(tname)
            if not tool:
                continue
            async for ev in tool.run(
                scan_id,
                target_domain,
                execution_mode=config.get("execution_mode"),
                runner_id=config.get("runner_id")
            ):
                _persist_event(scan_id, ev, ScanPhase.RECON)
                if ev.get("level") == "finding":
                    _persist_finding(scan_id, ev)
                if scan_id in _cancelled_scans:
                    break

        if scan_id in _cancelled_scans:
            await _update_status(scan_id, ScanStatus.FAILED)
            return

        await _update_status(scan_id, ScanStatus.RUNNING, ScanPhase.VULNSCAN)

        from api.tools.discovery import VULNSCAN_TOOLS
        enabled_vuln = config.get("vulnscan_tools", list(VULNSCAN_TOOLS.keys()))
        for tname in enabled_vuln:
            if scan_id in _cancelled_scans:
                break
            tool = ALL_TOOLS.get(tname)
            if not tool:
                continue
            async for ev in tool.run(
                scan_id,
                target_domain,
                execution_mode=config.get("execution_mode"),
                runner_id=config.get("runner_id")
            ):
                _persist_event(scan_id, ev, ScanPhase.VULNSCAN)
                if ev.get("level") == "finding":
                    _persist_finding(scan_id, ev)
                if scan_id in _cancelled_scans:
                    break

        if scan_id in _cancelled_scans:
            await _update_status(scan_id, ScanStatus.FAILED)
            return

        # Aggressive AI agent
        await _update_status(scan_id, ScanStatus.RUNNING, ScanPhase.EXPLOIT)
        if not config.get("skip_ai", False):
            from api.agents.aggressive_agent import run_aggressive_agent
            await run_aggressive_agent(
                scan_id=scan_id,
                target_domain=target_domain,
                scope=target.scope,
                out_of_scope=target.out_of_scope,
                max_iterations=config.get("ai_max_iterations", 40),
            )

        await _update_status(scan_id, ScanStatus.DONE)
        if not config.get("skip_hunter", False):
            _run_hunter_postprocess(scan_id, auto_report=config.get("auto_report", True))

    except Exception as e:
        _log(scan_id, f"Aggressive scan error: {e}", level="error")
        await _update_status(scan_id, ScanStatus.FAILED)
    finally:
        _active_scans.discard(scan_id)
        _cancelled_scans.discard(scan_id)


# ─── Routes ──────────────────────────────────────────────────────────────────

@router.get("/", response_model=List[Scan])
def list_scans(session: Session = Depends(get_session)) -> List[Scan]:
    """List all scans ordered by creation date (newest first)."""
    return session.exec(select(Scan).order_by(Scan.created_at.desc())).all()


@router.post("/", response_model=Scan, status_code=201)
def create_scan(
    data: ScanCreate,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
) -> Scan:
    """Create a new scan."""
    target = session.get(Target, data.target_id)
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    config = json.loads(data.config) if data.config else {}
    mode = ScanMode(data.mode) if data.mode else ScanMode.PASSIVE

    scan = Scan(target_id=data.target_id, config=data.config, mode=mode)
    session.add(scan)
    session.commit()
    session.refresh(scan)

    orchestrator = ScanOrchestrator(
        passive_runner=_run_passive_scan,
        aggressive_runner=_run_aggressive_scan,
    )
    config["mode"] = mode
    background_tasks.add_task(orchestrator.run, scan.id, target.domain, config, target)

    return scan


@router.get("/{scan_id}", response_model=Scan)
def get_scan(scan_id: str, session: Session = Depends(get_session)) -> Scan:
    """Get a specific scan by ID."""
    scan_obj = session.get(Scan, scan_id)
    if not scan_obj:
        raise HTTPException(status_code=404, detail="Scan not found")
    return scan_obj


@router.post("/{scan_id}/cancel")
async def cancel_scan(
    scan_id: str,
    session: Session = Depends(get_session),
) -> Dict[str, Any]:
    """Cancel a running scan."""
    scan_obj = session.get(Scan, scan_id)
    if not scan_obj:
        raise HTTPException(status_code=404, detail="Scan not found")
    _cancelled_scans.add(scan_id)
    from api.runners.manager import runner_manager
    remote_cancelled = await runner_manager.cancel_scan_jobs(scan_id)
    return {"detail": "Cancellation requested", "remote_jobs_cancelled": remote_cancelled}


@router.get("/{scan_id}/events", response_model=List[ScanEvent])
def get_events(
    scan_id: str,
    level: str = None,
    session: Session = Depends(get_session),
) -> List[ScanEvent]:
    """Get all events for a scan."""
    query = select(ScanEvent).where(ScanEvent.scan_id == scan_id)
    if level:
        query = query.where(ScanEvent.level == level)
    return session.exec(query.order_by(ScanEvent.created_at)).all()


@router.get("/{scan_id}/findings", response_model=List[Finding])
def get_findings(
    scan_id: str,
    session: Session = Depends(get_session),
) -> List[Finding]:
    """Get all findings for a scan."""
    return session.exec(
        select(Finding)
        .where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at.desc())
    ).all()
