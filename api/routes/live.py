"""Realtime dashboard REST + WebSocket routes."""

from __future__ import annotations

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect
from sqlmodel import Session, select

from api.database import get_session
from api.models import Scan, Finding, Approval, ApprovalStatus, ScanEvent, BountyProgram, BountyAccount
from api.realtime import hub, recent_events, get_agent_state

router = APIRouter(prefix="/live", tags=["live"])
ws_router = APIRouter(tags=["live-ws"])


@router.get("/status")
def live_status():
    return {"status": "ok", "stream": "/ws/live", "agent": get_agent_state()}


@router.get("/snapshot")
def live_snapshot(session: Session = Depends(get_session)):
    scans = session.exec(select(Scan).order_by(Scan.created_at.desc())).all()
    findings = session.exec(select(Finding).order_by(Finding.created_at.desc())).all()
    approvals = session.exec(
        select(Approval).where(Approval.status == ApprovalStatus.PENDING).order_by(Approval.created_at.desc())
    ).all()
    scan_events = session.exec(select(ScanEvent).order_by(ScanEvent.created_at.desc())).all()
    programs = session.exec(select(BountyProgram).order_by(BountyProgram.last_seen_at.desc())).all()
    accounts = session.exec(select(BountyAccount).order_by(BountyAccount.created_at.desc())).all()
    return {
        "agent": get_agent_state(),
        "active_scans": [s.model_dump(mode="json") for s in scans if str(s.status).endswith("running")][:20],
        "recent_scans": [s.model_dump(mode="json") for s in scans[:20]],
        "recent_findings": [f.model_dump(mode="json") for f in findings[:30]],
        "pending_approvals": [a.model_dump(mode="json") for a in approvals[:30]],
        "recent_programs": [p.model_dump(mode="json") for p in programs[:30]],
        "bounty_accounts": [{k:v for k,v in a.model_dump(mode="json").items() if k != "token_encrypted"} for a in accounts[:20]],
        "recent_scan_events": [e.model_dump(mode="json") for e in scan_events[:80]],
        "live_events": recent_events(100),
    }


@ws_router.websocket("/ws/live")
async def live_ws(ws: WebSocket):
    await hub.connect(ws)
    try:
        while True:
            msg = await ws.receive_text()
            if msg == "ping":
                await ws.send_text("pong")
    except WebSocketDisconnect:
        hub.disconnect(ws)
