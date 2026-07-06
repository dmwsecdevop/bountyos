from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from sqlmodel import Session, select
from typing import Optional, List, Dict
import os
import asyncio
from datetime import datetime

from api.database import get_session
from api.models import Finding, Scan, Target
from api.integrations.caido_client import CaidoClient
from api.agents.caido_analysis_agent import caido_analysis_agent

router = APIRouter(prefix="/integrations/caido", tags=["integrations"])

CAIDO_URL   = os.getenv("CAIDO_URL",       "http://localhost:8080")
CAIDO_TOKEN = os.getenv("CAIDO_API_TOKEN", "")

# ─── WebSocket Manager ────────────────────────────────────────────────────────

class CaidoConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []
        self.last_request_id: Optional[str] = None
        self.polling_task: Optional[asyncio.Task] = None

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)
        if not self.polling_task:
            self.polling_task = asyncio.create_task(self._poll_caido())

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)
        if not self.active_connections and self.polling_task:
            self.polling_task.cancel()
            self.polling_task = None

    async def broadcast(self, data: dict):
        for connection in self.active_connections:
            await connection.send_json(data)

    async def _poll_caido(self):
        client = CaidoClient(CAIDO_URL, CAIDO_TOKEN)
        while self.active_connections:
            try:
                requests = await client.get_requests(limit=10)
                if requests:
                    newest = requests[0]
                    if newest.get("id") != self.last_request_id:
                        self.last_request_id = newest.get("id")
                        
                        # Automated Analysis
                        analysis = await caido_analysis_agent.analyze(newest)
                        
                        await self.broadcast({
                            "request": newest,
                            "analysis": analysis.as_dict() if analysis else None
                        })
                await asyncio.sleep(2)
            except Exception as e:
                print(f"Caido polling/analysis error: {e}")
                await asyncio.sleep(5)

caido_ws_manager = CaidoConnectionManager()

# ─── Helper ──────────────────────────────────────────────────────────────────

def _get_client() -> CaidoClient:
    if not CAIDO_TOKEN:
        raise HTTPException(503, "CAIDO_API_TOKEN not set. Add it to your environment.")
    return CaidoClient(CAIDO_URL, CAIDO_TOKEN)


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.websocket("/ws")
async def caido_ws_stream(websocket: WebSocket):
    """
    WebSocket endpoint — streams live intercepted requests from Caido with AI analysis.
    """
    await caido_ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        caido_ws_manager.disconnect(websocket)

@router.get("/status")
async def caido_status():
    """Check if Caido is reachable and token is valid."""
    if not CAIDO_TOKEN:
        return {"connected": False, "reason": "CAIDO_API_TOKEN not set", "token_set": False, "url": CAIDO_URL, "model": os.getenv("BOUNTYOS_CAIDO_MODEL", "gemini-1.5-flash")}
    client = CaidoClient(CAIDO_URL, CAIDO_TOKEN)
    alive  = await client.ping()
    return {
        "connected": alive,
        "url":       CAIDO_URL,
        "token_set": bool(CAIDO_TOKEN),
        "model": os.getenv("BOUNTYOS_CAIDO_MODEL", "gemini-1.5-flash"),
    }


@router.post("/push/{scan_id}")
async def push_findings_to_caido(scan_id: str, session: Session = Depends(get_session)):
    """
    Push all confirmed findings from a BountyOS scan into Caido as issues.
    """
    client   = _get_client()
    findings = session.exec(
        select(Finding).where(Finding.scan_id == scan_id)
        .where(Finding.false_positive == False)
    ).all()

    if not findings:
        return {"pushed": 0, "message": "No findings to push"}

    pushed   = 0
    failed   = 0
    caido_ids = []

    for f in findings:
        desc = f"{f.description or ''}\n\nEvidence:\n{f.evidence or 'N/A'}"
        if f.url:
            desc += f"\n\nURL: {f.url}"
        if f.cwe_id:
            desc += f"\n\nCWE: {f.cwe_id}"
        if f.remediation:
            desc += f"\n\nRemediation: {f.remediation}"

        fid = await client.create_finding(f.title, f.severity, desc)
        if fid:
            pushed += 1
            caido_ids.append(fid)
        else:
            failed += 1

    return {
        "pushed":    pushed,
        "failed":    failed,
        "caido_ids": caido_ids,
        "message":   f"Pushed {pushed}/{len(findings)} findings to Caido",
    }


@router.get("/requests")
async def pull_caido_requests(limit: int = 50):
    """
    Pull intercepted HTTP requests from Caido.
    These can be fed to the AI agent as attack targets.
    """
    client   = _get_client()
    requests = await client.get_requests(limit)
    return {
        "count":    len(requests),
        "requests": requests,
    }


@router.post("/import-request/{request_id}")
async def import_caido_request_as_target(
    request_id: str,
    session: Session = Depends(get_session),
):
    """
    Import a specific Caido intercepted request as a BountyOS scan target.
    The AI agent will analyse the request for injection points.
    """
    client   = _get_client()
    requests = await client.get_requests(200)
    req      = next((r for r in requests if r["id"] == request_id), None)

    if not req:
        raise HTTPException(404, "Request not found in Caido")

    host = req.get("host", "")
    path = req.get("path", "/")
    port = req.get("port", 443)
    scheme = "https" if port == 443 else "http"
    url  = f"{scheme}://{host}{path}"
    if req.get("query"):
        url += f"?{req['query']}"

    return {
        "imported_url":    url,
        "method":          req.get("method", "GET"),
        "host":            host,
        "message":         f"Ready to scan: {url}. Create a target with domain={host} and launch a scan.",
    }


@router.get("/projects")
async def list_caido_projects():
    client   = _get_client()
    projects = await client.get_projects()
    return {"projects": projects}
