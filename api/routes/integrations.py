"""
BountyOS - Desktop Tool Integrations

Connectors for popular pentesting desktop tools:
  - Burp Suite Professional (REST API on port 1337)
  - OWASP ZAP (REST API on port 8090)
  - Metasploit RPC (msfrpcd on port 55553)
  - CherryTree / Obsidian note export
"""

import os
import json
import asyncio
import base64
import logging
from typing import Optional, List
import httpx

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from pydantic import BaseModel

from api.database import get_session
from api.models import Finding, Scan, Target

router = APIRouter(prefix="/integrations", tags=["integrations"])
logger = logging.getLogger(__name__)


# ═══════════════════════════════════════════════════════════════════════════════
# BURP SUITE PROFESSIONAL
# ═══════════════════════════════════════════════════════════════════════════════

BURP_URL    = os.getenv("BURP_URL",    "http://localhost:1337")
BURP_APIKEY = os.getenv("BURP_APIKEY", "")

class BurpClient:
    def __init__(self):
        self.base = f"{BURP_URL}/v0.1"
        self.headers = {"Authorization": f"Bearer {BURP_APIKEY}"} if BURP_APIKEY else {}

    async def get(self, path: str) -> dict:
        async with httpx.AsyncClient(timeout=10) as c:
            r = await c.get(f"{self.base}{path}", headers=self.headers)
            r.raise_for_status()
            return r.json()

    async def post(self, path: str, data: dict) -> dict:
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.post(f"{self.base}{path}", headers={**self.headers, "Content-Type": "application/json"}, json=data)
            r.raise_for_status()
            return r.json()

    async def ping(self) -> bool:
        try:
            await self.get("/")
            return True
        except Exception:
            return False

    async def get_issues(self) -> List[dict]:
        try:
            data = await self.get("/issue-definitions")
            return data if isinstance(data, list) else []
        except Exception:
            return []

    async def start_scan(self, url: str) -> Optional[str]:
        try:
            data = await self.post("/scan", {
                "urls": [url],
                "scope": {"include": [{"rule": url}]},
            })
            return data.get("task_id")
        except Exception:
            return None

    async def get_scan_status(self, task_id: str) -> dict:
        try:
            return await self.get(f"/scan/{task_id}")
        except Exception:
            return {}


@router.get("/burp/status")
async def burp_status():
    client = BurpClient()
    alive  = await client.ping()
    return {"connected": alive, "url": BURP_URL, "api_key_set": bool(BURP_APIKEY)}


@router.post("/burp/scan")
async def burp_start_scan(url: str):
    client  = BurpClient()
    task_id = await client.start_scan(url)
    if not task_id:
        raise HTTPException(502, "Failed to start Burp scan. Is Burp Suite running with REST API enabled?")
    return {"task_id": task_id, "url": url, "message": "Burp scan started"}


@router.post("/burp/push/{scan_id}")
async def push_to_burp(scan_id: str, session: Session = Depends(get_session)):
    """Export BountyOS scan targets to Burp Suite for manual testing."""
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    target = session.get(Target, scan.target_id)
    client  = BurpClient()
    task_id = await client.start_scan(f"https://{target.domain}")
    return {"message": f"Target pushed to Burp Suite", "task_id": task_id, "target": target.domain}


# ═══════════════════════════════════════════════════════════════════════════════
# OWASP ZAP
# ═══════════════════════════════════════════════════════════════════════════════

ZAP_URL    = os.getenv("ZAP_URL",    "http://localhost:8090")
ZAP_APIKEY = os.getenv("ZAP_APIKEY", "bountyos")

class ZAPClient:
    def __init__(self):
        self.base   = ZAP_URL
        self.apikey = ZAP_APIKEY

    async def _call(self, component: str, action_type: str, name: str, params: dict = None) -> dict:
        url = f"{self.base}/{component}/{action_type}/{name}/"
        qp  = {"apikey": self.apikey, **(params or {})}
        async with httpx.AsyncClient(timeout=30) as c:
            r = await c.get(url, params=qp)
            r.raise_for_status()
            return r.json()

    async def ping(self) -> bool:
        try:
            await self._call("core", "view", "version")
            return True
        except Exception:
            return False

    async def spider(self, url: str) -> str:
        data = await self._call("spider", "action", "scan", {"url": url})
        return data.get("scan", "")

    async def active_scan(self, url: str) -> str:
        data = await self._call("ascan", "action", "scan", {"url": url})
        return data.get("scan", "")

    async def get_alerts(self, url: str = "") -> List[dict]:
        params = {"url": url} if url else {}
        try:
            data = await self._call("core", "view", "alerts", params)
            return data.get("alerts", [])
        except Exception:
            return []

    async def get_scan_progress(self, scan_id: str) -> int:
        try:
            data = await self._call("ascan", "view", "status", {"scanId": scan_id})
            return int(data.get("status", 0))
        except Exception:
            return 0


@router.get("/zap/status")
async def zap_status():
    client = ZAPClient()
    alive  = await client.ping()
    return {"connected": alive, "url": ZAP_URL}


@router.post("/zap/spider")
async def zap_spider(url: str):
    client  = ZAPClient()
    scan_id = await client.spider(url)
    return {"scan_id": scan_id, "url": url, "message": "ZAP spider started"}


@router.post("/zap/active-scan")
async def zap_active_scan(url: str):
    client  = ZAPClient()
    scan_id = await client.active_scan(url)
    return {"scan_id": scan_id, "url": url, "message": "ZAP active scan started"}


@router.get("/zap/alerts")
async def zap_alerts(url: str = ""):
    client = ZAPClient()
    alerts = await client.get_alerts(url)
    return {"count": len(alerts), "alerts": alerts[:50]}


@router.post("/zap/import-alerts/{scan_id}")
async def import_zap_alerts_as_findings(
    scan_id: str, url: str = "",
    session: Session = Depends(get_session)
):
    """Import ZAP alerts as BountyOS findings."""
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    client = ZAPClient()
    alerts = await client.get_alerts(url)

    sev_map = {"High": "high", "Medium": "medium", "Low": "low", "Informational": "info"}
    imported = 0
    for alert in alerts[:100]:
        f = Finding(
            scan_id=scan_id,
            title=alert.get("name", "ZAP Alert"),
            severity=sev_map.get(alert.get("risk", "Low"), "info"),
            description=alert.get("description", ""),
            evidence=alert.get("evidence", ""),
            url=alert.get("url", ""),
            cwe_id=f"CWE-{alert.get('cweid','')}" if alert.get("cweid") else None,
            remediation=alert.get("solution", ""),
            tool="zap",
        )
        session.add(f)
        imported += 1
    session.commit()
    return {"imported": imported, "message": f"Imported {imported} ZAP alerts as BountyOS findings"}


# ═══════════════════════════════════════════════════════════════════════════════
# METASPLOIT RPC
# ═══════════════════════════════════════════════════════════════════════════════

MSF_RPC_HOST = os.getenv("MSF_RPC_HOST",     "127.0.0.1")
MSF_RPC_PORT = int(os.getenv("MSF_RPC_PORT", "55553"))
MSF_RPC_PASS = os.getenv("MSF_RPC_PASS",     "bountyos123")
MSF_RPC_SSL  = os.getenv("MSF_RPC_SSL",      "true").lower() == "true"

class MSFRPCClient:
    """
    Metasploit RPC client using msgpack HTTP API.
    Start msfrpcd: msfrpcd -P bountyos123 -S -f
    """
    def __init__(self):
        scheme      = "https" if MSF_RPC_SSL else "http"
        self.url    = f"{scheme}://{MSF_RPC_HOST}:{MSF_RPC_PORT}/api/1.0"
        self.token  = None

    async def _post(self, data: dict) -> dict:
        import msgpack
        async with httpx.AsyncClient(verify=False, timeout=30) as c:
            r = await c.post(
                self.url,
                content=msgpack.dumps(data),
                headers={"Content-Type": "binary/message-pack"},
            )
            return msgpack.loads(r.content)

    async def login(self) -> bool:
        try:
            import msgpack
        except ImportError:
            return False
        try:
            data = await self._post(["auth.login", "msf", MSF_RPC_PASS])
            self.token = data.get(b"token", b"").decode()
            return bool(self.token)
        except Exception:
            return False

    async def call(self, method: str, *args) -> dict:
        if not self.token:
            await self.login()
        try:
            return await self._post([method, self.token, *args])
        except Exception:
            logger.exception("Metasploit RPC call failed for method '%s'", method)
            return {"error": "Metasploit RPC request failed"}

    async def module_search(self, query: str) -> List[dict]:
        data = await self.call("module.search", query)
        return data.get(b"modules", []) if isinstance(data, dict) else []

    async def get_sessions(self) -> dict:
        data = await self.call("session.list")
        return data if isinstance(data, dict) else {}

    async def run_module(self, module_type: str, module_name: str,
                          options: dict) -> dict:
        data = await self.call(f"module.execute", module_type, module_name, options)
        return data


@router.get("/metasploit/status")
async def msf_status():
    client = MSFRPCClient()
    ok     = await client.login()
    return {
        "connected": ok,
        "host":      MSF_RPC_HOST,
        "port":      MSF_RPC_PORT,
        "note":      "Start msfrpcd with: msfrpcd -P bountyos123 -S -f",
    }


@router.get("/metasploit/sessions")
async def msf_sessions():
    client = MSFRPCClient()
    await client.login()
    sessions = await client.get_sessions()
    return {"sessions": sessions}


@router.post("/metasploit/search")
async def msf_search(query: str):
    client  = MSFRPCClient()
    await client.login()
    results = await client.module_search(query)
    return {"results": results[:20]}


# ═══════════════════════════════════════════════════════════════════════════════
# NOTE EXPORT (CherryTree / Obsidian / Markdown)
# ═══════════════════════════════════════════════════════════════════════════════

@router.get("/export/{scan_id}/markdown")
async def export_markdown(scan_id: str, session: Session = Depends(get_session)):
    """Export a full scan report as Markdown (Obsidian / CherryTree compatible)."""
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    target   = session.get(Target, scan.target_id)
    findings = session.exec(
        select(Finding).where(Finding.scan_id == scan_id)
        .order_by(Finding.severity)
    ).all()

    sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    findings  = sorted(findings, key=lambda f: sev_order.get(f.severity, 5))

    md = [
        f"# BountyOS Scan Report",
        f"",
        f"**Target:** {target.domain if target else 'Unknown'}",
        f"**Scan ID:** `{scan_id}`",
        f"**Mode:** {scan.mode}",
        f"**Status:** {scan.status}",
        f"**Date:** {scan.created_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"",
        f"---",
        f"",
        f"## Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
    ]
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = sum(1 for f in findings if f.severity == sev)
        md.append(f"| {sev.upper()} | {count} |")

    md += ["", "---", "", "## Findings", ""]
    for i, f in enumerate(findings, 1):
        md += [
            f"### {i}. [{f.severity.upper()}] {f.title}",
            f"",
            f"**Tool:** `{f.tool or 'N/A'}`",
        ]
        if f.cwe_id:
            md.append(f"**CWE:** {f.cwe_id}")
        if f.cvss_score:
            md.append(f"**CVSS:** {f.cvss_score}")
        if f.url:
            md.append(f"**URL:** `{f.url}`")
        if f.description:
            md += ["", f.description]
        if f.evidence:
            md += ["", "**Evidence:**", f"```", f.evidence[:500], f"```"]
        if f.remediation:
            md += ["", f"**Remediation:** {f.remediation}"]
        md.append("")

    return {"markdown": "\n".join(md), "filename": f"bountyos_{scan_id[:8]}.md"}


@router.get("/export/{scan_id}/json")
async def export_json(scan_id: str, session: Session = Depends(get_session)):
    """Export scan findings as structured JSON."""
    scan     = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")
    target   = session.get(Target, scan.target_id)
    findings = session.exec(select(Finding).where(Finding.scan_id == scan_id)).all()
    return {
        "scan":     {"id": scan_id, "mode": scan.mode, "status": scan.status},
        "target":   {"domain": target.domain if target else None, "scope": target.scope if target else None},
        "findings": [
            {
                "title":       f.title, "severity": f.severity,
                "cvss":        f.cvss_score, "cwe":  f.cwe_id,
                "url":         f.url,   "tool":       f.tool,
                "description": f.description, "evidence": f.evidence,
                "remediation": f.remediation,
            } for f in findings
        ],
    }

# ═══════════════════════════════════════════════════════════════════════════════
# CHROME DEVTOOLS MCP / BROWSER AGENT
# ═══════════════════════════════════════════════════════════════════════════════

from api.integrations.browser_mcp import BrowserMCPClient, BrowserMCPError
from api.integrations.caido_client import CaidoClient as BountyCaidoClient, CaidoConfigError, CaidoSafetyError
from api.models import ScanEvent, ScanPhase


class BrowserAnalyzeRequest(BaseModel):
    target_id: Optional[str] = None
    scan_id: Optional[str] = None


class CaidoImportRequest(BaseModel):
    limit: int = 100
    target_id: Optional[str] = None
    scan_id: Optional[str] = None


class CaidoAnalyzeRequest(BaseModel):
    request: dict
    target_id: Optional[str] = None
    scan_id: Optional[str] = None


def _target_dict(session: Session, target_id: Optional[str]) -> Optional[dict]:
    if not target_id:
        return None
    target = session.get(Target, target_id)
    if not target:
        raise HTTPException(404, "Target not found")
    return target.model_dump(mode="json")


def _store_event(session: Session, scan_id: Optional[str], tool: str, message: str, raw: dict | None = None) -> None:
    if not scan_id:
        return
    if not session.get(Scan, scan_id):
        raise HTTPException(404, "Scan not found")
    event = ScanEvent(scan_id=scan_id, phase=ScanPhase.RECON, tool=tool, level="info", message=message, raw=json.dumps(raw or {})[:8000])
    session.add(event)
    session.commit()


@router.get("/browser/status")
def browser_mcp_status():
    """Return Chrome DevTools MCP configuration status without leaking secrets."""
    return BrowserMCPClient().status()


@router.post("/browser/analyze")
async def browser_mcp_analyze(body: BrowserAnalyzeRequest, session: Session = Depends(get_session)):
    """Collect current in-scope browser evidence from Chrome DevTools MCP."""
    target = _target_dict(session, body.target_id)
    try:
        snapshot = await BrowserMCPClient().collect_snapshot(target)
        data = snapshot.as_dict()
        _store_event(session, body.scan_id, "browser-mcp", "Browser MCP snapshot imported", data)
        return {
            "ok": True,
            "summary": "Browser MCP snapshot imported for in-scope analysis.",
            "current_url": data["current_url"],
            "console_log_count": len(data["console_logs"]),
            "network_request_count": len(data["network_requests"]),
            "js_endpoints": data["js_endpoints"],
            "auth_flows": data["auth_flows"],
            "evidence": data,
            "model_used": os.getenv("BOUNTYOS_BROWSER_MODEL", "gemini-3.5-flash"),
        }
    except BrowserMCPError as exc:
        logger.exception("Browser MCP analysis failed")
        return {"ok": False, "error": "Unable to analyze browser snapshot at this time.", "summary": "Browser MCP unavailable or outside target scope."}


@router.get("/caido/status")
async def caido_proxy_status():
    """Return Caido configuration and connectivity status without exposing token values."""
    client = BountyCaidoClient()
    status = client.status()
    status["connected"] = await client.ping()
    if not status["token_set"]:
        status["error"] = "CAIDO_API_TOKEN is not configured"
    return status


@router.post("/caido/import-history")
async def caido_import_history(body: CaidoImportRequest, session: Session = Depends(get_session)):
    """Import Caido HTTP history metadata into BountyOS evidence events."""
    target = _target_dict(session, body.target_id)
    client = BountyCaidoClient()
    try:
        requests = await client.import_history(limit=max(1, min(body.limit, 500)))
        in_scope: list[dict] = []
        for request in requests:
            try:
                client.assert_request_in_scope(request, target)
                in_scope.append(request)
            except CaidoSafetyError:
                continue
        _store_event(session, body.scan_id, "caido", f"Imported {len(in_scope)} in-scope Caido requests", {"requests": in_scope[:50]})
        return {"ok": True, "summary": f"Imported {len(in_scope)} in-scope Caido requests.", "count": len(in_scope), "requests": in_scope[:100]}
    except CaidoConfigError as exc:
        return {"ok": False, "error": str(exc), "summary": "Caido token is missing."}
    except Exception as exc:
        raise HTTPException(502, f"Caido import failed: {exc}")


@router.post("/caido/analyze-request")
async def caido_analyze_request(body: CaidoAnalyzeRequest, session: Session = Depends(get_session)):
    """Analyze one selected in-scope Caido request with Gemini 3.5 Flash."""
    target = _target_dict(session, body.target_id)
    client = BountyCaidoClient()
    try:
        analysis = await client.analyze_request(body.request, target)
        data = analysis.as_dict()
        _store_event(session, body.scan_id, "caido", "Caido request analyzed with Gemini", data)
        return {"ok": True, **data}
    except CaidoConfigError as exc:
        return {"ok": False, "error": str(exc), "summary": "Caido token is missing."}
    except CaidoSafetyError as exc:
        logger.warning("Caido safety validation failed: %s", exc)
        return {"ok": False, "error": "Request failed safety validation.", "summary": "Caido request is outside approved scope."}
