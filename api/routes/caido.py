"""
BountyOS - Caido Integration

Caido is a modern web proxy for security testing (caido.io).
This connector:
  1. Pushes confirmed BountyOS findings into Caido's project
  2. Pulls Caido's intercepted HTTP requests for AI analysis
  3. Imports Caido replay items as attack targets
  4. Exports BountyOS scan reports in Caido-compatible format

Caido API: GraphQL at http://localhost:8080/graphql
Auth: Bearer token from Caido settings → API keys

Setup:
  1. Open Caido → Settings → API → Create API Key
  2. Set env var: CAIDO_API_TOKEN=your_token_here
  3. Set env var: CAIDO_URL=http://localhost:8080 (default)
"""

import os
import json
import asyncio
from datetime import datetime
from typing import Optional, List
import httpx

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from pydantic import BaseModel

from api.database import get_session
from api.models import Finding, Scan, Target

router = APIRouter(prefix="/integrations/caido", tags=["integrations"])

CAIDO_URL   = os.getenv("CAIDO_URL",       "http://localhost:8080")
CAIDO_TOKEN = os.getenv("CAIDO_API_TOKEN", "")


# ─── Caido GraphQL client ─────────────────────────────────────────────────────

class CaidoClient:
    def __init__(self, base_url: str, token: str):
        self.base_url = base_url.rstrip("/")
        self.graphql  = f"{self.base_url}/graphql"
        self.headers  = {
            "Content-Type":  "application/json",
            "Authorization": f"Bearer {token}",
        }

    async def query(self, query: str, variables: dict = None) -> dict:
        async with httpx.AsyncClient(timeout=15) as client:
            res = await client.post(
                self.graphql,
                headers=self.headers,
                json={"query": query, "variables": variables or {}},
            )
            res.raise_for_status()
            data = res.json()
            if "errors" in data:
                raise ValueError(f"Caido GraphQL error: {data['errors']}")
            return data.get("data", {})

    async def ping(self) -> bool:
        try:
            data = await self.query("{ viewer { username } }")
            return bool(data.get("viewer", {}).get("username"))
        except Exception:
            return False

    async def get_requests(self, limit: int = 100) -> List[dict]:
        """Pull intercepted HTTP requests from Caido."""
        q = """
        query GetRequests($first: Int) {
          requests(first: $first) {
            edges {
              node {
                id
                host
                port
                path
                method
                query
                headers { name value }
                response { statusCode }
              }
            }
          }
        }
        """
        try:
            data = await self.query(q, {"first": limit})
            edges = data.get("requests", {}).get("edges", [])
            return [e["node"] for e in edges]
        except Exception:
            return []

    async def create_finding(self, title: str, severity: str,
                              description: str, request_id: str = None) -> Optional[str]:
        """Push a finding into Caido."""
        # Caido uses its own finding/issue system
        # Map BountyOS severity to Caido severity
        sev_map = {
            "critical": "CRITICAL", "high": "HIGH",
            "medium": "MEDIUM",     "low": "LOW", "info": "INFO",
        }
        q = """
        mutation CreateFinding($title: String!, $severity: FindingSeverity!, $description: String!) {
          createFinding(input: { title: $title, severity: $severity, description: $description }) {
            finding { id title }
          }
        }
        """
        try:
            data = await self.query(q, {
                "title":       title,
                "severity":    sev_map.get(severity, "INFO"),
                "description": description,
            })
            fid = data.get("createFinding", {}).get("finding", {}).get("id")
            return fid
        except Exception:
            return None

    async def get_projects(self) -> List[dict]:
        q = "{ projects { id name } }"
        try:
            data = await self.query(q)
            return data.get("projects", [])
        except Exception:
            return []


def _get_client() -> CaidoClient:
    if not CAIDO_TOKEN:
        raise HTTPException(503, "CAIDO_API_TOKEN not set. Add it to your environment.")
    return CaidoClient(CAIDO_URL, CAIDO_TOKEN)


# ─── Routes ───────────────────────────────────────────────────────────────────

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
