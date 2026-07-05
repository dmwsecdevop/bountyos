"""Caido proxy integration for importing traffic and Gemini-assisted analysis."""

from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any

import httpx

from api.integrations.gemini_client import GeminiClient
from api.services.scope_guard import is_target_in_scope, normalize_host


class CaidoConfigError(RuntimeError):
    """Raised when Caido is not configured."""


class CaidoSafetyError(RuntimeError):
    """Raised when Caido traffic is outside approved target scope."""


@dataclass
class CaidoAnalysis:
    summary: str
    issues: list[str]
    model_used: str
    raw: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {"summary": self.summary, "issues": self.issues, "model_used": self.model_used, "raw": self.raw}


class CaidoClient:
    def __init__(self, base_url: str | None = None, token: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("CAIDO_URL") or "http://localhost:8080").rstrip("/")
        self.token = token if token is not None else os.getenv("CAIDO_API_TOKEN", "")
        self.graphql = f"{self.base_url}/graphql"

    def status(self) -> dict[str, Any]:
        return {
            "configured": bool(self.token),
            "connected": False,
            "url": self.base_url,
            "token_set": bool(self.token),
            "model": os.getenv("BOUNTYOS_CAIDO_MODEL", "gemini-1.5-flash"),
        }

    def _headers(self) -> dict[str, str]:
        if not self.token:
            raise CaidoConfigError("CAIDO_API_TOKEN is not configured")
        return {"Authorization": f"Bearer {self.token}", "Content-Type": "application/json"}

    async def query(self, query: str, variables: dict[str, Any] | None = None) -> dict[str, Any]:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(self.graphql, headers=self._headers(), json={"query": query, "variables": variables or {}})
            response.raise_for_status()
            data = response.json()
            if data.get("errors"):
                raise RuntimeError(f"Caido GraphQL error: {data['errors']}")
            return data.get("data", {})

    async def ping(self) -> bool:
        if not self.token:
            return False
        try:
            data = await self.query("{ viewer { username } }")
            return bool(data.get("viewer"))
        except Exception:
            return False

    async def import_history(self, limit: int = 100) -> list[dict[str, Any]]:
        q = """
        query GetRequests($first: Int) {
          requests(first: $first) {
            edges { node { id host port path method query headers { name value } response { statusCode } } }
          }
        }
        """
        data = await self.query(q, {"first": limit})
        return [edge.get("node", {}) for edge in data.get("requests", {}).get("edges", [])]

    @staticmethod
    def _scope_roots(target: dict[str, Any] | None) -> list[str]:
        if not target:
            return []
        roots = [target.get("domain", "")]
        roots += [x.strip() for x in (target.get("scope") or "").replace(",", "\n").splitlines() if x.strip()]
        return [normalize_host(root) for root in roots if root]

    def assert_request_in_scope(self, request: dict[str, Any], target: dict[str, Any] | None) -> None:
        roots = self._scope_roots(target)
        host = request.get("host") or request.get("url") or ""
        if roots and host and not is_target_in_scope(str(host), roots):
            raise CaidoSafetyError(f"Caido request host {host} is outside approved target scope")

    async def analyze_request(self, request: dict[str, Any], target: dict[str, Any] | None = None) -> CaidoAnalysis:
        self.assert_request_in_scope(request, target)
        model = os.getenv("BOUNTYOS_CAIDO_MODEL", "gemini-1.5-flash")
        prompt = (
            "Analyze this authorized Caido HTTP request/response for IDOR, auth bypass, SSRF, GraphQL authorization, "
            "JWT issues, CORS mistakes, and exposed secrets. Return concise operational findings, evidence, confidence, "
            "and the next least-intrusive safe action. Do not propose random exploitation.\n\n"
            f"REQUEST:\n{request}\n"
        )
        gemini = GeminiClient()
        result = await gemini.chat(prompt, context={"source": "caido", "target": target or {}}, model=model)
        keywords = ["IDOR", "auth bypass", "SSRF", "GraphQL", "JWT", "CORS", "exposed secrets"]
        return CaidoAnalysis(summary=result.text, issues=keywords, model_used=result.model, raw={"request": request, "target": target or {}})
