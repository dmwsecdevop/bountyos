"""Chrome DevTools MCP integration for safe, in-scope browser evidence."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

from api.services.scope_guard import is_target_in_scope, normalize_host


class BrowserMCPError(RuntimeError):
    """Clean browser MCP integration error."""


@dataclass
class BrowserSnapshot:
    current_url: str | None
    console_logs: list[dict[str, Any]]
    network_requests: list[dict[str, Any]]
    screenshots: list[dict[str, Any]]
    js_endpoints: list[str]
    auth_flows: list[str]
    raw: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "current_url": self.current_url,
            "console_logs": self.console_logs,
            "network_requests": self.network_requests,
            "screenshots": self.screenshots,
            "js_endpoints": self.js_endpoints,
            "auth_flows": self.auth_flows,
            "raw": self.raw,
        }


class BrowserMCPClient:
    def __init__(self, base_url: str | None = None) -> None:
        self.base_url = (base_url or os.getenv("CHROME_DEVTOOLS_MCP_URL") or os.getenv("BROWSER_MCP_URL") or "").rstrip("/")
        self.enabled = bool(self.base_url)

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self.enabled,
            "configured": self.enabled,
            "url": self.base_url or None,
            "model": os.getenv("BOUNTYOS_BROWSER_MODEL", "gemini-3.5-flash"),
        }

    async def _get_optional(self, path: str) -> Any:
        if not self.enabled:
            raise BrowserMCPError("Chrome DevTools MCP is not configured. Set CHROME_DEVTOOLS_MCP_URL.")
        async with httpx.AsyncClient(timeout=10) as client:
            response = await client.get(f"{self.base_url}{path}")
            if response.status_code == 404:
                return None
            response.raise_for_status()
            return response.json()

    @staticmethod
    def _extract_urls(value: Any) -> list[str]:
        text = value if isinstance(value, str) else str(value or "")
        found = re.findall(r"(?:(?:https?:)?//[^'\"\s)]+|/[A-Za-z0-9_./?=&%:-]+)", text)
        return sorted({item for item in found if len(item) > 1})[:200]

    @staticmethod
    def _detect_auth_flows(requests: list[dict[str, Any]], logs: list[dict[str, Any]]) -> list[str]:
        joined = "\n".join(str(x).lower() for x in [*requests, *logs])
        flows: list[str] = []
        checks = {
            "login/session flow": ["login", "session", "csrf"],
            "JWT/bearer token flow": ["authorization", "bearer", "jwt"],
            "OAuth/OIDC flow": ["oauth", "openid", "authorize", "callback"],
            "role/tenant boundary": ["role", "tenant", "organization", "workspace"],
        }
        for label, terms in checks.items():
            if any(term in joined for term in terms):
                flows.append(label)
        return flows

    @staticmethod
    def _scope_roots(target: dict[str, Any] | None) -> list[str]:
        if not target:
            return []
        roots = [target.get("domain", "")]
        for field in (target.get("scope") or "").replace(",", "\n").splitlines():
            roots.append(field.strip())
        return [normalize_host(root) for root in roots if root.strip()]

    async def collect_snapshot(self, target: dict[str, Any] | None = None) -> BrowserSnapshot:
        if not self.enabled:
            raise BrowserMCPError("Chrome DevTools MCP is disabled. Set CHROME_DEVTOOLS_MCP_URL to enable browser analysis.")

        status = await self._get_optional("/status") or {}
        page = await self._get_optional("/page") or await self._get_optional("/current-page") or {}
        console_logs = await self._get_optional("/console") or await self._get_optional("/logs") or []
        network_requests = await self._get_optional("/network") or await self._get_optional("/requests") or []
        screenshots = await self._get_optional("/screenshots") or []

        current_url = page.get("url") or status.get("url") or status.get("current_url")
        roots = self._scope_roots(target)
        if roots and current_url and not is_target_in_scope(current_url, roots):
            raise BrowserMCPError(f"Browser page {current_url} is outside approved target scope")

        raw = {"status": status, "page": page, "console": console_logs, "network": network_requests, "screenshots": screenshots}
        js_endpoints = sorted({*self._extract_urls(raw), *[str(req.get("url") or req.get("path") or "") for req in network_requests if isinstance(req, dict)]})[:200]
        return BrowserSnapshot(
            current_url=current_url,
            console_logs=console_logs if isinstance(console_logs, list) else [console_logs],
            network_requests=network_requests if isinstance(network_requests, list) else [network_requests],
            screenshots=screenshots if isinstance(screenshots, list) else [screenshots],
            js_endpoints=js_endpoints,
            auth_flows=self._detect_auth_flows(network_requests if isinstance(network_requests, list) else [], console_logs if isinstance(console_logs, list) else []),
            raw=raw,
        )
