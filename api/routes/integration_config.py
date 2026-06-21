"""Masked integration configuration endpoints for BountyOS.

These routes support the dashboard Integrations page. They never return raw
secret values. Values are written to the runtime .env file and os.environ so
connection checks can run immediately.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Callable, Dict, List

import httpx
from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/integrations/config", tags=["integrations-config"])

ENV_PATH = Path(os.getenv("BOUNTYOS_ENV_FILE", ".env")).resolve()

INTEGRATIONS: dict[str, list[str]] = {
    "gemini": ["GEMINI_API_KEY", "BOUNTYOS_CHAT_MODEL", "BOUNTYOS_AGENTIC_MODEL"],
    "browser": ["CHROME_DEVTOOLS_MCP_URL"],
    "caido": ["CAIDO_URL", "CAIDO_API_TOKEN"],
    "burp": ["BURP_URL", "BURP_APIKEY"],
    "zap": ["ZAP_URL", "ZAP_APIKEY"],
    "hackerone": ["HACKERONE_API_USERNAME", "HACKERONE_API_TOKEN"],
    "bugcrowd": ["BUGCROWD_API_TOKEN"],
    "intigriti": ["INTIGRITI_CLIENT_ID", "INTIGRITI_CLIENT_SECRET"],
    "yeswehack": ["YESWEHACK_API_KEY"],
    "discord": ["DISCORD_WEBHOOK_URL"],
    "telegram": ["TELEGRAM_BOT_TOKEN", "TELEGRAM_CHAT_ID"],
    "slack": ["SLACK_WEBHOOK_URL"],
    "github": ["GITHUB_TOKEN"],
}
ALL_KEYS = {key for keys in INTEGRATIONS.values() for key in keys}


def _mask(value: str) -> str:
    if not value:
        return ""
    return "••••" + value[-4:] if len(value) > 4 else "••••"


def _read_env_file() -> dict[str, str]:
    values: dict[str, str] = {}
    if not ENV_PATH.exists():
        return values
    for line in ENV_PATH.read_text(encoding="utf-8", errors="ignore").splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#") or "=" not in stripped:
            continue
        key, value = stripped.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def _write_env_key(key: str, value: str) -> None:
    ENV_PATH.parent.mkdir(parents=True, exist_ok=True)
    current = ENV_PATH.read_text(encoding="utf-8", errors="ignore").splitlines() if ENV_PATH.exists() else []
    found = False
    new_lines: list[str] = []
    for line in current:
        if line.strip().startswith(f"{key}="):
            new_lines.append(f"{key}={value}")
            found = True
        else:
            new_lines.append(line)
    if not found:
        new_lines.append(f"{key}={value}")
    ENV_PATH.write_text("\n".join(new_lines).rstrip() + "\n", encoding="utf-8")
    os.environ[key] = value


class SaveField(BaseModel):
    env_key: str
    value: str


@router.get("")
def list_config():
    file_values = _read_env_file()
    result = {}
    for integration_id, keys in INTEGRATIONS.items():
        result[integration_id] = {}
        for key in keys:
            value = os.getenv(key) or file_values.get(key, "")
            result[integration_id][key] = {"set": bool(value), "masked": _mask(value)}
    return {"env_path": str(ENV_PATH), "integrations": result}


@router.post("/save")
def save_config(field: SaveField):
    if field.env_key not in ALL_KEYS:
        raise HTTPException(400, f"Unknown integration key: {field.env_key}")
    if not field.value:
        raise HTTPException(400, "Value is empty")
    _write_env_key(field.env_key, field.value)
    return {"status": "saved", "env_key": field.env_key, "masked": _mask(field.value)}


async def _test_gemini() -> dict:
    key = os.getenv("GEMINI_API_KEY", "")
    if not key:
        return {"status": "failed", "message": "GEMINI_API_KEY is missing"}
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get(f"https://generativelanguage.googleapis.com/v1beta/models?key={key}")
    return {"status": "connected" if res.status_code == 200 else "failed", "http_status": res.status_code}


async def _test_browser() -> dict:
    url = os.getenv("CHROME_DEVTOOLS_MCP_URL", "").rstrip("/")
    if not url:
        return {"status": "failed", "message": "CHROME_DEVTOOLS_MCP_URL is missing"}
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get(url)
    return {"status": "connected" if res.status_code < 500 else "failed", "http_status": res.status_code}


async def _test_caido() -> dict:
    url = os.getenv("CAIDO_URL", "").rstrip("/")
    token = os.getenv("CAIDO_API_TOKEN", "")
    if not url or not token:
        return {"status": "failed", "message": "CAIDO_URL or CAIDO_API_TOKEN is missing"}
    async with httpx.AsyncClient(timeout=10, verify=False) as client:
        res = await client.post(f"{url}/graphql", headers={"Authorization": f"Bearer {token}"}, json={"query": "query { __typename }"})
    return {"status": "connected" if res.status_code < 500 else "failed", "http_status": res.status_code}


async def _test_burp() -> dict:
    url = os.getenv("BURP_URL", "http://localhost:1337").rstrip("/")
    key = os.getenv("BURP_APIKEY", "")
    headers = {"Authorization": f"Bearer {key}"} if key else {}
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get(f"{url}/v0.1/", headers=headers)
    return {"status": "connected" if res.status_code < 500 else "failed", "http_status": res.status_code}


async def _test_zap() -> dict:
    url = os.getenv("ZAP_URL", "http://localhost:8090").rstrip("/")
    key = os.getenv("ZAP_APIKEY", "")
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get(f"{url}/JSON/core/view/version/", params={"apikey": key} if key else {})
    return {"status": "connected" if res.status_code < 500 else "failed", "http_status": res.status_code}


async def _test_hackerone() -> dict:
    user = os.getenv("HACKERONE_API_USERNAME", "")
    token = os.getenv("HACKERONE_API_TOKEN", "")
    if not user or not token:
        return {"status": "failed", "message": "HackerOne credentials missing"}
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get("https://api.hackerone.com/v1/hackers/me/reports", params={"page[size]": 1}, auth=(user, token), headers={"Accept": "application/json"})
    return {"status": "connected" if res.status_code == 200 else "failed", "http_status": res.status_code}


async def _test_bugcrowd() -> dict:
    token = os.getenv("BUGCROWD_API_TOKEN", "")
    if not token:
        return {"status": "failed", "message": "BUGCROWD_API_TOKEN is missing"}
    async with httpx.AsyncClient(timeout=10) as client:
        res = await client.get("https://api.bugcrowd.com/submissions", params={"page[limit]": 1}, headers={"Accept": "application/vnd.bugcrowd+json", "Authorization": f"Token {token}"})
    return {"status": "connected" if res.status_code == 200 else "failed", "http_status": res.status_code}


TESTERS: dict[str, Callable[[], object]] = {
    "gemini": _test_gemini,
    "browser": _test_browser,
    "caido": _test_caido,
    "burp": _test_burp,
    "zap": _test_zap,
    "hackerone": _test_hackerone,
    "bugcrowd": _test_bugcrowd,
}
MANUAL_ONLY = {
    "intigriti": "Intigriti currently needs browser/OAuth setup; manual verification required.",
    "yeswehack": "YesWeHack setup may require session/browser auth; manual verification required.",
    "discord": "Discord webhook is saved; send-test is not implemented yet.",
    "telegram": "Telegram config is saved; send-test is not implemented yet.",
    "slack": "Slack webhook is saved; send-test is not implemented yet.",
    "github": "GitHub token is saved; repository-specific tests are not implemented yet.",
}


@router.post("/test/{integration_id}")
async def test_config(integration_id: str):
    if integration_id in MANUAL_ONLY:
        return {"status": "manual", "message": MANUAL_ONLY[integration_id]}
    tester = TESTERS.get(integration_id)
    if not tester:
        raise HTTPException(404, "Unknown integration")
    try:
        return await tester()
    except Exception as exc:
        return {"status": "error", "message": str(exc)}
