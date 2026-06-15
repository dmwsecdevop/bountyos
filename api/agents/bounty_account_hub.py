"""Bounty Account Hub.

Adds connected bounty-account sync without password scraping.
Users connect API/OAuth tokens for HackerOne, Bugcrowd, Intigriti, YesWeHack,
or a custom API feed. The hub stores tokens locally encrypted and imports any
program/scope data the platform API grants access to.

This module intentionally does not add new scope-hardening or change scanner
behavior. It only discovers programs and imports visible scope metadata.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple

from cryptography.fernet import Fernet, InvalidToken
from sqlmodel import Session, select

from api.models import BountyAccount, BountyProgram
from api.realtime import publish_sync
from api.integrations.resilient_http import ConnectorError, request_json_sync

_DOMAIN_RE = re.compile(r"(?i)(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}")

PLATFORM_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "hackerone": {
        "label": "HackerOne",
        "base_url": "https://api.hackerone.com",
        "auth": "basic_token",
        "program_paths": ["/v1/hackers/programs", "/v1/programs"],
        "token_hint": "HackerOne API username/token identifier + API token value",
    },
    "bugcrowd": {
        "label": "Bugcrowd",
        "base_url": "https://api.bugcrowd.com",
        "auth": "api_token",
        "program_paths": ["/programs", "/engagements", "/v1/programs", "/v1/engagements"],
        "token_hint": "Bugcrowd API token / bearer token where your account has API access",
    },
    "intigriti": {
        "label": "Intigriti",
        "base_url": "https://api.intigriti.com",
        "auth": "api_token",
        "program_paths": ["/researcher/v1/programs", "/programs", "/v1/programs"],
        "token_hint": "Intigriti researcher API token",
    },
    "yeswehack": {
        "label": "YesWeHack",
        "base_url": "https://api.yeswehack.com",
        "auth": "oauth_bearer",
        "program_paths": ["/programs", "/user/programs", "/v1/programs"],
        "token_hint": "YesWeHack OAuth bearer token / app token with read permissions",
    },
    "custom": {
        "label": "Custom JSON feed",
        "base_url": "",
        "auth": "api_token",
        "program_paths": [""],
        "token_hint": "Optional token for your own JSON feed endpoint",
    },
}


@dataclass
class SyncSummary:
    account_id: str
    platform: str
    checked_paths: List[str]
    imported: int = 0
    updated: int = 0
    total_seen: int = 0
    errors: List[str] = None
    error_details: List[Dict[str, Any]] = None
    status: str = "pending"
    attempts: int = 0
    retry_after_seconds: Optional[int] = None

    def add_error(self, error: ConnectorError) -> None:
        self.errors = self.errors or []
        self.error_details = self.error_details or []
        self.errors.append(error.message)
        self.error_details.append(error.as_dict())
        self.attempts = max(self.attempts, error.attempts)
        if error.retry_after_seconds is not None:
            self.retry_after_seconds = error.retry_after_seconds

    def as_dict(self) -> Dict[str, Any]:
        return {
            "account_id": self.account_id,
            "platform": self.platform,
            "checked_paths": self.checked_paths,
            "imported": self.imported,
            "updated": self.updated,
            "total_seen": self.total_seen,
            "errors": self.errors or [],
            "error_details": self.error_details or [],
            "status": self.status,
            "attempts": self.attempts,
            "retry_after_seconds": self.retry_after_seconds,
        }


class BountyAccountHub:
    def platform_defaults(self) -> Dict[str, Any]:
        return PLATFORM_DEFAULTS

    # ── token handling ──────────────────────────────────────────────────────

    def _fernet(self) -> Fernet:
        explicit = os.getenv("BOUNTYOS_ACCOUNT_KEY")
        if explicit:
            return Fernet(explicit.encode() if isinstance(explicit, str) else explicit)
        secret = os.getenv("BOUNTYOS_ACCOUNT_SECRET") or os.getenv("SECRET_KEY") or "bountyos-local-dev-account-secret"
        key = base64.urlsafe_b64encode(hashlib.sha256(secret.encode()).digest())
        return Fernet(key)

    def encrypt_token(self, token: str) -> str:
        if not token:
            return ""
        return self._fernet().encrypt(token.encode()).decode()

    def decrypt_token(self, encrypted: Optional[str]) -> str:
        if not encrypted:
            return ""
        try:
            return self._fernet().decrypt(encrypted.encode()).decode()
        except InvalidToken:
            return ""

    def mask_token(self, token: str) -> str:
        if not token:
            return "not set"
        if len(token) <= 8:
            return "****"
        return token[:4] + "…" + token[-4:]

    def safe_account(self, account: BountyAccount) -> Dict[str, Any]:
        data = account.model_dump(mode="json")
        data.pop("token_encrypted", None)
        data["has_token"] = bool(account.token_encrypted)
        return data

    # ── accounts ────────────────────────────────────────────────────────────

    def create_account(
        self,
        session: Session,
        *,
        platform: str,
        display_name: str,
        username: Optional[str] = None,
        token_secret: Optional[str] = None,
        auth_type: Optional[str] = None,
        api_base_url: Optional[str] = None,
        notes: Optional[str] = None,
    ) -> BountyAccount:
        platform = (platform or "custom").strip().lower()
        defaults = PLATFORM_DEFAULTS.get(platform, PLATFORM_DEFAULTS["custom"])
        token_secret = token_secret or ""
        account = BountyAccount(
            platform=platform,
            display_name=display_name.strip() or defaults["label"],
            username=username,
            auth_type=auth_type or defaults["auth"],
            token_label=self.mask_token(token_secret),
            token_encrypted=self.encrypt_token(token_secret) if token_secret else None,
            api_base_url=(api_base_url or defaults.get("base_url") or "").rstrip("/"),
            status="created",
            notes=notes,
        )
        session.add(account)
        session.commit()
        session.refresh(account)
        publish_sync("account.created", self.safe_account(account))
        return account

    def update_token(self, session: Session, account: BountyAccount, token_secret: str, username: Optional[str] = None) -> BountyAccount:
        account.token_encrypted = self.encrypt_token(token_secret)
        account.token_label = self.mask_token(token_secret)
        if username is not None:
            account.username = username
        account.updated_at = datetime.utcnow()
        session.add(account)
        session.commit()
        session.refresh(account)
        publish_sync("account.updated", self.safe_account(account))
        return account

    # ── HTTP helpers ────────────────────────────────────────────────────────

    def _headers_and_auth(self, account: BountyAccount, token: str) -> Tuple[Dict[str, str], Any]:
        headers = {"Accept": "application/json", "User-Agent": "BountyOS-AccountHub/1.0"}
        auth = None
        auth_type = (account.auth_type or PLATFORM_DEFAULTS.get(account.platform, {}).get("auth") or "api_token").lower()
        if auth_type == "basic_token" or account.platform == "hackerone":
            if account.username and token:
                auth = (account.username, token)
            elif token:
                headers["Authorization"] = f"Bearer {token}"
        elif token:
            headers["Authorization"] = f"Bearer {token}"
        return headers, auth

    def _candidate_paths(self, account: BountyAccount) -> List[str]:
        custom_paths = []
        if account.notes and "paths=" in account.notes:
            # Optional notes format: paths=/v1/programs,/v1/invites
            try:
                custom_paths = [x.strip() for x in account.notes.split("paths=", 1)[1].split()[0].split(",") if x.strip()]
            except Exception:
                custom_paths = []
        defaults = PLATFORM_DEFAULTS.get(account.platform, PLATFORM_DEFAULTS["custom"])
        return custom_paths or defaults.get("program_paths", [""])

    def _url_for(self, base: str, path: str) -> str:
        if path.startswith("http://") or path.startswith("https://"):
            return path
        if not base:
            return path
        return base.rstrip("/") + "/" + path.lstrip("/")

    # ── parsing ─────────────────────────────────────────────────────────────

    def _extract_items(self, data: Any) -> List[Any]:
        if isinstance(data, list):
            return data
        if not isinstance(data, dict):
            return []
        for key in ["data", "results", "programs", "engagements", "items", "objects"]:
            val = data.get(key)
            if isinstance(val, list):
                return val
            if isinstance(val, dict):
                nested = self._extract_items(val)
                if nested:
                    return nested
        return [data] if any(k in data for k in ["name", "title", "handle", "attributes"]) else []

    def _flat_get(self, obj: Dict[str, Any], *keys: str) -> Optional[Any]:
        cur = obj
        for key in keys:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(key)
        return cur

    def _strings_recursive(self, obj: Any) -> Iterable[str]:
        if obj is None:
            return
        if isinstance(obj, str):
            yield obj
        elif isinstance(obj, dict):
            for v in obj.values():
                yield from self._strings_recursive(v)
        elif isinstance(obj, list):
            for v in obj:
                yield from self._strings_recursive(v)

    def _extract_domains(self, item: Any) -> List[str]:
        domains: List[str] = []
        for text in self._strings_recursive(item):
            for match in _DOMAIN_RE.findall(text):
                cleaned = match.strip().lower().rstrip(".")
                if cleaned not in domains:
                    domains.append(cleaned)
        # Keep it practical; raw API objects can include docs/API hostnames too.
        noisy = {"hackerone.com", "bugcrowd.com", "intigriti.com", "yeswehack.com"}
        return [d for d in domains if d not in noisy][:250]

    def _normalize_program(self, platform: str, item: Any, account: BountyAccount) -> Optional[Dict[str, Any]]:
        if not isinstance(item, dict):
            return None
        attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else {}
        name = (
            item.get("name") or item.get("title") or item.get("program_name") or item.get("handle") or
            attrs.get("name") or attrs.get("title") or attrs.get("handle")
        )
        if not name:
            return None
        url = item.get("url") or item.get("program_url") or item.get("link") or attrs.get("url") or attrs.get("program_url")
        domains = self._extract_domains(item)
        reward_hint = None
        for key in ["reward", "rewards", "reward_range", "bounty", "bounties", "max_reward", "min_reward"]:
            val = item.get(key) or attrs.get(key)
            if val:
                reward_hint = json.dumps(val)[:280] if not isinstance(val, str) else val[:280]
                break
        text = json.dumps(item).lower()[:20000]
        offers_bounty = any(k in text for k in ["bounty", "reward", "paid", "payout", "cash"])
        status = item.get("status") or attrs.get("status") or item.get("state") or attrs.get("state") or "unknown"
        value_score = 30 + (35 if offers_bounty else 0) + min(len(domains), 20)
        if any("api" in d for d in domains):
            value_score += 5
        if any(d.startswith("*.") for d in domains):
            value_score += 10
        raw = dict(item)
        raw["connected_account_id"] = account.id
        raw["connected_account_name"] = account.display_name
        raw["connected_private_or_invited"] = True
        return {
            "name": str(name)[:240],
            "platform": platform,
            "url": str(url)[:600] if url else None,
            "offers_bounty": offers_bounty,
            "reward_hint": reward_hint,
            "domains": domains,
            "scope_raw": json.dumps(raw, default=str)[:30000],
            "status": str(status)[:80],
            "value_score": min(value_score, 100),
        }

    # ── sync/test ────────────────────────────────────────────────────────────

    def _status_from_summary(self, summary: Dict[str, Any]) -> str:
        if summary.get("total_seen", 0) > 0 or summary.get("imported", 0) > 0 or summary.get("updated", 0) > 0:
            return "connected"
        details = summary.get("error_details") or []
        codes = {d.get("code") for d in details}
        if "token_expired_or_invalid" in codes or "missing_token" in codes:
            return "token_expired"
        if "access_denied" in codes:
            return "access_denied"
        if "rate_limited" in codes:
            return "rate_limited"
        if codes & {"service_unavailable", "network_timeout", "network_error"}:
            return "unavailable"
        if summary.get("errors"):
            return "error"
        return "connected"

    def test_account(self, session: Session, account_id: str) -> Dict[str, Any]:
        account = session.get(BountyAccount, account_id)
        if not account:
            raise ValueError("Account not found")
        summary = self.sync_account(session, account_id, dry_run=True, max_items=5)
        account.status = self._status_from_summary(summary)
        account.last_error = "; ".join(summary.get("errors", [])[:2]) if summary.get("errors") else None
        account.updated_at = datetime.utcnow()
        session.add(account)
        session.commit()
        session.refresh(account)
        publish_sync("account.tested", {"account": self.safe_account(account), "summary": summary})
        return {"ok": account.status == "connected", "account": self.safe_account(account), "summary": summary}

    def sync_account(self, session: Session, account_id: str, *, dry_run: bool = False, max_items: int = 200) -> Dict[str, Any]:
        account = session.get(BountyAccount, account_id)
        if not account:
            raise ValueError("Account not found")

        token = self.decrypt_token(account.token_encrypted)
        summary = SyncSummary(
            account_id=account.id,
            platform=account.platform,
            checked_paths=[],
            errors=[],
            error_details=[],
        )
        imported_programs: List[Dict[str, Any]] = []

        if account.platform != "custom" and not token:
            code = "token_unreadable" if account.token_encrypted else "missing_token"
            error = ConnectorError(
                code=code,
                message=(
                    "The saved token could not be decrypted. Check BOUNTYOS_ACCOUNT_KEY/SECRET_KEY or save the token again."
                    if code == "token_unreadable"
                    else "No API token is configured for this account. Add a token, then test the connection again."
                ),
                retryable=False,
                provider=account.platform,
                attempts=0,
            )
            summary.add_error(error)
            summary.status = "token_expired" if code == "missing_token" else "error"
            out = summary.as_dict()
            out["preview_programs"] = []
            if not dry_run:
                account.status = summary.status
                account.last_error = error.message
                account.updated_at = datetime.utcnow()
                session.add(account)
                session.commit()
            publish_sync("account.sync.finished", out)
            return out

        headers, auth = self._headers_and_auth(account, token)
        base = (account.api_base_url or PLATFORM_DEFAULTS.get(account.platform, {}).get("base_url") or "").rstrip("/")
        paths = self._candidate_paths(account)
        publish_sync("account.sync.started", {"account": self.safe_account(account), "dry_run": dry_run})

        for path in paths:
            url = self._url_for(base, path)
            if not url or not url.startswith(("http://", "https://")):
                error = ConnectorError(
                    code="invalid_endpoint",
                    message=f"Invalid API URL/path: {url or path}",
                    retryable=False,
                    endpoint=url or path,
                    provider=account.platform,
                )
                summary.add_error(error)
                continue

            summary.checked_paths.append(url)
            response = request_json_sync(
                provider=account.platform,
                url=url,
                headers=headers,
                auth=auth,
                timeout_seconds=15.0,
            )
            summary.attempts = max(summary.attempts, response.attempts)
            if not response.ok:
                if response.error:
                    summary.add_error(response.error)
                    publish_sync("account.sync.error", {
                        "account_id": account.id,
                        "platform": account.platform,
                        "error": response.error.as_dict(),
                    })
                    # Authentication and rate-limit failures apply to the account,
                    # so trying alternate paths usually creates noise.
                    if response.error.code in {
                        "token_expired_or_invalid", "rate_limited",
                        "network_timeout", "network_error", "service_unavailable",
                    }:
                        break
                continue

            items = self._extract_items(response.data)[:max_items]
            summary.total_seen += len(items)
            for item in items:
                normalized = self._normalize_program(account.platform, item, account)
                if not normalized:
                    continue
                imported_programs.append(normalized)
                if dry_run:
                    continue
                existing = session.exec(
                    select(BountyProgram)
                    .where(BountyProgram.platform == account.platform)
                    .where(BountyProgram.name == normalized["name"])
                ).first()
                domains_json = json.dumps(normalized["domains"])
                if existing:
                    changed = (
                        existing.domains_json != domains_json or
                        existing.url != normalized["url"] or
                        existing.reward_hint != normalized["reward_hint"] or
                        existing.offers_bounty != normalized["offers_bounty"]
                    )
                    existing.url = normalized["url"]
                    existing.offers_bounty = normalized["offers_bounty"]
                    existing.reward_hint = normalized["reward_hint"]
                    existing.domains_json = domains_json
                    existing.scope_raw = normalized["scope_raw"]
                    existing.status = normalized["status"]
                    existing.value_score = normalized["value_score"]
                    existing.last_seen_at = datetime.utcnow()
                    if changed:
                        existing.last_changed_at = datetime.utcnow()
                        summary.updated += 1
                    session.add(existing)
                else:
                    session.add(BountyProgram(
                        name=normalized["name"],
                        platform=normalized["platform"],
                        url=normalized["url"],
                        offers_bounty=normalized["offers_bounty"],
                        reward_hint=normalized["reward_hint"],
                        domains_json=domains_json,
                        scope_raw=normalized["scope_raw"],
                        status=normalized["status"],
                        value_score=normalized["value_score"],
                    ))
                    summary.imported += 1
            if imported_programs:
                break

        summary.status = self._status_from_summary(summary.as_dict())
        if not dry_run:
            # Existing synced data remains untouched when a provider is down or
            # rate-limited. Only the account health fields are updated.
            account.last_sync_at = datetime.utcnow() if summary.status == "connected" else account.last_sync_at
            account.status = summary.status
            account.last_error = "; ".join(summary.errors[:2]) if summary.errors else None
            account.updated_at = datetime.utcnow()
            session.add(account)
            session.commit()

        out = summary.as_dict()
        out["preview_programs"] = imported_programs[:20]
        out["preserved_existing_data"] = bool(summary.errors)
        publish_sync("account.sync.finished", out)
        return out

    def sync_all_accounts(self, session: Session, *, max_items: int = 200) -> Dict[str, Any]:
        accounts = session.exec(select(BountyAccount).where(BountyAccount.status != "disabled")).all()
        results = []
        for account in accounts:
            try:
                results.append(self.sync_account(session, account.id, max_items=max_items))
            except Exception as exc:
                results.append({
                    "account_id": account.id,
                    "platform": account.platform,
                    "status": "error",
                    "errors": [str(exc)],
                    "error_details": [{"code": "internal_error", "message": str(exc), "retryable": False}],
                })
        return {
            "accounts_checked": len(accounts),
            "connected": len([r for r in results if r.get("status") == "connected"]),
            "failed": len([r for r in results if r.get("status") != "connected"]),
            "results": results,
        }


account_hub = BountyAccountHub()
