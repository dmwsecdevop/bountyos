"""Resilient outbound HTTP helpers for BountyOS connectors.

Provides consistent handling for expired/invalid tokens, rate limits, temporary
provider outages, timeouts, DNS/network failures, malformed JSON, retries, and
an in-memory connector health registry used by the dashboard.
"""

from __future__ import annotations

import email.utils
import os
import random
import threading
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

import httpx
from api.integrations.proxy_manager import ProxyManager
from api.integrations.rate_limiter import RateLimiter

proxy_manager = ProxyManager()
rate_limiter = RateLimiter()


@dataclass
class ConnectorError:
    code: str
    message: str
    retryable: bool
    status_code: Optional[int] = None
    retry_after_seconds: Optional[int] = None
    endpoint: Optional[str] = None
    provider: Optional[str] = None
    attempts: int = 1
    response_preview: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ConnectorResponse:
    ok: bool
    data: Any = None
    status_code: Optional[int] = None
    attempts: int = 1
    error: Optional[ConnectorError] = None
    headers: Optional[Dict[str, str]] = None

    def as_dict(self) -> Dict[str, Any]:
        return {
            "ok": self.ok,
            "data": self.data,
            "status_code": self.status_code,
            "attempts": self.attempts,
            "error": self.error.as_dict() if self.error else None,
            "headers": self.headers or {},
        }


class ConnectorHealthRegistry:
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._items: Dict[str, Dict[str, Any]] = {}

    def record_success(self, provider: str, endpoint: str, status_code: int, attempts: int) -> None:
        now = datetime.now(timezone.utc).isoformat()
        with self._lock:
            old = self._items.get(provider, {})
            self._items[provider] = {
                "provider": provider,
                "status": "healthy",
                "last_checked_at": now,
                "last_success_at": now,
                "last_error_at": old.get("last_error_at"),
                "last_error": None,
                "status_code": status_code,
                "endpoint": endpoint,
                "attempts": attempts,
                "consecutive_failures": 0,
                "retry_after_seconds": None,
            }

    def record_failure(self, provider: str, error: ConnectorError) -> None:
        now = datetime.now(timezone.utc).isoformat()
        status = {
            "token_expired_or_invalid": "auth_error",
            "access_denied": "auth_error",
            "missing_token": "auth_error",
            "rate_limited": "rate_limited",
            "service_unavailable": "unavailable",
            "network_timeout": "unavailable",
            "network_error": "unavailable",
        }.get(error.code, "degraded")
        with self._lock:
            old = self._items.get(provider, {})
            self._items[provider] = {
                "provider": provider,
                "status": status,
                "last_checked_at": now,
                "last_success_at": old.get("last_success_at"),
                "last_error_at": now,
                "last_error": error.as_dict(),
                "status_code": error.status_code,
                "endpoint": error.endpoint,
                "attempts": error.attempts,
                "consecutive_failures": int(old.get("consecutive_failures", 0)) + 1,
                "retry_after_seconds": error.retry_after_seconds,
            }

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            items = [dict(v) for v in self._items.values()]
        counts: Dict[str, int] = {}
        for item in items:
            counts[item["status"]] = counts.get(item["status"], 0) + 1
        return {"total": len(items), "counts": counts, "connectors": sorted(items, key=lambda x: x["provider"])}

    def get(self, provider: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            item = self._items.get(provider)
            return dict(item) if item else None

    def reset(self, provider: Optional[str] = None) -> None:
        with self._lock:
            if provider:
                self._items.pop(provider, None)
            else:
                self._items.clear()


connector_health = ConnectorHealthRegistry()


def _retry_after_seconds(headers: httpx.Headers) -> Optional[int]:
    raw = headers.get("Retry-After")
    if not raw:
        return None
    try:
        return max(0, int(float(raw)))
    except (TypeError, ValueError):
        try:
            dt = email.utils.parsedate_to_datetime(raw)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return max(0, int((dt - datetime.now(timezone.utc)).total_seconds()))
        except Exception:
            return None


def _preview(response: Optional[httpx.Response]) -> Optional[str]:
    if response is None:
        return None
    try:
        return response.text.replace("\n", " ")[:300]
    except Exception:
        return None


def classify_response_error(provider: str, endpoint: str, response: httpx.Response, attempts: int) -> ConnectorError:
    code = response.status_code
    retry_after = _retry_after_seconds(response.headers)
    preview = _preview(response)
    if code == 401:
        return ConnectorError(
            code="token_expired_or_invalid",
            message="The API token is invalid, expired, revoked, or uses the wrong authentication type. Update the token and test the account again.",
            retryable=False,
            status_code=code,
            endpoint=endpoint,
            provider=provider,
            attempts=attempts,
            response_preview=preview,
        )
    if code == 403:
        return ConnectorError(
            code="access_denied",
            message="The token is valid but does not have permission for this API endpoint or program data.",
            retryable=False,
            status_code=code,
            endpoint=endpoint,
            provider=provider,
            attempts=attempts,
            response_preview=preview,
        )
    if code == 429:
        return ConnectorError(
            code="rate_limited",
            message="The provider rate-limited BountyOS. It will retry automatically; try again later if the limit persists.",
            retryable=True,
            status_code=code,
            retry_after_seconds=retry_after,
            endpoint=endpoint,
            provider=provider,
            attempts=attempts,
            response_preview=preview,
        )
    if code in (408, 425) or code >= 500:
        return ConnectorError(
            code="service_unavailable",
            message=f"The provider is temporarily unavailable (HTTP {code}). BountyOS retried the request and preserved existing data.",
            retryable=True,
            status_code=code,
            retry_after_seconds=retry_after,
            endpoint=endpoint,
            provider=provider,
            attempts=attempts,
            response_preview=preview,
        )
    if code == 404:
        return ConnectorError(
            code="endpoint_not_found",
            message="The configured API endpoint was not found. The platform API path may have changed or your custom URL is incorrect.",
            retryable=False,
            status_code=code,
            endpoint=endpoint,
            provider=provider,
            attempts=attempts,
            response_preview=preview,
        )
    return ConnectorError(
        code="api_error",
        message=f"The provider returned HTTP {code}.",
        retryable=False,
        status_code=code,
        endpoint=endpoint,
        provider=provider,
        attempts=attempts,
        response_preview=preview,
    )


def _backoff(attempt: int, retry_after: Optional[int], max_wait: float) -> float:
    if retry_after is not None:
        return min(float(retry_after), max_wait)
    base = float(os.getenv("BOUNTYOS_RETRY_BASE_SECONDS", "0.75"))
    return min(max_wait, base * (2 ** max(0, attempt - 1)) + random.uniform(0, 0.25))


def request_json_sync(
    *,
    provider: str,
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    auth: Any = None,
    params: Optional[Dict[str, Any]] = None,
    json_body: Any = None,
    timeout_seconds: float = 15.0,
    max_attempts: Optional[int] = None,
    follow_redirects: bool = True,
) -> ConnectorResponse:
    attempts_allowed = max(1, max_attempts or int(os.getenv("BOUNTYOS_CONNECTOR_RETRIES", "3")))
    max_wait = float(os.getenv("BOUNTYOS_MAX_RETRY_WAIT", "8"))
    timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 8.0))
    last_error: Optional[ConnectorError] = None
    proxy = proxy_manager.get_proxy()

    with httpx.Client(timeout=timeout, follow_redirects=follow_redirects, proxies={"http://": proxy, "https://": proxy} if proxy else None) as client:
        for attempt in range(1, attempts_allowed + 1):
            rate_limiter.check_and_wait(provider)
            try:
                response = client.request(method, url, headers=headers, auth=auth, params=params, json=json_body)
                if response.is_success:
                    try:
                        data = response.json()
                    except Exception:
                        error = ConnectorError(
                            code="invalid_json",
                            message="The provider responded, but the response was not valid JSON.",
                            retryable=False,
                            status_code=response.status_code,
                            endpoint=url,
                            provider=provider,
                            attempts=attempt,
                            response_preview=_preview(response),
                        )
                        connector_health.record_failure(provider, error)
                        return ConnectorResponse(False, status_code=response.status_code, attempts=attempt, error=error)
                    connector_health.record_success(provider, url, response.status_code, attempt)
                    return ConnectorResponse(True, data=data, status_code=response.status_code, attempts=attempt, headers=dict(response.headers))

                error = classify_response_error(provider, url, response, attempt)
                last_error = error
                if proxy:
                    proxy_manager.report_failure(proxy)
                if not error.retryable or attempt >= attempts_allowed:
                    connector_health.record_failure(provider, error)
                    return ConnectorResponse(False, status_code=response.status_code, attempts=attempt, error=error, headers=dict(response.headers))
                time.sleep(_backoff(attempt, error.retry_after_seconds, max_wait))
            except httpx.TimeoutException:
                if proxy:
                    proxy_manager.report_failure(proxy)
                last_error = ConnectorError(
                    code="network_timeout",
                    message="The API request timed out. BountyOS retried automatically; check internet access or provider availability.",
                    retryable=True,
                    endpoint=url,
                    provider=provider,
                    attempts=attempt,
                )
            except httpx.RequestError as exc:
                if proxy:
                    proxy_manager.report_failure(proxy)
                last_error = ConnectorError(
                    code="network_error",
                    message=f"Could not reach the provider: {exc}",
                    retryable=True,
                    endpoint=url,
                    provider=provider,
                    attempts=attempt,
                )
            if attempt < attempts_allowed:
                time.sleep(_backoff(attempt, None, max_wait))

    assert last_error is not None
    connector_health.record_failure(provider, last_error)
    return ConnectorResponse(False, attempts=last_error.attempts, error=last_error)


async def request_json_async(
    *,
    provider: str,
    url: str,
    method: str = "GET",
    headers: Optional[Dict[str, str]] = None,
    auth: Any = None,
    params: Optional[Dict[str, Any]] = None,
    json_body: Any = None,
    timeout_seconds: float = 15.0,
    max_attempts: Optional[int] = None,
    follow_redirects: bool = True,
) -> ConnectorResponse:
    import anyio

    attempts_allowed = max(1, max_attempts or int(os.getenv("BOUNTYOS_CONNECTOR_RETRIES", "3")))
    max_wait = float(os.getenv("BOUNTYOS_MAX_RETRY_WAIT", "8"))
    timeout = httpx.Timeout(timeout_seconds, connect=min(timeout_seconds, 8.0))
    last_error: Optional[ConnectorError] = None
    proxy = proxy_manager.get_proxy()

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=follow_redirects, proxies={"http://": proxy, "https://": proxy} if proxy else None) as client:
        for attempt in range(1, attempts_allowed + 1):
            rate_limiter.check_and_wait(provider)
            try:
                response = await client.request(method, url, headers=headers, auth=auth, params=params, json=json_body)
                if response.is_success:
                    try:
                        data = response.json()
                    except Exception:
                        error = ConnectorError(
                            code="invalid_json",
                            message="The provider responded, but the response was not valid JSON.",
                            retryable=False,
                            status_code=response.status_code,
                            endpoint=url,
                            provider=provider,
                            attempts=attempt,
                            response_preview=_preview(response),
                        )
                        connector_health.record_failure(provider, error)
                        return ConnectorResponse(False, status_code=response.status_code, attempts=attempt, error=error)
                    connector_health.record_success(provider, url, response.status_code, attempt)
                    return ConnectorResponse(True, data=data, status_code=response.status_code, attempts=attempt, headers=dict(response.headers))

                error = classify_response_error(provider, url, response, attempt)
                last_error = error
                if proxy:
                    proxy_manager.report_failure(proxy)
                if not error.retryable or attempt >= attempts_allowed:
                    connector_health.record_failure(provider, error)
                    return ConnectorResponse(False, status_code=response.status_code, attempts=attempt, error=error, headers=dict(response.headers))
                await anyio.sleep(_backoff(attempt, error.retry_after_seconds, max_wait))
            except httpx.TimeoutException:
                if proxy:
                    proxy_manager.report_failure(proxy)
                last_error = ConnectorError(
                    code="network_timeout",
                    message="The API request timed out. BountyOS retried automatically; check internet access or provider availability.",
                    retryable=True,
                    endpoint=url,
                    provider=provider,
                    attempts=attempt,
                )
            except httpx.RequestError as exc:
                if proxy:
                    proxy_manager.report_failure(proxy)
                last_error = ConnectorError(
                    code="network_error",
                    message=f"Could not reach the provider: {exc}",
                    retryable=True,
                    endpoint=url,
                    provider=provider,
                    attempts=attempt,
                )
            if attempt < attempts_allowed:
                await anyio.sleep(_backoff(attempt, None, max_wait))

    assert last_error is not None
    connector_health.record_failure(provider, last_error)
    return ConnectorResponse(False, attempts=last_error.attempts, error=last_error)
