"""Live data expert for BountyOS chat/voice agent.

Purpose:
- Answer current-data questions without burning main model calls.
- Keep this as a narrow utility layer: currency, crypto, recent CVEs, basic public IP.
- Falls back cleanly when internet/API is unavailable.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional

from api.realtime import publish_sync
from api.integrations.resilient_http import ConnectorResponse, request_json_async


@dataclass
class LiveDataResult:
    ok: bool
    kind: str
    answer: str
    source: str = ""
    data: Optional[Dict[str, Any]] = None
    error: Optional[str] = None

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class LiveDataAgent:
    """Small live-data connector used by AI chat and Architect Agent."""

    def __init__(self) -> None:
        self.timeout = float(os.getenv("BOUNTYOS_LIVE_TIMEOUT", "10"))
        self.default_currency = os.getenv("BOUNTYOS_DEFAULT_CURRENCY", "INR").upper()

    def detect(self, text: str) -> Optional[str]:
        t = (text or "").lower()
        if any(k in t for k in ["dollar rate", "usd rate", "exchange rate", "currency rate", "1 usd", "usd to", "dollar to", "us dollar"]):
            return "currency"
        if any(k in t for k in ["bitcoin price", "btc price", "ethereum price", "eth price", "crypto price"]):
            return "crypto"
        if any(k in t for k in ["latest cve", "recent cve", "new cve", "today cve", "cve for", "vulnerability news"]):
            return "cve"
        if any(k in t for k in ["my public ip", "public ip", "what is my ip"]):
            return "public_ip"
        if any(k in t for k in ["today", "current", "latest", "now"]):
            if any(k in t for k in ["rate", "price", "cve", "ip"]):
                return "live_unknown"
        return None

    def _connector_failure(self, kind: str, source: str, response: ConnectorResponse) -> LiveDataResult:
        error = response.error
        if not error:
            return LiveDataResult(False, kind, f"{source} lookup failed.", source=source, error="unknown_error")
        retry = f" Retry after about {error.retry_after_seconds} seconds." if error.retry_after_seconds is not None else ""
        return LiveDataResult(
            ok=False,
            kind=kind,
            answer=f"{source} is unavailable right now: {error.message}{retry}",
            source=source,
            data={
                "error_code": error.code,
                "status_code": error.status_code,
                "retryable": error.retryable,
                "retry_after_seconds": error.retry_after_seconds,
                "attempts": response.attempts,
            },
            error=error.code,
        )

    async def answer_async(self, text: str) -> LiveDataResult:
        kind = self.detect(text) or "live_unknown"
        publish_sync("live_data.started", {"kind": kind, "query": text})
        try:
            if kind == "currency":
                res = await self._currency(text)
            elif kind == "crypto":
                res = await self._crypto(text)
            elif kind == "cve":
                res = await self._recent_cves(text)
            elif kind == "public_ip":
                res = await self._public_ip()
            else:
                res = LiveDataResult(
                    ok=False,
                    kind=kind,
                    answer=(
                        "I detected a live/current-data question, but no connector matched it yet. "
                        "Supported live tools now: currency, crypto price, recent CVEs, and public IP."
                    ),
                    error="unsupported_live_query",
                )
        except Exception as e:
            res = LiveDataResult(
                ok=False,
                kind=kind,
                answer=f"Live data lookup failed: {e}",
                error=str(e),
            )
        publish_sync("live_data.finished", res.as_dict())
        return res

    def answer(self, text: str) -> LiveDataResult:
        """Sync wrapper for FastAPI sync routes."""
        import anyio
        return anyio.run(self.answer_async, text)

    def _currency_pair(self, text: str) -> tuple[str, str]:
        t = (text or "").upper()
        codes = re.findall(r"\b[A-Z]{3}\b", t)
        if "USD" in codes:
            base = "USD"
            # choose the first non-USD code after USD when possible
            quote = next((c for c in codes if c != "USD"), self.default_currency)
            return base, quote
        # natural language defaults for India users
        if "DOLLAR" in t or "US DOLLAR" in t:
            return "USD", self.default_currency
        if len(codes) >= 2:
            return codes[0], codes[1]
        return "USD", self.default_currency

    async def _currency(self, text: str) -> LiveDataResult:
        base, quote = self._currency_pair(text)
        url = f"https://api.frankfurter.app/latest?from={base}&to={quote}"
        response = await request_json_async(provider="frankfurter", url=url, timeout_seconds=self.timeout)
        if not response.ok:
            return self._connector_failure("currency", "Frankfurter exchange-rate API", response)
        data = response.data
        rate = data.get("rates", {}).get(quote)
        date = data.get("date")
        if rate is None:
            raise ValueError(f"No {base}->{quote} rate returned")
        return LiveDataResult(
            ok=True,
            kind="currency",
            answer=f"Latest available rate: 1 {base} = {rate} {quote}. Date: {date}.",
            source="Frankfurter public exchange-rate API",
            data={"base": base, "quote": quote, "rate": rate, "date": date},
        )

    async def _crypto(self, text: str) -> LiveDataResult:
        t = (text or "").lower()
        coin = "bitcoin"
        symbol = "BTC"
        if "eth" in t or "ethereum" in t:
            coin, symbol = "ethereum", "ETH"
        vs = "inr" if any(k in t for k in ["inr", "rupee", "india"]) else "usd"
        url = f"https://api.coingecko.com/api/v3/simple/price?ids={coin}&vs_currencies={vs}"
        response = await request_json_async(provider="coingecko", url=url, timeout_seconds=self.timeout)
        if not response.ok:
            return self._connector_failure("crypto", "CoinGecko price API", response)
        data = response.data
        price = data.get(coin, {}).get(vs)
        if price is None:
            raise ValueError("No crypto price returned")
        return LiveDataResult(
            ok=True,
            kind="crypto",
            answer=f"Latest available {symbol} price: {price} {vs.upper()}.",
            source="CoinGecko simple price API",
            data={"coin": coin, "symbol": symbol, "vs": vs.upper(), "price": price},
        )

    async def _recent_cves(self, text: str) -> LiveDataResult:
        keyword = ""
        m = re.search(r"cve\s+(?:for|in|about)\s+([a-zA-Z0-9_.+\- ]{2,40})", text, re.I)
        if m:
            keyword = m.group(1).strip()
        now = datetime.now(timezone.utc)
        start = now - timedelta(days=7)
        params: Dict[str, str] = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": now.strftime("%Y-%m-%dT%H:%M:%S.000"),
        }
        if keyword:
            params["keywordSearch"] = keyword
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        response = await request_json_async(provider="nvd", url=url, params=params, timeout_seconds=self.timeout)
        if not response.ok:
            return self._connector_failure("cve", "NVD CVE API", response)
        data = response.data
        vulns = data.get("vulnerabilities", [])[:5]
        if not vulns:
            return LiveDataResult(
                ok=True,
                kind="cve",
                answer="No recent CVEs found for that query in the last 7 days from NVD.",
                source="NVD CVE API",
                data={"count": 0, "query": keyword or "recent"},
            )
        lines = ["Recent CVEs from NVD:"]
        compact = []
        for item in vulns:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "unknown")
            published = cve.get("published", "")[:10]
            descs = cve.get("descriptions", [])
            desc = next((d.get("value", "") for d in descs if d.get("lang") == "en"), "")
            desc = re.sub(r"\s+", " ", desc)[:180]
            lines.append(f"- {cve_id} ({published}): {desc}")
            compact.append({"id": cve_id, "published": published, "description": desc})
        return LiveDataResult(
            ok=True,
            kind="cve",
            answer="\n".join(lines),
            source="NVD CVE API",
            data={"items": compact, "query": keyword or "recent"},
        )

    async def _public_ip(self) -> LiveDataResult:
        response = await request_json_async(provider="ipify", url="https://api.ipify.org?format=json", timeout_seconds=self.timeout)
        if not response.ok:
            return self._connector_failure("public_ip", "ipify public IP API", response)
        data = response.data
        ip = data.get("ip")
        return LiveDataResult(
            ok=True,
            kind="public_ip",
            answer=f"Public IP seen by the API: {ip}",
            source="ipify public IP API",
            data={"ip": ip},
        )


live_data_agent = LiveDataAgent()
