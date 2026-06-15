"""Bounty Program Radar.

Checks online/public bug bounty program feeds and stores program + domain scope
metadata in BountyOS. This module is intentionally passive: it imports program
scope and can create targets, but it does not start active testing by itself.
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, asdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Tuple
from urllib.parse import urlparse

from sqlmodel import Session, select

from api.models import BountyProgram, Target
from api.realtime import publish_sync
from api.integrations.resilient_http import request_json_sync

DEFAULT_PROJECTDISCOVERY_FEED = (
    "https://raw.githubusercontent.com/projectdiscovery/public-bugbounty-programs/main/dist/data.json"
)

DOMAIN_RE = re.compile(r"^(?:\*\.)?([a-z0-9.-]+\.[a-z]{2,})$", re.I)


@dataclass
class ProgramHit:
    name: str
    platform: str
    url: Optional[str] = None
    offers_bounty: bool = False
    domains: Optional[List[str]] = None
    reward_hint: Optional[str] = None
    raw: Optional[Dict[str, Any]] = None

    def as_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        data["domains"] = self.domains or []
        return data


@dataclass
class RadarSummary:
    checked_sources: int = 0
    fetched_programs: int = 0
    new_programs: int = 0
    updated_programs: int = 0
    total_domains_seen: int = 0
    errors: Optional[List[str]] = None
    error_details: Optional[List[Dict[str, Any]]] = None
    successful_sources: int = 0
    status: str = "pending"

    def as_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["errors"] = self.errors or []
        d["error_details"] = self.error_details or []
        return d


class ProgramRadarAgent:
    """Passive program discovery/import agent."""

    def sources(self) -> List[Dict[str, Any]]:
        feeds = [s.strip() for s in os.getenv("BOUNTYOS_PROGRAM_FEEDS", "").split(",") if s.strip()]
        if not feeds:
            feeds = [DEFAULT_PROJECTDISCOVERY_FEED]
        return [
            {
                "name": "ProjectDiscovery public bug bounty programs" if url == DEFAULT_PROJECTDISCOVERY_FEED else "Custom JSON feed",
                "type": "json_feed",
                "url": url,
                "enabled": True,
            }
            for url in feeds
        ]

    def check_sources(self, session: Session, max_programs: int = 500) -> Dict[str, Any]:
        publish_sync("program.check.started", {"message": "Bounty Program Radar started", "max_programs": max_programs})
        summary = RadarSummary(errors=[], error_details=[])
        stored: List[Dict[str, Any]] = []

        for source in self.sources():
            summary.checked_sources += 1
            try:
                hits, fetch_meta = self.fetch_source(source)
                if not fetch_meta.get("ok"):
                    detail = fetch_meta.get("error") or {"code": "unknown_error", "message": "Program feed failed"}
                    err = f"{source.get('name')}: {detail.get('message')}"
                    summary.errors.append(err)
                    summary.error_details.append({"source": source, **detail})
                    publish_sync("program.check.error", {"message": err, "source": source, "error": detail})
                    continue
                summary.successful_sources += 1
                if max_programs:
                    hits = hits[:max_programs]
                summary.fetched_programs += len(hits)
                for hit in hits:
                    saved, was_new, was_updated = self.upsert_program(session, hit)
                    summary.total_domains_seen += len(json.loads(saved.domains_json or "[]"))
                    if was_new:
                        summary.new_programs += 1
                        publish_sync("program.found", {"message": f"New program found: {saved.name}", "program": saved.model_dump(mode="json")})
                    elif was_updated:
                        summary.updated_programs += 1
                        publish_sync("program.updated", {"message": f"Program scope changed: {saved.name}", "program": saved.model_dump(mode="json")})
                    stored.append(saved.model_dump(mode="json"))
                session.commit()
            except Exception as exc:  # keep watcher resilient
                err = f"{source.get('name')}: {exc}"
                summary.errors.append(err)
                summary.error_details.append({"source": source, "code": "internal_error", "message": str(exc), "retryable": False})
                publish_sync("program.check.error", {"message": err, "source": source})

        if summary.successful_sources == summary.checked_sources:
            summary.status = "healthy"
        elif summary.successful_sources:
            summary.status = "partial"
        else:
            summary.status = "unavailable"
        result = {
            "summary": summary.as_dict(),
            "programs": stored[:100],
            "preserved_existing_data": bool(summary.errors),
        }
        publish_sync("program.check.finished", {"message": "Bounty Program Radar finished", **summary.as_dict()})
        return result

    def fetch_source(self, source: Dict[str, Any]) -> Tuple[List[ProgramHit], Dict[str, Any]]:
        url = source["url"]
        host = urlparse(url).netloc or "custom-feed"
        provider = f"program_feed:{host}"
        response = request_json_sync(
            provider=provider,
            url=url,
            headers={"Accept": "application/json", "User-Agent": "BountyOS-ProgramRadar/2.0"},
            timeout_seconds=25.0,
        )
        if not response.ok:
            return [], response.as_dict()
        return self.parse_programs(response.data, source), response.as_dict()

    def parse_programs(self, data: Any, source: Dict[str, Any]) -> List[ProgramHit]:
        # Supported shapes:
        # 1) ProjectDiscovery dist/data.json: list[{name,url,bounty,domains}]
        # 2) {programs:[...]}
        # 3) {data:[...]}
        # 4) HackerOne-like {data:[{attributes:{name,handle,...}, relationships/structured_scopes}]}
        if isinstance(data, dict):
            items = data.get("programs") or data.get("data") or data.get("results") or []
        else:
            items = data
        if not isinstance(items, list):
            return []

        hits: List[ProgramHit] = []
        for item in items:
            hit = self.parse_item(item, source)
            if hit and hit.name and hit.domains:
                hits.append(hit)
        return hits

    def parse_item(self, item: Any, source: Dict[str, Any]) -> Optional[ProgramHit]:
        if not isinstance(item, dict):
            return None
        attrs = item.get("attributes") if isinstance(item.get("attributes"), dict) else item

        name = attrs.get("name") or attrs.get("program_name") or attrs.get("handle") or attrs.get("title")
        url = attrs.get("url") or attrs.get("policy_url") or attrs.get("submission_url") or attrs.get("program_url")
        bounty = attrs.get("bounty")
        if bounty is None:
            bounty = attrs.get("offers_bounty") or attrs.get("bounty_program") or False
        reward_hint = attrs.get("reward") or attrs.get("reward_hint") or attrs.get("min_bounty")

        domains = []
        for key in ("domains", "targets", "scope", "assets", "structured_scopes"):
            domains.extend(self.extract_domains(attrs.get(key)))
        # HackerOne-like relationships sometimes carry structured scopes.
        rel = item.get("relationships") if isinstance(item.get("relationships"), dict) else {}
        for value in rel.values():
            domains.extend(self.extract_domains(value))

        domains = self.normalize_domains(domains)
        if not name and domains:
            name = domains[0]
        if not name:
            return None
        return ProgramHit(
            name=str(name).strip(),
            platform=self.platform_from_source(source, attrs),
            url=str(url).strip() if url else None,
            offers_bounty=bool(bounty),
            domains=domains,
            reward_hint=str(reward_hint) if reward_hint is not None else None,
            raw=item,
        )

    def extract_domains(self, value: Any) -> List[str]:
        domains: List[str] = []
        if value is None:
            return domains
        if isinstance(value, str):
            domains.extend(self.find_domains_in_text(value))
        elif isinstance(value, list):
            for v in value:
                domains.extend(self.extract_domains(v))
        elif isinstance(value, dict):
            # Prefer specific scope/asset fields, then scan values as fallback.
            for key in ("asset_identifier", "asset", "domain", "host", "target", "endpoint", "url", "identifier", "name"):
                if key in value:
                    domains.extend(self.extract_domains(value.get(key)))
            if not domains:
                for v in value.values():
                    domains.extend(self.extract_domains(v))
        return domains

    def find_domains_in_text(self, text: str) -> List[str]:
        text = text.strip().lower()
        text = text.replace("https://", "").replace("http://", "").split("/")[0]
        text = text.replace(":443", "").replace(":80", "")
        candidates = [x.strip().strip(",;[](){}<>\"'") for x in re.split(r"\s+|,", text) if x.strip()]
        out = []
        for c in candidates:
            m = DOMAIN_RE.match(c)
            if m:
                out.append(c)
        return out

    def normalize_domains(self, domains: Iterable[str]) -> List[str]:
        clean = []
        seen = set()
        for d in domains:
            d = str(d).strip().lower()
            d = d.replace("https://", "").replace("http://", "").split("/")[0]
            d = d.strip(" .")
            if not d or d.startswith("localhost") or "*" in d[2:]:
                continue
            if DOMAIN_RE.match(d) and d not in seen:
                seen.add(d)
                clean.append(d)
        return clean[:200]

    def platform_from_source(self, source: Dict[str, Any], attrs: Dict[str, Any]) -> str:
        text = " ".join(str(x) for x in [source.get("name", ""), source.get("url", ""), attrs.get("url", "")]).lower()
        if "hackerone" in text:
            return "hackerone"
        if "bugcrowd" in text:
            return "bugcrowd"
        if "intigriti" in text:
            return "intigriti"
        if "yeswehack" in text or "yes we hack" in text:
            return "yeswehack"
        if "projectdiscovery" in text:
            return "projectdiscovery"
        return "custom"

    def value_score(self, hit: ProgramHit) -> int:
        score = 40
        domains = hit.domains or []
        if hit.offers_bounty:
            score += 25
        if len(domains) >= 10:
            score += 10
        if len(domains) >= 50:
            score += 10
        lower = " ".join([hit.name or "", hit.url or "", " ".join(domains)]).lower()
        for word in ["api", "cloud", "app", "wallet", "pay", "bank", "admin", "mobile", "oauth", "graphql"]:
            if word in lower:
                score += 3
        return min(score, 100)

    def upsert_program(self, session: Session, hit: ProgramHit) -> Tuple[BountyProgram, bool, bool]:
        domains_json = json.dumps(hit.domains or [], sort_keys=True)
        existing = session.exec(
            select(BountyProgram).where(BountyProgram.name == hit.name).where(BountyProgram.platform == hit.platform)
        ).first()
        now = datetime.utcnow()
        if existing:
            was_updated = existing.domains_json != domains_json or existing.url != hit.url or bool(existing.offers_bounty) != bool(hit.offers_bounty)
            existing.url = hit.url
            existing.offers_bounty = hit.offers_bounty
            existing.reward_hint = hit.reward_hint
            existing.domains_json = domains_json
            existing.scope_raw = json.dumps(hit.raw or {}, default=str)[:20000]
            existing.value_score = self.value_score(hit)
            existing.last_seen_at = now
            if was_updated:
                existing.last_changed_at = now
            session.add(existing)
            return existing, False, was_updated

        program = BountyProgram(
            name=hit.name,
            platform=hit.platform,
            url=hit.url,
            offers_bounty=hit.offers_bounty,
            reward_hint=hit.reward_hint,
            domains_json=domains_json,
            scope_raw=json.dumps(hit.raw or {}, default=str)[:20000],
            value_score=self.value_score(hit),
            first_seen_at=now,
            last_seen_at=now,
            last_changed_at=now,
        )
        session.add(program)
        return program, True, False

    def add_program_targets(self, session: Session, program_id: str, limit: int = 25) -> Dict[str, Any]:
        program = session.get(BountyProgram, program_id)
        if not program:
            raise ValueError("Program not found")
        domains = json.loads(program.domains_json or "[]")[:limit]
        created = []
        existing_domains = {t.domain.lower() for t in session.exec(select(Target)).all()}
        for domain in domains:
            clean = domain.replace("*.", "")
            if clean.lower() in existing_domains:
                continue
            target = Target(
                name=f"{program.name} / {clean}",
                domain=clean,
                scope=domain,
                out_of_scope=None,
                notes=f"Imported from Bounty Program Radar ({program.platform}). Program URL: {program.url or 'n/a'}",
            )
            session.add(target)
            created.append(target)
            existing_domains.add(clean.lower())
        session.commit()
        for t in created:
            session.refresh(t)
        publish_sync("program.targets.created", {"message": f"Created {len(created)} targets from {program.name}", "program_id": program_id})
        return {"program": program.model_dump(mode="json"), "created_targets": [t.model_dump(mode="json") for t in created]}


radar = ProgramRadarAgent()
