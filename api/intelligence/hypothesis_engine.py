"""Deterministic expert-style bug hypothesis engine.

The engine does not claim vulnerabilities are confirmed.  It converts evidence
patterns into ranked, reviewable hypotheses and safe next steps.
"""
from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Dict, List
from sqlmodel import Session, select

from api.models import AttackNode, BugHypothesis, Finding, Scan, ScanEvent, Target
from api.intelligence.memory import shared_memory

RULES: List[Dict[str, Any]] = [
    {"bug_class":"idor", "title":"Possible broken object-level authorization", "terms":["/api/","user_id","account_id","order_id","profile","invoice","object id","numeric id"], "impact":0.88, "approval":True,
     "steps":["Map object identifiers and ownership boundaries", "Use only researcher-controlled accounts for cross-account comparison", "Stop after the first minimal authorization mismatch"]},
    {"bug_class":"auth_flow", "title":"Authentication or recovery state-machine weakness", "terms":["login","forgot password","password reset","mfa","2fa","oauth","invite","verify email","session"], "impact":0.9, "approval":True,
     "steps":["Diagram every state transition", "Compare web/mobile/legacy flows", "Validate with test accounts and no real-user impact"]},
    {"bug_class":"secret_exposure", "title":"Potential exposed secret, configuration, backup or source artifact", "terms":[".env","config.yml","web.config","backup",".bak","debug.log","source map",".map","api key","secret"], "impact":0.82, "approval":False,
     "steps":["Verify the artifact is publicly accessible", "Redact secret values in evidence", "Check scope before any credential validation"]},
    {"bug_class":"ssrf", "title":"Potential server-side request forgery surface", "terms":["webhook","callback","fetch url","import url","avatar url","proxy","redirect_uri","url="], "impact":0.86, "approval":True,
     "steps":["Identify server-side URL consumption", "Prepare a controlled callback domain", "Use a single harmless callback and stop after confirmation"]},
    {"bug_class":"file_upload", "title":"Potential file-upload validation or storage weakness", "terms":["upload","multipart","attachment","avatar","document","file type","content-type"], "impact":0.8, "approval":True,
     "steps":["Map extension, MIME and storage controls", "Use inert test files only", "Check whether uploaded content is served with unsafe headers"]},
    {"bug_class":"graphql", "title":"GraphQL schema and authorization review candidate", "terms":["graphql","__schema","apollo","mutation","query{"], "impact":0.76, "approval":False,
     "steps":["Map public schema metadata where allowed", "Identify object-level authorization boundaries", "Prioritize sensitive mutations and nested objects"]},
    {"bug_class":"subdomain_takeover", "title":"Potential dangling DNS or third-party subdomain claim", "terms":["nxdomain","no such app","there isn't a github pages site","unclaimed","dangling cname","herokuapp","github.io"], "impact":0.78, "approval":False,
     "steps":["Confirm DNS delegation and provider fingerprint", "Do not claim resources without explicit program permission", "Capture DNS and provider evidence"]},
    {"bug_class":"xss", "title":"Client-side injection or unsafe rendering candidate", "terms":["xss","reflected","innerhtml","document.write","dangerouslysetinnerhtml","postmessage","dom sink"], "impact":0.72, "approval":True,
     "steps":["Identify source-to-sink data flow", "Use a harmless marker before any execution proof", "Stop at minimal non-destructive confirmation"]},
    {"bug_class":"cors", "title":"Cross-origin trust boundary may be too broad", "terms":["access-control-allow-origin","cors","allow-credentials","origin reflected"], "impact":0.62, "approval":False,
     "steps":["Compare trusted and untrusted origins", "Confirm whether credentials and sensitive responses combine", "Do not overstate impact without readable data"]},
    {"bug_class":"business_logic", "title":"Business-logic abuse surface worth focused review", "terms":["checkout","coupon","discount","subscription","billing","payment","refund","order","invite","role","team"], "impact":0.84, "approval":True,
     "steps":["Model actors, roles, assets and state transitions", "Check skipped, repeated and concurrent steps", "Use researcher-controlled transactions and minimal amounts"]},
    {"bug_class":"known_vulnerability", "title":"Version/CVE correlation requires confirmation", "terms":["cve-","outdated","version","end of life","vulnerable version"], "impact":0.68, "approval":False,
     "steps":["Confirm the exact reachable version", "Separate version match from exploitability", "Use a safe template or vendor advisory for validation"]},
]


class HypothesisEngine:
    def _corpus(self, session: Session, scan_id: str) -> tuple[str, List[str]]:
        events = session.exec(select(ScanEvent).where(ScanEvent.scan_id == scan_id)).all()
        findings = session.exec(select(Finding).where(Finding.scan_id == scan_id)).all()
        nodes = session.exec(select(AttackNode).where(AttackNode.scan_id == scan_id)).all()
        pieces: List[str] = []
        evidence: List[str] = []
        for e in events:
            text = " ".join(filter(None, [e.message, e.raw]))
            pieces.append(text)
            if text: evidence.append(text[:300])
        for f in findings:
            text = " ".join(filter(None, [f.title, f.description, f.evidence, f.url, f.cwe_id]))
            pieces.append(text)
            evidence.append(f"Finding: {f.title}" + (f" @ {f.url}" if f.url else ""))
        for n in nodes:
            pieces.extend([n.label, n.key, n.attributes_json])
        return "\n".join(pieces).lower(), evidence

    def generate(self, session: Session, scan_id: str, replace: bool = False) -> List[Dict[str, Any]]:
        scan = session.get(Scan, scan_id)
        if not scan: raise ValueError("Scan not found")
        target = session.get(Target, scan.target_id)
        corpus, base_evidence = self._corpus(session, scan_id)
        existing = {h.bug_class: h for h in session.exec(select(BugHypothesis).where(BugHypothesis.scan_id == scan_id)).all()}
        created: List[BugHypothesis] = []

        for rule in RULES:
            hits = [term for term in rule["terms"] if term in corpus]
            if not hits:
                continue
            density = min(1.0, len(hits) / max(3, len(rule["terms"]) * 0.45))
            confidence = round(min(0.95, 0.45 + density * 0.38 + min(0.12, corpus.count(hits[0]) * 0.015)), 2)
            priority = round(100 * confidence * rule["impact"], 1)
            evidence = [f"Matched evidence pattern: {h}" for h in hits[:8]]
            evidence.extend(base_evidence[:6])
            row = existing.get(rule["bug_class"])
            if row and not replace:
                row.confidence = max(row.confidence, confidence)
                row.priority_score = max(row.priority_score, priority)
                row.evidence_json = json.dumps(list(dict.fromkeys(json.loads(row.evidence_json or "[]") + evidence))[:20])
                row.safe_next_steps_json = json.dumps(rule["steps"])
                row.updated_at = datetime.utcnow()
            else:
                row = BugHypothesis(
                    scan_id=scan_id, title=rule["title"], bug_class=rule["bug_class"],
                    target=target.domain if target else None, confidence=confidence,
                    priority_score=priority,
                    bounty_value="high" if rule["impact"] >= .82 else "medium",
                    reasoning_summary=(
                        f"The attack graph contains {len(hits)} signal(s) commonly associated with "
                        f"{rule['bug_class'].replace('_',' ')}. This is a hypothesis, not a confirmed vulnerability."
                    ),
                    evidence_json=json.dumps(evidence[:20]),
                    safe_next_steps_json=json.dumps(rule["steps"]),
                    approval_required=rule["approval"], status="proposed",
                )
            session.add(row); session.flush(); created.append(row)
        session.commit()
        ids = [h.id for h in created]
        shared_memory.add(
            session, "bug_hunter_brain", "reasoning_summary",
            f"Generated or refreshed {len(created)} evidence-backed hypotheses.",
            scan_id, {"hypothesis_ids": ids}, .85,
        )
        refreshed = [session.get(BugHypothesis, hid) for hid in ids]
        return [self.serialize(h) for h in sorted([x for x in refreshed if x], key=lambda x: x.priority_score, reverse=True)]

    @staticmethod
    def serialize(h: BugHypothesis) -> Dict[str, Any]:
        item = h.model_dump(mode="json")
        for source, target in [("evidence_json", "evidence"), ("safe_next_steps_json", "safe_next_steps")]:
            try: item[target] = json.loads(getattr(h, source) or "[]")
            except Exception: item[target] = []
        return item


hypothesis_engine = HypothesisEngine()
