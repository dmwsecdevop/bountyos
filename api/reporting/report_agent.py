"""Bounty-ready report generator for confirmed or high-confidence findings."""
from __future__ import annotations

import html
import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

from sqlmodel import Session, select

from api.models import (
    BountyReport, BugHypothesis, EvidenceArtifact, Finding, Scan, Target,
    ValidationAttempt,
)
from api.validation.evidence import redact
from api.intelligence.memory import shared_memory

SEV_TO_CVSS = {"critical": 9.5, "high": 8.1, "medium": 5.5, "low": 3.1, "info": 0.0}
CWE_MAP = {
    "idor": "CWE-639", "auth_flow": "CWE-287", "secret_exposure": "CWE-200",
    "ssrf": "CWE-918", "file_upload": "CWE-434", "graphql": "CWE-285",
    "subdomain_takeover": "CWE-284", "xss": "CWE-79", "cors": "CWE-942",
    "business_logic": "CWE-840", "known_vulnerability": "CWE-1104",
}


def _safe_json(raw: str, default: Any):
    try: return json.loads(raw or json.dumps(default))
    except Exception: return default


class ReportAgent:
    def _choose_finding(self, session: Session, scan_id: str, finding_id: Optional[str]) -> Optional[Finding]:
        if finding_id:
            return session.get(Finding, finding_id)
        findings = session.exec(select(Finding).where(Finding.scan_id == scan_id)).all()
        order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        findings.sort(key=lambda f: order.get(getattr(f.severity, "value", str(f.severity)), 5))
        return findings[0] if findings else None

    def generate(self, session: Session, scan_id: str, finding_id: Optional[str] = None,
                 validation_attempt_id: Optional[str] = None) -> Dict[str, Any]:
        scan = session.get(Scan, scan_id)
        if not scan: raise ValueError("Scan not found")
        target = session.get(Target, scan.target_id)
        finding = self._choose_finding(session, scan_id, finding_id)
        attempt = session.get(ValidationAttempt, validation_attempt_id) if validation_attempt_id else None
        hypothesis = session.get(BugHypothesis, attempt.hypothesis_id) if attempt else None
        if not hypothesis:
            hypothesis = session.exec(
                select(BugHypothesis).where(BugHypothesis.scan_id == scan_id)
                .order_by(BugHypothesis.priority_score.desc())
            ).first()

        bug_class = hypothesis.bug_class if hypothesis else "security_finding"
        title = finding.title if finding else (hypothesis.title if hypothesis else f"Security finding on {target.domain if target else 'target'}")
        severity = getattr(finding.severity, "value", str(finding.severity)) if finding else ("high" if hypothesis and hypothesis.priority_score >= 70 else "medium")
        cvss = finding.cvss_score if finding and finding.cvss_score is not None else SEV_TO_CVSS.get(severity, 5.5)
        cwe = finding.cwe_id if finding and finding.cwe_id else CWE_MAP.get(bug_class, "CWE-20")
        endpoint = finding.url if finding and finding.url else (hypothesis.target if hypothesis else (target.domain if target else ""))
        evidence_rows = session.exec(select(EvidenceArtifact).where(EvidenceArtifact.scan_id == scan_id)).all()
        evidence_text = []
        if finding and finding.evidence:
            evidence_text.append(redact(finding.evidence))
        if attempt:
            evidence_text.extend(redact(x) for x in _safe_json(attempt.evidence_json, []))
        evidence_text.extend(f"{e.title}: {e.content[:1200]}" for e in evidence_rows[:8])
        evidence_text = list(dict.fromkeys(evidence_text))

        confirmed = bool(finding and not finding.false_positive) or bool(attempt and attempt.status == "confirmed")
        likely = bool(attempt and attempt.status == "likely") or bool(hypothesis and hypothesis.confidence >= .8)
        report_status = "ready" if confirmed and evidence_text else ("needs_evidence" if not evidence_text else "draft")

        summary = (
            (finding.description if finding and finding.description else None)
            or (hypothesis.reasoning_summary if hypothesis else None)
            or "BountyOS identified an evidence-backed security weakness that requires program triage."
        )
        confirmed_impact = "The confirmed impact is limited to the behavior shown in the attached evidence."
        potential_impact = "Related endpoints or state transitions may be affected, but those paths are not claimed without separate validation."
        if bug_class == "idor":
            confirmed_impact = "A user may be able to access an object that is not owned by their account when server-side ownership checks are missing."
            potential_impact = "Similar read, update, download, cancellation, or administrative object endpoints may share the same authorization weakness."
        elif bug_class == "secret_exposure":
            confirmed_impact = "A sensitive configuration or source artifact appears reachable without the intended access control."
            potential_impact = "Any exposed credential must be assessed separately and rotated; the report does not claim credential validity unless verified within program rules."
        elif bug_class == "auth_flow":
            confirmed_impact = "The authentication or recovery state machine may accept a transition without the expected identity or authorization check."
            potential_impact = "Depending on the affected transition, this could lead to unauthorized account changes or account access."

        reproduction = [
            "Use a researcher-controlled account and open the affected feature.",
            f"Send the request or action associated with: {endpoint or 'the affected resource'}.",
            "Change only the minimum object/state value required to demonstrate the behavior.",
            "Observe the response and compare it with the expected authorization or validation result.",
            "Stop immediately after the first minimal proof and preserve the sanitized request/response evidence.",
        ]
        if hypothesis:
            steps = _safe_json(hypothesis.safe_next_steps_json, [])
            if steps: reproduction = steps

        expected = "The server should reject unauthorized, invalid, or out-of-state requests with a consistent 4xx response and no sensitive data."
        actual = "The observed behavior differs from the expected server-side authorization or validation control, as shown in the evidence."
        remediation = finding.remediation if finding and finding.remediation else (
            "Enforce the security decision in deterministic server-side code for every affected endpoint. "
            "Do not rely on the UI or an AI model to authorize privileged changes. Add negative authorization tests, "
            "least-privilege service permissions, and regression coverage for every state transition."
        )

        quality_items = {
            "clear_title": bool(title), "in_scope_target": bool(target and target.scope),
            "reproduction_steps": len(reproduction) >= 3, "evidence": bool(evidence_text),
            "severity_reasoning": bool(severity and cvss is not None), "remediation": bool(remediation),
            "confirmed_or_likely": confirmed or likely,
        }
        quality_score = round(sum(quality_items.values()) / len(quality_items) * 100)
        missing = [k.replace("_", " ") for k, ok in quality_items.items() if not ok]

        now = datetime.utcnow()
        payload = {
            "title": title, "platform": "BountyOS export", "target": target.domain if target else None,
            "scope": target.scope if target else None, "endpoint": endpoint, "bug_class": bug_class,
            "cwe": cwe, "severity": severity, "cvss": cvss,
            "confidence": hypothesis.confidence if hypothesis else (0.95 if confirmed else 0.7),
            "status": "confirmed" if confirmed else ("likely" if likely else "draft"),
            "executive_summary": summary, "preconditions": ["Use only authorized, researcher-controlled accounts and in-scope assets."],
            "steps_to_reproduce": reproduction, "expected_behavior": expected, "actual_behavior": actual,
            "confirmed_impact": confirmed_impact, "potential_impact": potential_impact,
            "evidence": evidence_text, "remediation": remediation,
            "verification_steps": [
                "Repeat the minimal reproduction after the fix.",
                "Confirm the server now returns a consistent 403/404 or validation error.",
                "Test related read, write, delete and download operations independently.",
                "Confirm logs show the rejected request without exposing secrets.",
            ],
            "safety_statement": (
                "Testing used authorized targets and researcher-controlled data. No bulk enumeration, persistence, "
                "destructive action, or unrelated data collection was performed. Testing stopped after minimal proof."
            ),
            "timeline": [{"time": now.isoformat(), "event": "Report generated by BountyOS Report Agent"}],
            "quality": {"score": quality_score, "missing": missing, "checks": quality_items},
        }

        md = self.to_markdown(payload)
        report = BountyReport(
            scan_id=scan_id, finding_id=finding.id if finding else None,
            validation_attempt_id=attempt.id if attempt else None, title=title,
            status=report_status, content_markdown=md,
            content_json=json.dumps(payload, default=str), quality_score=quality_score,
            missing_items_json=json.dumps(missing),
        )
        session.add(report); session.commit(); session.refresh(report)
        self.write_exports(report)
        report_id = report.id
        shared_memory.add(session, "report_agent", "result",
                          f"Generated report '{title}' with quality score {quality_score}/100.",
                          scan_id, {"report_id": report_id, "status": report_status}, .95)
        report = session.get(BountyReport, report_id)
        return self.serialize(report)

    def write_exports(self, report: BountyReport) -> Dict[str, str]:
        base = Path(os.getenv("BOUNTYOS_EXPORT_DIR", "./exports")) / "reports"
        base.mkdir(parents=True, exist_ok=True)
        stem = report.id
        md_path = base / f"{stem}.md"
        json_path = base / f"{stem}.json"
        html_path = base / f"{stem}.html"
        md_path.write_text(report.content_markdown, encoding="utf-8")
        data = _safe_json(report.content_json, {})
        json_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        html_path.write_text(self.to_html(data), encoding="utf-8")
        return {"markdown": str(md_path), "json": str(json_path), "html": str(html_path)}

    def to_markdown(self, p: Dict[str, Any]) -> str:
        steps = "\n".join(f"{i+1}. {s}" for i, s in enumerate(p["steps_to_reproduce"]))
        evidence = "\n\n".join(f"```text\n{e}\n```" for e in p["evidence"]) or "_Evidence still required._"
        verification = "\n".join(f"- {s}" for s in p["verification_steps"])
        return f"""# {p['title']}

## Executive summary
{p['executive_summary']}

## Target
- **Asset:** {p['target'] or '-'}
- **Endpoint:** {p['endpoint'] or '-'}
- **Scope:** {p['scope'] or '-'}
- **Bug class:** {p['bug_class']}
- **CWE:** {p['cwe']}
- **Severity:** {p['severity'].upper()} (CVSS {p['cvss']})
- **Confidence:** {p['confidence']:.0%}

## Preconditions
- Use only authorized, researcher-controlled accounts and in-scope assets.

## Steps to reproduce
{steps}

## Expected behavior
{p['expected_behavior']}

## Actual behavior
{p['actual_behavior']}

## Evidence
{evidence}

## Impact
**Confirmed:** {p['confirmed_impact']}

**Potential, not yet claimed:** {p['potential_impact']}

## Recommended remediation
{p['remediation']}

## Verification after fix
{verification}

## Testing safety statement
{p['safety_statement']}

## Report quality
- Score: **{p['quality']['score']}/100**
- Missing: {', '.join(p['quality']['missing']) if p['quality']['missing'] else 'None'}
"""

    def to_html(self, p: Dict[str, Any]) -> str:
        md = self.to_markdown(p)
        return f"""<!doctype html><html><head><meta charset='utf-8'><title>{html.escape(p['title'])}</title>
<style>body{{font:15px system-ui;background:#071016;color:#d8f7ee;max-width:960px;margin:auto;padding:40px}}pre{{white-space:pre-wrap;background:#0d1d24;padding:24px;border:1px solid #1d4450;border-radius:12px}}h1{{color:#3dffd0}}</style></head><body><pre>{html.escape(md)}</pre></body></html>"""

    @staticmethod
    def serialize(report: BountyReport) -> Dict[str, Any]:
        item = report.model_dump(mode="json")
        item["content"] = _safe_json(report.content_json, {})
        item["missing_items"] = _safe_json(report.missing_items_json, [])
        item["exports"] = ReportAgent().write_exports(report)
        return item


report_agent = ReportAgent()
