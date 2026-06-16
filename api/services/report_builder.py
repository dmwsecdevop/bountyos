from __future__ import annotations
from typing import Any
from api.models import Finding, Scan
from api.database import session_ctx
TEMPLATES=["HackerOne","Bugcrowd","Intigriti","Generic Markdown"]
def _missing(value: Any, label: str) -> str: return str(value) if value not in (None, "") else f"Missing {label}; evidence was not provided."
def fallback_report_for_finding(f: Finding, template: str = "Generic Markdown") -> dict:
    return {
        "template": template if template in TEMPLATES else "Generic Markdown",
        "title": f.title,
        "summary": _missing(f.description, "summary"),
        "impact": "Impact should be derived from the confirmed evidence. Missing impact if not present in finding context.",
        "steps_to_reproduce": "Missing reproducible steps; add exact authorized steps from existing evidence before submission.",
        "evidence": _missing(f.evidence, "evidence"),
        "affected_assets": [f.url] if f.url else [],
        "severity": str(f.severity),
        "cvss": f.cvss_score,
        "remediation": _missing(f.remediation, "remediation"),
        "timeline_notes": "Generated from existing Finding fields only; no evidence invented.",
    }
def draft_finding_report(finding_id: str, template: str = "Generic Markdown") -> dict | None:
    with session_ctx() as s:
        f=s.get(Finding,finding_id)
        return fallback_report_for_finding(f, template) if f else None
def scan_summary(scan_id: str) -> dict:
    with session_ctx() as s:
        scan=s.get(Scan, scan_id); findings=s.exec(__import__('sqlmodel').select(Finding).where(Finding.scan_id==scan_id)).all()
    return {"scan_id":scan_id,"status":getattr(scan,'status',None),"finding_count":len(findings),"findings":[fallback_report_for_finding(f) for f in findings]}
def templates(): return TEMPLATES
