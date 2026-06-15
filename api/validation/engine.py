"""Controlled validation planner/executor.

Safe actions analyse existing evidence.  Active actions create a deterministic
approval request and a bounded plan.  Execution adapters can be added later,
but arbitrary model-generated shell commands are never accepted here.
"""
from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Dict, Optional
from sqlmodel import Session, select

from api.models import (
    Approval, ApprovalStatus, BugHypothesis, Finding, PlannerDecision, ScanPhase,
    ValidationAttempt,
)
from api.validation.policy import evaluate
from api.validation.evidence import evidence_store
from api.intelligence.memory import shared_memory
from api.learning.experience_store import experience_store


class ValidationEngine:
    def create_attempt(self, session: Session, decision_id: str) -> Dict[str, Any]:
        decision = session.get(PlannerDecision, decision_id)
        if not decision:
            raise ValueError("Planner decision not found")
        hypothesis = session.get(BugHypothesis, decision.hypothesis_id) if decision.hypothesis_id else None
        policy = evaluate(decision.action_name, decision.rationale)
        plan = {
            "action": decision.action_name,
            "target": decision.target,
            "hypothesis": hypothesis.title if hypothesis else None,
            "risk_level": policy.level,
            "request_budget": policy.request_budget,
            "stop_condition": policy.stop_condition,
            "steps": json.loads(hypothesis.safe_next_steps_json or "[]") if hypothesis else [],
        }
        status = "blocked" if policy.level == "blocked" else ("awaiting_approval" if policy.level == "approval_required" else "planned")
        attempt = ValidationAttempt(
            scan_id=decision.scan_id, hypothesis_id=decision.hypothesis_id or "",
            planner_decision_id=decision.id, validation_type=decision.action_name,
            status=status, plan_json=json.dumps(plan), approved=False,
        )
        session.add(attempt)
        decision.status = "skipped" if status == "blocked" else "queued"
        session.add(decision); session.commit(); session.refresh(attempt)

        approval_id = None
        if status == "awaiting_approval":
            approval = Approval(
                scan_id=decision.scan_id, phase=ScanPhase.EXPLOIT,
                action=f"Validate: {decision.action_name}",
                context=json.dumps({"validation_attempt_id": attempt.id, "plan": plan}),
                status=ApprovalStatus.PENDING,
            )
            session.add(approval); session.commit(); session.refresh(approval)
            approval_id = approval.id
            session.refresh(attempt)
        attempt_id = attempt.id
        shared_memory.add(session, "validation_agent", "plan",
                          f"Prepared {decision.action_name} with policy level {policy.level}.",
                          decision.scan_id, {"attempt_id": attempt_id, "approval_id": approval_id}, .9)
        attempt = session.get(ValidationAttempt, attempt_id)
        return {**self.serialize(attempt), "policy": policy.as_dict(), "approval_id": approval_id}

    def approve(self, session: Session, attempt_id: str, approved: bool) -> Dict[str, Any]:
        attempt = session.get(ValidationAttempt, attempt_id)
        if not attempt:
            raise ValueError("Validation attempt not found")
        attempt.approved = approved
        attempt.status = "approved" if approved else "blocked"
        session.add(attempt)
        # Resolve the linked approval if present.
        approvals = session.exec(select(Approval).where(Approval.scan_id == attempt.scan_id)).all()
        for approval in approvals:
            if attempt.id in (approval.context or "") and approval.status == ApprovalStatus.PENDING:
                approval.status = ApprovalStatus.APPROVED if approved else ApprovalStatus.REJECTED
                approval.decided_at = datetime.utcnow()
                session.add(approval)
        session.commit()
        session.refresh(attempt)
        return self.serialize(attempt)

    def execute(self, session: Session, attempt_id: str, dry_run: bool = True) -> Dict[str, Any]:
        attempt = session.get(ValidationAttempt, attempt_id)
        if not attempt:
            raise ValueError("Validation attempt not found")
        hypothesis = session.get(BugHypothesis, attempt.hypothesis_id)
        policy = evaluate(attempt.validation_type, hypothesis.reasoning_summary if hypothesis else "")
        if policy.level == "blocked":
            attempt.status = "blocked"; attempt.finished_at = datetime.utcnow()
            attempt.result_summary = policy.reason
            session.add(attempt); session.commit(); session.refresh(attempt)
            return self.serialize(attempt)
        if policy.level == "approval_required" and not attempt.approved:
            attempt.status = "awaiting_approval"; session.add(attempt); session.commit()
            return self.serialize(attempt)

        attempt.status = "running"; attempt.started_at = datetime.utcnow()
        session.add(attempt); session.commit()

        # Evidence-driven validation.  This intentionally does not accept raw
        # commands or payloads from model output.  Active adapters can use the
        # bounded plan after approval; dry-run remains the default.
        findings = session.exec(select(Finding).where(Finding.scan_id == attempt.scan_id)).all()
        matching = []
        if hypothesis:
            terms = set((hypothesis.bug_class + " " + hypothesis.title).lower().replace("_", " ").split())
            for f in findings:
                text = " ".join(filter(None, [f.title, f.description, f.evidence, f.cwe_id])).lower()
                if sum(1 for t in terms if len(t) > 3 and t in text) >= 1:
                    matching.append(f)
        evidence_lines = []
        for f in matching[:8]:
            evidence_lines.append(f"Finding {f.id}: {f.title} | severity={getattr(f.severity, 'value', f.severity)} | url={f.url or '-'}")
            if f.evidence:
                evidence_lines.append(f.evidence[:1200])

        if dry_run and policy.level == "approval_required":
            status = "approved"
            summary = "Approved validation plan is ready. Dry-run mode prevented active requests; connect a bounded validation adapter to execute it."
        elif matching:
            status = "likely"
            summary = f"Existing scan evidence supports the hypothesis with {len(matching)} related finding(s); active proof was not required."
        else:
            status = "inconclusive"
            summary = "No existing evidence was strong enough to confirm the hypothesis. Additional approved, minimal validation is required."

        attempt.status = status
        attempt.result_summary = summary
        attempt.evidence_json = json.dumps(evidence_lines)
        attempt.requests_sent = 0
        attempt.finished_at = datetime.utcnow()
        session.add(attempt)
        if hypothesis:
            hypothesis.status = "confirmed" if status == "confirmed" else ("validating" if status in {"approved", "likely"} else status)
            session.add(hypothesis)
        session.commit()

        if evidence_lines:
            evidence_store.add(
                session, attempt.scan_id, f"Validation evidence: {attempt.validation_type}",
                "\n".join(evidence_lines), "log", attempt.id,
            )
        experience_store.record(
            session, attempt.validation_type, status, attempt.scan_id,
            {"hypothesis_id": attempt.hypothesis_id, "dry_run": dry_run},
            novelty_reward=3 if matching else 0,
            impact_reward=6 if status in {"likely", "confirmed"} else 0,
            cost_penalty=1 if policy.level == "approval_required" else 0,
        )
        shared_memory.add(session, "validation_agent", "result", summary, attempt.scan_id,
                          {"attempt_id": attempt.id, "status": status}, .8)
        session.refresh(attempt)
        return self.serialize(attempt)

    @staticmethod
    def serialize(attempt: ValidationAttempt) -> Dict[str, Any]:
        item = attempt.model_dump(mode="json")
        for source, target, default in [
            ("plan_json", "plan", {}), ("evidence_json", "evidence", [])
        ]:
            try: item[target] = json.loads(getattr(attempt, source) or json.dumps(default))
            except Exception: item[target] = default
        return item


validation_engine = ValidationEngine()
