"""Evidence-grounded self-evaluation for BountyOS agents.

This module deliberately does not trust an agent's own prose as proof. Scores are
computed from database evidence, workflow state, approval records, and report
quality checks. A different model may later add a critique, but deterministic
checks remain the source of truth.
"""
from __future__ import annotations

import json
import re
from collections import defaultdict
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from sqlmodel import Session, select

from api.models import (
    AgentEvaluation, AgentPerformanceRecord, BugHypothesis, BountyReport,
    EvidenceArtifact, Finding, PlannerDecision, Scan, ValidationAttempt,
)
from api.intelligence.memory import shared_memory
from api.learning.experience_store import experience_store

ACTIVE_WORDS = {
    "validate", "active", "exploit", "idor", "authorization", "ssrf", "upload",
    "auth", "nuclei", "sqlmap", "ffuf", "payload", "request", "graphql",
}
SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*:\s*bearer\s+)([^\s]+)"),
    re.compile(r"(?i)(api[_-]?key\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)(password\s*[=:]\s*)([^\s,;]+)"),
    re.compile(r"(?i)(cookie\s*:\s*)([^\n]+)"),
]


def _json(raw: str, default: Any):
    try:
        return json.loads(raw or json.dumps(default))
    except Exception:
        return default


def _clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


def _status(score: int) -> str:
    if score >= 90:
        return "accepted"
    if score >= 75:
        return "accepted_with_warnings"
    if score >= 50:
        return "retry"
    return "rejected"


def _weighted(scores: Dict[str, int]) -> int:
    weights = {
        "evidence_quality": .24,
        "accuracy": .23,
        "reproducibility": .16,
        "impact_confidence": .14,
        "efficiency": .10,
        "safety": .13,
    }
    return round(sum(scores[k] * weights[k] for k in weights))


class QualityEngine:
    version = "1.0"

    def _store(self, session: Session, *, scan_id: Optional[str], task_type: str,
               task_id: Optional[str], producer_agent: str, evaluator_agent: str,
               model_expert: str, scores: Dict[str, int], findings: List[str],
               recommendations: List[str], calibrated_confidence: float,
               retry_count: int = 0, parent_evaluation_id: Optional[str] = None,
               metadata: Optional[dict] = None) -> Dict[str, Any]:
        overall = _weighted(scores)
        row = AgentEvaluation(
            scan_id=scan_id,
            task_type=task_type,
            task_id=task_id,
            producer_agent=producer_agent,
            evaluator_agent=evaluator_agent,
            model_expert=model_expert,
            status=_status(overall),
            overall_score=overall,
            evidence_quality=scores["evidence_quality"],
            accuracy=scores["accuracy"],
            reproducibility=scores["reproducibility"],
            impact_confidence=scores["impact_confidence"],
            efficiency=scores["efficiency"],
            safety=scores["safety"],
            calibrated_confidence=round(calibrated_confidence, 4),
            findings_json=json.dumps(findings),
            recommendations_json=json.dumps(recommendations),
            retry_count=retry_count,
            parent_evaluation_id=parent_evaluation_id,
            metadata_json=json.dumps(metadata or {}, default=str),
        )
        session.add(row)
        session.commit()
        session.refresh(row)
        perf = AgentPerformanceRecord(
            scan_id=scan_id,
            evaluation_id=row.id,
            agent=producer_agent,
            model_expert=model_expert,
            task_type=task_type,
            outcome=row.status,
            quality_score=overall,
            confirmed=bool((metadata or {}).get("confirmed")),
            latency_ms=float((metadata or {}).get("latency_ms", 0.0)),
            estimated_cost=float((metadata or {}).get("estimated_cost", 0.0)),
        )
        session.add(perf)
        session.commit()
        if scan_id:
            shared_memory.add(
                session, "quality_loop", "result",
                f"Evaluated {task_type} from {producer_agent}: {overall}/100 ({row.status}).",
                scan_id, {"evaluation_id": row.id, "task_id": task_id}, overall / 100,
            )
            experience_store.record(
                session, action=f"evaluate_{task_type}", result=row.status, scan_id=scan_id,
                context={"task_id": task_id, "producer_agent": producer_agent, "score": overall},
                novelty_reward=max(0.0, scores["evidence_quality"] / 50 - 1),
                impact_reward=max(0.0, scores["accuracy"] / 50 - 1),
                cost_penalty=0.2 if overall < 50 else 0.0,
                false_positive_penalty=1.0 if row.status == "rejected" else 0.0,
            )
        session.refresh(row)
        return self.serialize(row)

    def evaluate_hypothesis(self, session: Session, hypothesis: BugHypothesis,
                            parent_evaluation_id: Optional[str] = None,
                            retry_count: int = 0) -> Dict[str, Any]:
        evidence = _json(hypothesis.evidence_json, [])
        steps = _json(hypothesis.safe_next_steps_json, [])
        evidence_text = " ".join(map(str, evidence)).lower()
        supported = bool(evidence) and any(token in evidence_text for token in hypothesis.bug_class.replace("_", " ").split())
        evidence_score = int(_clamp(25 + 18 * len(evidence) + (10 if hypothesis.target else 0)))
        accuracy = 88 if supported else (70 if len(evidence) >= 2 else 48)
        reproducibility = int(_clamp(30 + 14 * len(steps)))
        impact = int(_clamp(35 + hypothesis.priority_score * .45 + (10 if hypothesis.bounty_value == "high" else 0)))
        efficiency = 92 if 2 <= len(steps) <= 6 else (70 if steps else 35)
        active = hypothesis.approval_required or hypothesis.bug_class in {"idor", "ssrf", "file_upload", "auth_flow", "business_logic"}
        safety = 94 if (not active or hypothesis.approval_required) else 45
        max_conf = .45 if not evidence else (.68 if len(evidence) == 1 else (.88 if len(evidence) < 4 else .96))
        calibrated = min(float(hypothesis.confidence), max_conf, (evidence_score + accuracy) / 200)
        findings, recs = [], []
        if not evidence:
            findings.append("Hypothesis has no attached evidence.")
            recs.append("Collect at least one concrete scan event, endpoint, or finding before prioritizing it.")
        if not supported:
            findings.append("Evidence does not clearly support the selected bug class.")
            recs.append("Reclassify the hypothesis or add evidence that directly matches the claimed weakness.")
        if hypothesis.confidence > calibrated + .1:
            findings.append("Original confidence is higher than the evidence supports.")
            recs.append(f"Calibrate confidence to approximately {calibrated:.0%} until stronger proof exists.")
        if active and not hypothesis.approval_required:
            findings.append("Active validation was proposed without an approval requirement.")
            recs.append("Require approval before any active validation request is sent.")
        scores = dict(evidence_quality=evidence_score, accuracy=accuracy,
                      reproducibility=reproducibility, impact_confidence=impact,
                      efficiency=efficiency, safety=safety)
        return self._store(
            session, scan_id=hypothesis.scan_id, task_type="hypothesis", task_id=hypothesis.id,
            producer_agent="bug_hunter_brain", evaluator_agent="critic_verifier",
            model_expert="quality_critic", scores=scores, findings=findings,
            recommendations=recs, calibrated_confidence=calibrated,
            retry_count=retry_count, parent_evaluation_id=parent_evaluation_id,
            metadata={"original_confidence": hypothesis.confidence, "evidence_count": len(evidence)},
        )

    def evaluate_plan(self, session: Session, plan: PlannerDecision,
                      parent_evaluation_id: Optional[str] = None,
                      retry_count: int = 0) -> Dict[str, Any]:
        hyp = session.get(BugHypothesis, plan.hypothesis_id) if plan.hypothesis_id else None
        text = f"{plan.action_type} {plan.action_name} {plan.rationale}".lower()
        active = any(word in text for word in ACTIVE_WORDS)
        evidence_score = 85 if hyp else 48
        accuracy = 88 if hyp and plan.target else (72 if hyp else 50)
        reproducibility = 88 if plan.action_name and plan.rationale and plan.target else 58
        impact = int(_clamp(plan.expected_value * 100))
        effort_penalty = {"low": 0, "medium": 12, "high": 25}.get(plan.effort, 15)
        noise_penalty = {"low": 0, "medium": 10, "high": 25}.get(plan.noise, 12)
        efficiency = int(_clamp(100 - effort_penalty - noise_penalty))
        safety = 95 if (not active or plan.approval_required) else 35
        calibrated = min(.95, max(.25, (accuracy + evidence_score + impact) / 300))
        findings, recs = [], []
        if not hyp:
            findings.append("Plan is not linked to a hypothesis.")
            recs.append("Link the action to evidence and a specific bug hypothesis.")
        if not plan.target:
            findings.append("Plan has no explicit target resource.")
            recs.append("Set the exact in-scope asset or endpoint before execution.")
        if active and not plan.approval_required:
            findings.append("Potentially active action is missing an approval gate.")
            recs.append("Mark the plan approval_required before preparing validation.")
        if plan.expected_value < .35:
            findings.append("Expected value is low relative to execution cost.")
            recs.append("Prefer a higher-value action or collect more passive evidence first.")
        scores = dict(evidence_quality=evidence_score, accuracy=accuracy,
                      reproducibility=reproducibility, impact_confidence=impact,
                      efficiency=efficiency, safety=safety)
        return self._store(
            session, scan_id=plan.scan_id, task_type="plan", task_id=plan.id,
            producer_agent="adaptive_planner", evaluator_agent="critic_verifier",
            model_expert="quality_critic", scores=scores, findings=findings,
            recommendations=recs, calibrated_confidence=calibrated,
            retry_count=retry_count, parent_evaluation_id=parent_evaluation_id,
            metadata={"expected_value": plan.expected_value, "active_action": active},
        )

    def evaluate_validation(self, session: Session, attempt: ValidationAttempt,
                            parent_evaluation_id: Optional[str] = None,
                            retry_count: int = 0) -> Dict[str, Any]:
        artifacts = session.exec(select(EvidenceArtifact).where(EvidenceArtifact.validation_attempt_id == attempt.id)).all()
        plan = _json(attempt.plan_json, {})
        confirmed = attempt.status == "confirmed"
        conclusive = attempt.status in {"confirmed", "likely", "false_positive"}
        evidence_score = int(_clamp(20 + len(artifacts) * 22 + (20 if attempt.evidence_json not in {"", "[]"} else 0)))
        accuracy = 95 if confirmed and artifacts else (82 if conclusive else 55)
        reproducibility = int(_clamp(35 + (25 if plan.get("stop_condition") else 0) + (20 if plan.get("request_budget") is not None else 0) + min(20, len(artifacts) * 5)))
        impact = 95 if confirmed else (78 if attempt.status == "likely" else 45)
        budget = int(plan.get("request_budget") or 0)
        efficiency = 95 if attempt.requests_sent <= max(1, budget) else 55
        needs_approval = bool(plan.get("approval_required", True))
        safety = 98 if (not needs_approval or attempt.approved) else 25
        calibrated = .97 if confirmed and artifacts else (.82 if attempt.status == "likely" and artifacts else .55 if conclusive else .35)
        findings, recs = [], []
        if not artifacts:
            findings.append("No evidence artifact is attached to the validation result.")
            recs.append("Capture a sanitized request, response, or deterministic validation log.")
        if needs_approval and not attempt.approved:
            findings.append("Validation lacks recorded approval.")
            recs.append("Do not accept active validation without an approval record.")
        if attempt.requests_sent > max(1, budget):
            findings.append("Validation exceeded its planned request budget.")
            recs.append("Tighten the executor stop condition and request ceiling.")
        if not conclusive:
            findings.append("Validation result is inconclusive.")
            recs.append("Retry only with additional evidence or a revised minimal proof plan.")
        scores = dict(evidence_quality=evidence_score, accuracy=accuracy,
                      reproducibility=reproducibility, impact_confidence=impact,
                      efficiency=efficiency, safety=safety)
        return self._store(
            session, scan_id=attempt.scan_id, task_type="validation", task_id=attempt.id,
            producer_agent="exploit_validation_agent", evaluator_agent="critic_verifier",
            model_expert="quality_verifier", scores=scores, findings=findings,
            recommendations=recs, calibrated_confidence=calibrated,
            retry_count=retry_count, parent_evaluation_id=parent_evaluation_id,
            metadata={"confirmed": confirmed, "artifact_count": len(artifacts), "request_budget": budget},
        )

    def evaluate_report(self, session: Session, report: BountyReport,
                        parent_evaluation_id: Optional[str] = None,
                        retry_count: int = 0) -> Dict[str, Any]:
        content = _json(report.content_json, {})
        evidence = content.get("evidence") or []
        steps = content.get("steps_to_reproduce") or []
        raw = report.content_markdown or ""
        leaked = any(pattern.search(raw) and "[REDACTED" not in pattern.search(raw).group(0) for pattern in SECRET_PATTERNS)
        evidence_score = int(_clamp(25 + min(55, len(evidence) * 18) + (20 if report.validation_attempt_id else 0)))
        accuracy = int(_clamp(report.quality_score + (5 if content.get("confirmed_impact") else -10)))
        reproducibility = int(_clamp(20 + len(steps) * 13 + (15 if content.get("expected_behavior") else 0) + (15 if content.get("actual_behavior") else 0)))
        status = content.get("status", "draft")
        impact = 92 if status == "confirmed" else (76 if status == "likely" else 50)
        efficiency = 92 if len(raw) < 12000 else 72
        safety = 35 if leaked else (96 if content.get("safety_statement") else 72)
        calibrated = min(.98, max(.35, (accuracy + evidence_score + impact) / 300))
        findings, recs = [], []
        if not evidence:
            findings.append("Report has no attached evidence.")
            recs.append("Attach sanitized request/response or validation artifacts before submission.")
        if len(steps) < 3:
            findings.append("Reproduction steps are incomplete.")
            recs.append("Add minimal, deterministic steps that another triager can reproduce.")
        if leaked:
            findings.append("Possible credential or token material appears unredacted.")
            recs.append("Redact all tokens, cookies, passwords, and unrelated personal data.")
        if report.status != "ready":
            findings.append(f"Report status is {report.status}, not ready.")
            recs.append("Resolve missing quality checks before submission.")
        scores = dict(evidence_quality=evidence_score, accuracy=accuracy,
                      reproducibility=reproducibility, impact_confidence=impact,
                      efficiency=efficiency, safety=safety)
        return self._store(
            session, scan_id=report.scan_id, task_type="report", task_id=report.id,
            producer_agent="report_agent", evaluator_agent="critic_verifier",
            model_expert="quality_critic", scores=scores, findings=findings,
            recommendations=recs, calibrated_confidence=calibrated,
            retry_count=retry_count, parent_evaluation_id=parent_evaluation_id,
            metadata={"report_quality_score": report.quality_score, "confirmed": status == "confirmed", "secret_leak_detected": leaked},
        )

    def evaluate_scan(self, session: Session, scan_id: str,
                      task_types: Optional[Sequence[str]] = None,
                      replace_existing: bool = False) -> Dict[str, Any]:
        if not session.get(Scan, scan_id):
            raise ValueError("Scan not found")
        allowed = set(task_types or ["hypothesis", "plan", "validation", "report"])
        if replace_existing:
            old = session.exec(
                select(AgentEvaluation).where(
                    AgentEvaluation.scan_id == scan_id,
                    AgentEvaluation.task_type.in_(list(allowed)),
                )
            ).all()
            for row in old:
                session.delete(row)
            session.commit()
        results: List[Dict[str, Any]] = []
        if "hypothesis" in allowed:
            for row in session.exec(select(BugHypothesis).where(BugHypothesis.scan_id == scan_id)).all():
                results.append(self.evaluate_hypothesis(session, row))
        if "plan" in allowed:
            for row in session.exec(select(PlannerDecision).where(PlannerDecision.scan_id == scan_id)).all():
                results.append(self.evaluate_plan(session, row))
        if "validation" in allowed:
            for row in session.exec(select(ValidationAttempt).where(ValidationAttempt.scan_id == scan_id)).all():
                results.append(self.evaluate_validation(session, row))
        if "report" in allowed:
            for row in session.exec(select(BountyReport).where(BountyReport.scan_id == scan_id)).all():
                results.append(self.evaluate_report(session, row))
        return {"scan_id": scan_id, "evaluations": results, "summary": self.summary(session, scan_id)}

    def latest_for_task(self, session: Session, task_type: str, task_id: str) -> Optional[AgentEvaluation]:
        return session.exec(
            select(AgentEvaluation).where(
                AgentEvaluation.task_type == task_type,
                AgentEvaluation.task_id == task_id,
            ).order_by(AgentEvaluation.created_at.desc())
        ).first()

    def list(self, session: Session, scan_id: Optional[str] = None,
             status: Optional[str] = None, limit: int = 300) -> List[Dict[str, Any]]:
        query = select(AgentEvaluation)
        if scan_id:
            query = query.where(AgentEvaluation.scan_id == scan_id)
        if status:
            query = query.where(AgentEvaluation.status == status)
        rows = session.exec(query.order_by(AgentEvaluation.created_at.desc()).limit(limit)).all()
        return [self.serialize(row) for row in rows]

    def summary(self, session: Session, scan_id: Optional[str] = None) -> Dict[str, Any]:
        query = select(AgentEvaluation)
        if scan_id:
            query = query.where(AgentEvaluation.scan_id == scan_id)
        rows = session.exec(query).all()
        by_status: Dict[str, int] = defaultdict(int)
        by_agent: Dict[str, List[int]] = defaultdict(list)
        by_task: Dict[str, List[int]] = defaultdict(list)
        for row in rows:
            by_status[row.status] += 1
            by_agent[row.producer_agent].append(row.overall_score)
            by_task[row.task_type].append(row.overall_score)
        avg = round(sum(r.overall_score for r in rows) / len(rows), 1) if rows else 0
        return {
            "total": len(rows), "average_score": avg, "by_status": dict(by_status),
            "by_agent": {k: {"count": len(v), "average_score": round(sum(v)/len(v), 1)} for k, v in by_agent.items()},
            "by_task": {k: {"count": len(v), "average_score": round(sum(v)/len(v), 1)} for k, v in by_task.items()},
            "needs_attention": sum(by_status[s] for s in ("retry", "rejected")),
        }

    def performance(self, session: Session) -> Dict[str, Any]:
        rows = session.exec(select(AgentPerformanceRecord)).all()
        groups: Dict[Tuple[str, str, str], List[AgentPerformanceRecord]] = defaultdict(list)
        for row in rows:
            groups[(row.agent, row.model_expert, row.task_type)].append(row)
        items = []
        for (agent, expert, task), vals in groups.items():
            items.append({
                "agent": agent, "model_expert": expert, "task_type": task,
                "count": len(vals),
                "average_score": round(sum(v.quality_score for v in vals) / len(vals), 1),
                "accept_rate": round(sum(v.outcome in {"accepted", "accepted_with_warnings"} for v in vals) / len(vals), 3),
                "confirmed_rate": round(sum(bool(v.confirmed) for v in vals) / len(vals), 3),
                "average_latency_ms": round(sum(v.latency_ms for v in vals) / len(vals), 1),
            })
        items.sort(key=lambda x: (x["average_score"], x["count"]), reverse=True)
        return {"records": len(rows), "experts": items}

    @staticmethod
    def serialize(row: AgentEvaluation) -> Dict[str, Any]:
        data = row.model_dump(mode="json")
        data["findings"] = _json(row.findings_json, [])
        data["recommendations"] = _json(row.recommendations_json, [])
        data["metadata"] = _json(row.metadata_json, {})
        return data


quality_engine = QualityEngine()
