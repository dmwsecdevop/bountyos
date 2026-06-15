"""Controlled retry orchestration for weak agent outputs.

Retries regenerate plans/reports/hypotheses or prepare a new validation attempt.
They never auto-execute active validation.
"""
from __future__ import annotations

from typing import Any, Dict
from sqlmodel import Session, select

from api.models import AgentEvaluation, BountyReport, BugHypothesis, PlannerDecision, ValidationAttempt
from api.intelligence import attack_graph, hypothesis_engine, adaptive_planner
from api.reporting import report_agent
from api.validation import validation_engine
from .engine import quality_engine


class RetryManager:
    max_retries = 2

    def retry(self, session: Session, evaluation_id: str) -> Dict[str, Any]:
        evaluation = session.get(AgentEvaluation, evaluation_id)
        if not evaluation:
            raise ValueError("Evaluation not found")
        if evaluation.status in {"accepted", "accepted_with_warnings"}:
            return {"ok": False, "message": "This result is already accepted and does not require a retry.", "evaluation": quality_engine.serialize(evaluation)}
        if evaluation.retry_count >= self.max_retries:
            return {"ok": False, "message": "Maximum retry count reached. Escalate to the main model or human review.", "requires_escalation": True}
        scan_id = evaluation.scan_id
        task_type = evaluation.task_type
        generated: Any = None
        if task_type == "hypothesis":
            generated = hypothesis_engine.generate(session, scan_id, replace=True)
            attack_graph.build(session, scan_id, reset=False)
            adaptive_planner.plan(session, scan_id, replace=True)
            task = session.get(BugHypothesis, evaluation.task_id)
            if task:
                new_eval = quality_engine.evaluate_hypothesis(session, task, evaluation.id, evaluation.retry_count + 1)
            else:
                latest = session.exec(select(BugHypothesis).where(BugHypothesis.scan_id == scan_id).order_by(BugHypothesis.priority_score.desc())).first()
                new_eval = quality_engine.evaluate_hypothesis(session, latest, evaluation.id, evaluation.retry_count + 1) if latest else None
        elif task_type == "plan":
            generated = adaptive_planner.plan(session, scan_id, replace=True)
            task = session.get(PlannerDecision, evaluation.task_id)
            if task:
                new_eval = quality_engine.evaluate_plan(session, task, evaluation.id, evaluation.retry_count + 1)
            else:
                new_eval = None
        elif task_type == "validation":
            original = session.get(ValidationAttempt, evaluation.task_id)
            if not original or not original.planner_decision_id:
                return {"ok": False, "message": "Validation retry needs a linked planner decision.", "requires_escalation": True}
            generated = validation_engine.create_attempt(session, original.planner_decision_id)
            return {
                "ok": True,
                "message": "A revised validation attempt was prepared. Approval and execution are still required; nothing active ran automatically.",
                "prepared_validation": generated,
                "parent_evaluation_id": evaluation.id,
            }
        elif task_type == "report":
            original = session.get(BountyReport, evaluation.task_id)
            if not original:
                raise ValueError("Original report not found")
            generated = report_agent.generate(session, original.scan_id, original.finding_id, original.validation_attempt_id)
            new_report = session.get(BountyReport, generated["id"])
            new_eval = quality_engine.evaluate_report(session, new_report, evaluation.id, evaluation.retry_count + 1)
        else:
            return {"ok": False, "message": f"Automatic retry is not supported for task type: {task_type}", "requires_escalation": True}
        return {
            "ok": True,
            "message": f"Retry completed for {task_type}.",
            "generated": generated,
            "evaluation": new_eval,
        }


retry_manager = RetryManager()
