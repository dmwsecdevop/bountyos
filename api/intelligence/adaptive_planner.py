"""Adaptive next-action planner using hypotheses and historical utility."""
from __future__ import annotations

import json
from typing import Any, Dict, List
from sqlmodel import Session, select

from api.models import BugHypothesis, PlannerDecision
from api.learning.experience_store import experience_store
from api.intelligence.memory import shared_memory

ACTION_MAP: Dict[str, Dict[str, Any]] = {
    "idor": {"name":"controlled_object_authorization_review", "effort":"medium", "noise":"low", "approval":True},
    "auth_flow": {"name":"authentication_state_machine_review", "effort":"high", "noise":"low", "approval":True},
    "secret_exposure": {"name":"public_artifact_evidence_review", "effort":"low", "noise":"passive", "approval":False},
    "ssrf": {"name":"controlled_callback_validation_plan", "effort":"medium", "noise":"low", "approval":True},
    "file_upload": {"name":"inert_upload_control_review", "effort":"medium", "noise":"low", "approval":True},
    "graphql": {"name":"graphql_schema_authorization_review", "effort":"medium", "noise":"low", "approval":False},
    "subdomain_takeover": {"name":"dangling_dns_provider_verification", "effort":"low", "noise":"passive", "approval":False},
    "xss": {"name":"client_rendering_dataflow_review", "effort":"medium", "noise":"low", "approval":True},
    "cors": {"name":"cors_policy_evidence_review", "effort":"low", "noise":"low", "approval":False},
    "business_logic": {"name":"business_state_transition_review", "effort":"high", "noise":"low", "approval":True},
    "known_vulnerability": {"name":"version_advisory_correlation", "effort":"low", "noise":"passive", "approval":False},
}
EFFORT_FACTOR = {"low": 1.0, "medium": 0.82, "high": 0.64}


class AdaptivePlanner:
    def plan(self, session: Session, scan_id: str, replace: bool = False) -> List[Dict[str, Any]]:
        hypotheses = session.exec(
            select(BugHypothesis).where(BugHypothesis.scan_id == scan_id)
            .order_by(BugHypothesis.priority_score.desc())
        ).all()
        existing = {
            p.hypothesis_id: p for p in session.exec(select(PlannerDecision).where(PlannerDecision.scan_id == scan_id)).all()
            if p.hypothesis_id
        }
        decisions: List[PlannerDecision] = []
        for h in hypotheses:
            cfg = ACTION_MAP.get(h.bug_class, {"name":"evidence_review", "effort":"medium", "noise":"low", "approval":h.approval_required})
            prior = experience_store.action_prior(session, cfg["name"])
            learning_boost = max(-0.15, min(0.15, prior["average_utility"] / 100.0))
            expected = max(0.01, min(0.99, (h.priority_score / 100.0) * EFFORT_FACTOR[cfg["effort"]] + learning_boost))
            rationale = (
                f"Prioritize {cfg['name'].replace('_',' ')} because {h.title.lower()} has "
                f"{h.confidence:.0%} confidence and priority {h.priority_score:.1f}. "
                f"Historical action utility: {prior['average_utility']:.2f} across {prior['count']} run(s)."
            )
            row = existing.get(h.id)
            if row and not replace:
                row.expected_value = round(expected, 3)
                row.rationale = rationale
                row.approval_required = bool(cfg["approval"])
                row.effort = cfg["effort"]
                row.noise = cfg["noise"]
            else:
                row = PlannerDecision(
                    scan_id=scan_id, hypothesis_id=h.id, action_type="validation",
                    action_name=cfg["name"], target=h.target,
                    expected_value=round(expected, 3), effort=cfg["effort"], noise=cfg["noise"],
                    approval_required=bool(cfg["approval"]), rationale=rationale, status="queued",
                )
            h.status = "planned"
            session.add(h); session.add(row); session.flush(); decisions.append(row)
        session.commit()
        decisions.sort(key=lambda p: p.expected_value, reverse=True)
        ids = [d.id for d in decisions]
        shared_memory.add(session, "adaptive_planner", "plan",
                          f"Ranked {len(decisions)} next actions by expected value, effort and prior utility.",
                          scan_id, {"decision_ids": ids}, .87)
        refreshed = [session.get(PlannerDecision, did) for did in ids]
        refreshed = [x for x in refreshed if x]
        refreshed.sort(key=lambda p: p.expected_value, reverse=True)
        return [self.serialize(d) for d in refreshed]

    @staticmethod
    def serialize(d: PlannerDecision) -> Dict[str, Any]:
        return d.model_dump(mode="json")


adaptive_planner = AdaptivePlanner()
