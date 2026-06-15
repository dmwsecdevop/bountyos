"""Deterministic validation policy for the Hunter workflow.

The policy is intentionally separate from model output.  Models may propose an
action, but this module decides whether it is safe, requires approval, or is
blocked.
"""
from __future__ import annotations

from dataclasses import dataclass, asdict
from typing import Dict

SAFE_ACTIONS = {
    "public_artifact_evidence_review",
    "graphql_schema_authorization_review",
    "dangling_dns_provider_verification",
    "cors_policy_evidence_review",
    "version_advisory_correlation",
    "evidence_review",
}
APPROVAL_ACTIONS = {
    "controlled_object_authorization_review",
    "authentication_state_machine_review",
    "controlled_callback_validation_plan",
    "inert_upload_control_review",
    "client_rendering_dataflow_review",
    "business_state_transition_review",
}
BLOCKED_TERMS = {
    "credential theft", "dump database", "webshell", "persistence", "malware",
    "destructive", "mass exploit", "delete data", "steal data", "bypass mfa",
}

@dataclass
class PolicyDecision:
    level: str  # safe | approval_required | blocked
    action: str
    reason: str
    request_budget: int
    stop_condition: str

    def as_dict(self) -> Dict:
        return asdict(self)


def evaluate(action_name: str, description: str = "") -> PolicyDecision:
    low = f"{action_name} {description}".lower()
    if any(term in low for term in BLOCKED_TERMS):
        return PolicyDecision(
            "blocked", action_name,
            "The requested operation is destructive, persistence-oriented, or exceeds minimal proof requirements.",
            0, "Do not execute.",
        )
    if action_name in APPROVAL_ACTIONS:
        return PolicyDecision(
            "approval_required", action_name,
            "This is an active validation step and requires explicit approval before any request is sent.",
            6, "Stop after the first minimal confirmation or when the request budget is reached.",
        )
    return PolicyDecision(
        "safe", action_name,
        "This action reviews existing/public evidence and can run without active exploitation.",
        0, "Stop when evidence is classified as likely, inconclusive, or false positive.",
    )
