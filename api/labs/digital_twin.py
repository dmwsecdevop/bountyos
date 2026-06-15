"""Synthetic digital-twin scenarios for safe Hunter workflow testing."""
from __future__ import annotations

from typing import Any, Dict, List

SCENARIOS: Dict[str, Dict[str, Any]] = {
    "saas_api": {
        "name": "SaaS API authorization lab",
        "description": "Synthetic user, team, invite, billing and object-ownership signals.",
        "signals": ["/api/users/{id}", "/api/orders/{order_id}", "invite", "billing", "numeric id", "role"],
        "expected_hypotheses": ["idor", "business_logic", "auth_flow"],
    },
    "exposure": {
        "name": "Configuration exposure lab",
        "description": "Synthetic archived URLs, source maps, backup files and secret-like strings.",
        "signals": ["/.env", "/app.js.map", "/backup.zip", "api key", "debug.log"],
        "expected_hypotheses": ["secret_exposure", "known_vulnerability"],
    },
    "agentic_support": {
        "name": "Agentic support authorization lab",
        "description": "Synthetic account recovery agent with excessive agency and missing deterministic authorization.",
        "signals": ["forgot password", "recovery email", "mfa", "support agent", "account modification", "session"],
        "expected_hypotheses": ["auth_flow", "business_logic"],
    },
}


def list_scenarios() -> List[Dict[str, Any]]:
    return [{"id": key, **value} for key, value in SCENARIOS.items()]


def get_scenario(scenario_id: str) -> Dict[str, Any]:
    if scenario_id not in SCENARIOS:
        raise ValueError("Unknown digital-twin scenario")
    return {"id": scenario_id, **SCENARIOS[scenario_id]}
