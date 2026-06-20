"""ArchitectAgent wrapper that forces the clean single-pass model router.

This avoids the legacy duplicate-route implementation while keeping the existing
ArchitectAgent behavior unchanged.
"""

from api.agents import architect_agent as legacy_architect_agent
from api.agents.model_router_clean import router as clean_model_router

legacy_architect_agent.model_router = clean_model_router

ArchitectAgent = legacy_architect_agent.ArchitectAgent
ArchitectDecision = legacy_architect_agent.ArchitectDecision

__all__ = ["ArchitectAgent", "ArchitectDecision"]
