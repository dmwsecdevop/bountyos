"""
Mixture-of-Models / Experts router for BountyOS.

Goal:
- local/light heuristic expert for recon, summaries, command parsing
- main model for high-value bug reasoning after scan data exists
- exploit/validation expert for approved active validation planning

This module chooses the expert; it does not add new target-scope enforcement.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional


@dataclass
class ExpertRoute:
    expert: str
    provider: str
    model: str
    workload: str
    reason: str
    max_tokens: int

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ModelExpertRouter:
    def __init__(self) -> None:
        self.local_model = os.getenv("BOUNTYOS_LOCAL_MODEL", "heuristic-local")
        self.light_model = os.getenv("BOUNTYOS_LIGHT_MODEL", "gemini-2.5-flash-lite")
        self.main_model = os.getenv("BOUNTYOS_MAIN_MODEL", "gemini-2.5-pro")
        self.exploit_model = os.getenv("BOUNTYOS_EXPLOIT_MODEL", self.main_model)
        self.provider = os.getenv("BOUNTYOS_AI_PROVIDER", "vertex")
        self.live_model = os.getenv("BOUNTYOS_LIVE_MODEL", "tool-live-data")

    def route(self, text: str = "", action: str = "", has_scan_context: bool = False) -> ExpertRoute:
        raw = f"{text} {action}".lower()


        if any(k in raw for k in ["self evaluate", "evaluate agents", "quality loop", "critic agent", "verify work", "review agent work", "retry weak", "confidence calibration", "model performance"]):
            return ExpertRoute(
                expert="quality_critic_expert",
                provider="local",
                model=self.light_model,
                workload="evidence_grounded_agent_evaluation",
                reason="Agent-quality request detected; deterministic critic/verifier checks evidence before model commentary.",
                max_tokens=768,
            )

        if any(k in raw for k in ["dollar rate", "usd rate", "exchange rate", "currency rate", "bitcoin price", "btc price", "ethereum price", "eth price", "latest cve", "recent cve", "today cve", "vulnerability news", "public ip", "what is my ip"]):
            return ExpertRoute(
                expert="live_data_expert",
                provider="tool",
                model=self.live_model,
                workload="current_live_data_lookup",
                reason="Current/live-data question detected; route to deterministic API connector instead of guessing.",
                max_tokens=512,
            )

        if any(k in raw for k in ["exploit", "idor", "ssrf", "rce", "sqlmap", "xss", "bypass", "validate", "proof"]):
            return ExpertRoute(
                expert="exploit_validation_expert",
                provider=self.provider,
                model=self.exploit_model,
                workload="approved_active_validation_or_bug_proof",
                reason="Active validation / exploitability language detected; route to strongest expert.",
                max_tokens=2048,
            )

        if has_scan_context and any(k in raw for k in ["finding", "bug", "critical", "high", "chain", "impact", "report", "summary"]):
            return ExpertRoute(
                expert="bug_reasoning_expert",
                provider=self.provider,
                model=self.main_model,
                workload="post_scan_bug_reasoning",
                reason="Scan context exists and user is asking for bug/impact reasoning.",
                max_tokens=2048,
            )

        if any(k in raw for k in ["connected account", "bounty account", "sync accounts", "my programs", "private invite", "private program", "login", "oauth", "api token"]):
            return ExpertRoute(
                expert="bounty_account_hub_expert",
                provider="local",
                model=self.local_model,
                workload="connected_bounty_account_sync",
                reason="Connected bounty-account/private invite request; route to account hub tool connector.",
                max_tokens=768,
            )

        if any(k in raw for k in ["easy program", "easy scope", "less effort", "more money", "make money", "opportunity score", "profitable program"]):
            return ExpertRoute(
                expert="program_opportunity_expert",
                provider="local",
                model=self.local_model,
                workload="program_opportunity_scoring",
                reason="User wants low-effort/high-upside bounty target ranking; route to local opportunity scorer.",
                max_tokens=768,
            )

        if any(k in raw for k in ["program", "bounty", "hackerone", "bugcrowd", "intigriti", "yeswehack", "scope import", "program radar"]):
            return ExpertRoute(
                expert="program_radar_expert",
                provider="local",
                model=self.local_model,
                workload="program_discovery_scope_import",
                reason="Program discovery/scope import is feed parsing and ranking; local expert is enough.",
                max_tokens=512,
            )

        if any(k in raw for k in ["passive", "recon", "subdomain", "wayback", "crt", "show", "list", "status", "cancel"]):
            return ExpertRoute(
                expert="local_recon_expert",
                provider="local",
                model=self.local_model,
                workload="recon_or_dashboard_command",
                reason="Recon/status command can be handled by local/light logic.",
                max_tokens=512,
            )

        return ExpertRoute(
            expert="light_triage_expert",
            provider=self.provider,
            model=self.light_model,
            workload="general_triage_or_chat",
            reason="No heavy exploit/finding reasoning needed; use light model/heuristic path.",
            max_tokens=768,
        )


router = ModelExpertRouter()
