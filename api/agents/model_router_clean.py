"""Clean single-pass model router for BountyOS v6.

This module fixes the old duplicate-route behavior and preserves specific
routing for browser, proxy, planning, reporting, recon, parsing, and validation
workloads.
"""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass
from typing import Any, Dict, Optional

FLASH_DEFAULT = "gemini-1.5-flash"
PRO_DEFAULT = "gemini-1.5-pro"


@dataclass
class ExpertRoute:
    expert: str
    provider: str
    model: str
    workload: str
    reason: str
    max_tokens: int
    policy: str
    target_profile: str
    selected_tools: list[str]
    next_actions: list[str]
    requires_approval: bool = False
    approval_reason: str = ""
    fallback_model: str = ""

    def as_dict(self) -> Dict[str, Any]:
        return asdict(self)


class ModelExpertRouter:
    def __init__(self) -> None:
        self.policy = os.getenv("BOUNTYOS_MODEL_POLICY", "performance")
        self.provider = os.getenv("BOUNTYOS_AI_PROVIDER", "gemini")
        self.live_model = os.getenv("BOUNTYOS_LIVE_MODEL", "tool-live-data")
        self.chat_model = os.getenv("BOUNTYOS_CHAT_MODEL", os.getenv("BOUNTYOS_LIGHT_MODEL", "gemini-1.5-flash-8b"))
        self.planner_model = os.getenv("BOUNTYOS_PLANNER_MODEL", FLASH_DEFAULT)
        self.recon_model = os.getenv("BOUNTYOS_RECON_MODEL", FLASH_DEFAULT)
        self.parser_model = os.getenv("BOUNTYOS_PARSER_MODEL", FLASH_DEFAULT)
        self.agentic_model = os.getenv("BOUNTYOS_AGENTIC_MODEL", "gemini-1.5-flash")
        self.browser_model = os.getenv("BOUNTYOS_BROWSER_MODEL", "gemini-1.5-flash")
        self.caido_model = os.getenv("BOUNTYOS_CAIDO_MODEL", "gemini-1.5-flash")
        self.validation_model = os.getenv("BOUNTYOS_VALIDATION_MODEL", os.getenv("BOUNTYOS_MAIN_MODEL", PRO_DEFAULT))
        self.report_model = os.getenv("BOUNTYOS_REPORT_MODEL", os.getenv("BOUNTYOS_MAIN_MODEL", PRO_DEFAULT))
        self.bug_fallback_model = os.getenv("BOUNTYOS_BUG_FALLBACK_MODEL", "gemini-1.5-flash")

    def _route(
        self,
        *,
        expert: str,
        model: str,
        workload: str,
        reason: str,
        target_profile: str,
        selected_tools: list[str],
        next_actions: list[str],
        max_tokens: int = 2048,
        provider: Optional[str] = None,
        requires_approval: bool = False,
        approval_reason: str = "",
        fallback_model: str = "",
    ) -> ExpertRoute:
        return ExpertRoute(
            expert=expert,
            provider=provider or self.provider,
            model=model,
            workload=workload,
            reason=reason,
            max_tokens=max_tokens,
            policy=self.policy,
            target_profile=target_profile,
            selected_tools=selected_tools,
            next_actions=next_actions,
            requires_approval=requires_approval,
            approval_reason=approval_reason,
            fallback_model=fallback_model,
        )

    @staticmethod
    def _target_text(text: str, target_context: Optional[dict[str, Any]]) -> str:
        target = target_context or {}
        chunks = [text]
        for key in ("domain", "name", "scope", "out_of_scope", "notes", "technology", "program"):
            value = target.get(key)
            if value:
                chunks.append(str(value))
        return " ".join(chunks).lower()

    def classify_target(self, text: str = "", target_context: Optional[dict[str, Any]] = None) -> tuple[str, list[str], list[str]]:
        raw = self._target_text(text, target_context)
        if any(k in raw for k in ["graphql", "gql", "/graphql", "apollo"]):
            return (
                "graphql",
                ["graphql endpoint discovery", "introspection check", "authorization review", "katana", "httpx"],
                ["Discover GraphQL endpoints", "Check introspection safely", "Map role boundaries"],
            )
        if any(k in raw for k in ["swagger", "openapi", "api.", "/api/", "rest api", "postman", "jwt", "bearer"]):
            return (
                "api",
                ["katana", "httpx", "arjun", "api templates", "jwt checks", "swagger/openapi discovery"],
                ["Discover API docs", "Probe parameters", "Review auth handling", "Run safe API checks"],
            )
        if any(k in raw for k in ["s3", "bucket", "gcs", "blob.core", "cloudfront", "metadata", "aws", "azure", "gcp"]):
            return (
                "cloud",
                ["storage exposure checks", "secret indicators", "metadata review", "httpx", "cloud templates"],
                ["Check exposed storage", "Look for metadata leaks", "Review public secret indicators"],
            )
        if any(k in raw for k in ["wordpress", "wp-content", "wp-json", "drupal", "joomla", "cms"]):
            return (
                "cms",
                ["whatweb", "httpx", "cms templates"],
                ["Fingerprint CMS", "Run CMS-specific safe checks", "Check exposed admin surfaces"],
            )
        if any(k in raw for k in ["login", "account", "dashboard", "tenant", "workspace", "organization", "invite", "role", "saas"]):
            return (
                "saas_web_app",
                ["katana", "httpx", "JS endpoint extraction", "auth flow mapping", "access-control ranking"],
                ["Map auth flows", "Extract JS endpoints", "Rank access-control candidates", "Identify role boundaries"],
            )
        return (
            "generic_domain",
            ["subfinder", "dnsx", "httpx", "katana", "whatweb", "safe templates"],
            ["Passive recon", "Resolve live hosts", "Detect technologies", "Rank next safe checks"],
        )

    def route(
        self,
        text: str = "",
        action: str = "",
        has_scan_context: bool = False,
        target_context: Optional[dict[str, Any]] = None,
    ) -> ExpertRoute:
        raw = f"{text} {action}".lower()
        profile, profile_tools, profile_actions = self.classify_target(raw, target_context)

        if any(k in raw for k in ["analyze browser", "use browser", "browser mcp", "current page", "devtools", "chrome devtools"]):
            return self._route(
                expert="browser_reasoning_expert",
                model=self.browser_model,
                workload="browser_reasoning",
                reason="Browser evidence task detected; use Gemini 3.5 Flash for fast browser reasoning.",
                target_profile=profile,
                selected_tools=["Chrome DevTools MCP", "console logs", "network capture", "JS endpoint extraction", *profile_tools],
                next_actions=["Collect current in-scope page", "Import browser evidence", "Extract JS endpoints", "Detect auth/session flows"],
                max_tokens=2048,
            )

        if any(k in raw for k in ["check caido", "caido traffic", "use caido", "proxy traffic", "analyze request", "http history"]):
            return self._route(
                expert="caido_analysis_expert",
                model=self.caido_model,
                workload="caido_analysis",
                reason="Proxy traffic analysis detected; use Gemini 3.5 Flash for fast traffic triage.",
                target_profile=profile,
                selected_tools=["Caido HTTP history", "request/response review", "evidence store", *profile_tools],
                next_actions=["Import in-scope proxy history", "Analyze selected requests", "Flag auth/API/session risks"],
                max_tokens=2048,
            )

        if any(k in raw for k in ["agentic", "autonomous", "plan workflow", "operate"]):
            return self._route(
                expert="agentic_planning_expert",
                model=self.agentic_model,
                workload="agentic_planning",
                reason="Agentic workflow planning detected; use Gemini 3.5 Flash.",
                target_profile=profile,
                selected_tools=profile_tools,
                next_actions=["Create bounded job", "Select safe tools", "Store evidence", "Ask approval before active validation"],
                max_tokens=2048,
            )

        if any(k in raw for k in ["dollar rate", "usd rate", "exchange rate", "bitcoin price", "btc price", "latest cve", "recent cve", "today cve", "vulnerability news", "public ip", "what is my ip"]):
            return self._route(
                expert="live_data_expert",
                provider="tool",
                model=self.live_model,
                workload="current_live_data_lookup",
                reason="Current data lookup; use deterministic connector instead of model guessing.",
                target_profile=profile,
                selected_tools=["live-data connector"],
                next_actions=["Fetch current data", "Return concise sourced answer"],
                max_tokens=512,
            )

        if any(k in raw for k in ["report", "writeup", "write report", "bounty report"]):
            return self._route(
                expert="report_writer_expert",
                model=self.report_model,
                workload="report_writing",
                reason="Report writing needs strong model for clarity, impact, and reproduction detail.",
                target_profile=profile,
                selected_tools=profile_tools,
                next_actions=["Summarize evidence", "Write reproduction steps", "Validate impact and remediation"],
                max_tokens=4096,
            )

        if action == "start_passive_scan" or any(k in raw for k in ["passive", "passive recon", "subdomain", "wayback", "crt", "plan", "tools", "select tool", "classify target"]):
            return self._route(
                expert="recon_planner_expert",
                model=self.recon_model,
                workload="passive_recon_planning_and_tool_selection",
                reason="Recon planning, target classification, and tool selection use Flash-class model for speed.",
                target_profile=profile,
                selected_tools=profile_tools,
                next_actions=profile_actions,
                max_tokens=1536,
            )

        if any(k in raw for k in ["validate", "proof", "poc", "critical", "high", "severity", "auth bypass", "idor", "ssrf", "jwt", "graphql authorization"]):
            return self._route(
                expert="validation_reasoning_expert",
                model=self.validation_model,
                workload="evidence_driven_validation_reasoning",
                reason="High-impact validation keywords detected; use strong reasoning model.",
                target_profile=profile,
                selected_tools=profile_tools + ["least-intrusive validation checklist", "evidence store"],
                next_actions=["Review existing evidence", "Choose least-intrusive verification", "Request approval before active validation"],
                max_tokens=4096,
                requires_approval=any(k in raw for k in ["validate", "proof", "poc", "active"]),
                approval_reason="Active validation may affect the target; explicit approval is required before execution.",
                fallback_model=self.bug_fallback_model,
            )

        if any(k in raw for k in ["parse", "extract", "tool output", "stdout", "json", "findings"]):
            return self._route(
                expert="parser_expert",
                model=self.parser_model,
                workload="tool_output_parsing",
                reason="Parsing workload; use fastest Flash-class model.",
                target_profile=profile,
                selected_tools=profile_tools,
                next_actions=["Parse tool output", "Extract evidence", "Create concise finding candidates"],
                max_tokens=2048,
            )

        if any(k in raw for k in ["summary", "summarize", "scan summary", "status"]):
            return self._route(
                expert="scan_summary_expert",
                model=self.recon_model,
                workload="scan_summary",
                reason="Scan summaries should be fast and operational; use Flash-class recon model.",
                target_profile=profile,
                selected_tools=profile_tools,
                next_actions=["Summarize status", "List blockers", "Rank next safe steps"],
                max_tokens=1536,
            )

        if any(k in raw for k in ["aggressive", "active scan", "active recon", "nuclei", "sqlmap", "ffuf"]):
            return self._route(
                expert="active_recon_planner",
                model=self.planner_model,
                workload="active_recon_planning",
                reason="Active planning uses Flash for speed but requires approval before execution.",
                target_profile=profile,
                selected_tools=profile_tools,
                next_actions=["Plan active checks", "Use least-intrusive probes first", "Request approval before execution"],
                max_tokens=1536,
                requires_approval=True,
                approval_reason="Active recon can send intrusive traffic and must be explicitly approved.",
            )

        if has_scan_context and any(k in raw for k in ["bug", "impact", "finding", "chain"]):
            return self._route(
                expert="bug_reasoning_expert",
                model=self.validation_model,
                workload="post_scan_bug_reasoning",
                reason="Scan context plus bug-impact question; use strongest validation model.",
                target_profile=profile,
                selected_tools=profile_tools + ["evidence review", "confidence scoring"],
                next_actions=["Review evidence", "Reduce false positives", "Rank impact"],
                max_tokens=4096,
                fallback_model=self.bug_fallback_model,
            )

        return self._route(
            expert="chat_triage_expert",
            model=self.chat_model,
            workload="chat_and_triage",
            reason="General chat/triage uses fastest Flash-class model under performance policy.",
            target_profile=profile,
            selected_tools=profile_tools,
            next_actions=profile_actions,
            max_tokens=1536,
        )


router = ModelExpertRouter()
