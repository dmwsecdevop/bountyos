"""Performance-first Smart Model Router for BountyOS v6.

The router optimizes for high-impact bug discovery while preserving BountyOS'
safety model: active/intrusive validation requires explicit approval and exploit
reasoning must be evidence-driven.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, asdict
from typing import Any, Dict, Optional


FLASH_DEFAULT = "gemini-2.5-flash"
PRO_DEFAULT = "gemini-2.5-pro"


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
        self.chat_model = os.getenv("BOUNTYOS_CHAT_MODEL", os.getenv("BOUNTYOS_LIGHT_MODEL", "gemini-2.5-flash-lite"))
        self.planner_model = os.getenv("BOUNTYOS_PLANNER_MODEL", FLASH_DEFAULT)
        self.recon_model = os.getenv("BOUNTYOS_RECON_MODEL", FLASH_DEFAULT)
        self.parser_model = os.getenv("BOUNTYOS_PARSER_MODEL", FLASH_DEFAULT)
        self.agentic_model = os.getenv("BOUNTYOS_AGENTIC_MODEL", "gemini-3.5-flash")
        self.browser_model = os.getenv("BOUNTYOS_BROWSER_MODEL", "gemini-3.5-flash")
        self.caido_model = os.getenv("BOUNTYOS_CAIDO_MODEL", "gemini-3.5-flash")
        self.exploit_model = os.getenv("BOUNTYOS_EXPLOIT_MODEL", PRO_DEFAULT)
        self.validation_model = os.getenv("BOUNTYOS_VALIDATION_MODEL", self.exploit_model)
        self.report_model = os.getenv("BOUNTYOS_REPORT_MODEL", os.getenv("BOUNTYOS_MAIN_MODEL", PRO_DEFAULT))
        self.bug_fallback_model = os.getenv("BOUNTYOS_BUG_FALLBACK_MODEL", "gemini-3.5-flash")

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
                ["graphql endpoint discovery", "introspection check", "auth/role checks", "katana", "httpx"],
                ["Discover GraphQL endpoints", "Check introspection safely", "Map roles and authorization boundaries"],
            )
        if any(k in raw for k in ["swagger", "openapi", "api.", "/api/", "rest api", "postman", "jwt", "bearer"]):
            return (
                "api",
                ["katana", "httpx", "arjun", "nuclei api templates", "jwt checks", "swagger/openapi discovery"],
                ["Discover API docs and OpenAPI specs", "Probe parameters with arjun", "Check JWT/auth handling", "Run API nuclei templates"],
            )
        if any(k in raw for k in ["s3", "bucket", "gcs", "blob.core", "cloudfront", "metadata", "aws", "azure", "gcp"]):
            return (
                "cloud",
                ["bucket exposure checks", "secrets checks", "metadata leak checks", "httpx", "nuclei cloud templates"],
                ["Check exposed storage", "Look for metadata leaks", "Review public secrets indicators"],
            )
        if any(k in raw for k in ["wordpress", "wp-content", "wp-json", "drupal", "joomla", "cms"]):
            return (
                "wordpress_cms",
                ["whatweb", "httpx", "nuclei cms templates", "wpscan-compatible checks"],
                ["Fingerprint CMS version/plugins", "Run CMS-specific nuclei templates", "Check exposed admin surfaces"],
            )
        if any(k in raw for k in ["login", "account", "dashboard", "tenant", "workspace", "organization", "invite", "role", "saas"]):
            return (
                "saas_web_app",
                ["katana", "httpx", "JS endpoint extraction", "auth flow mapping", "IDOR candidate ranking"],
                ["Map auth flows", "Extract JS endpoints", "Rank IDOR candidates", "Identify role boundaries"],
            )
        return (
            "generic_domain",
            ["subfinder", "dnsx", "httpx", "katana", "whatweb", "nuclei safe templates"],
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

        if any(k in raw for k in ["analyze browser", "use browser", "browser mcp", "current page", "devtools"]):
            return self._route(
                expert="browser_reasoning_expert",
                model=self.browser_model,
                workload="browser_reasoning",
                reason="Browser/Chrome DevTools MCP task detected; use Gemini 3.5 Flash for agentic browser reasoning.",
                target_profile=profile,
                selected_tools=["Chrome DevTools MCP", "console logs", "network capture", "JS endpoint extraction", *profile_tools],
                next_actions=["Collect current in-scope page", "Import console/network evidence", "Extract JS endpoints", "Detect auth/session flows"],
                max_tokens=2048,
            )

        if any(k in raw for k in ["check caido", "caido traffic", "use caido", "proxy traffic", "analyze request"]):
            return self._route(
                expert="caido_analysis_expert",
                model=self.caido_model,
                workload="caido_analysis",
                reason="Caido proxy traffic analysis detected; use Gemini 3.5 Flash for fast traffic triage.",
                target_profile=profile,
                selected_tools=["Caido HTTP history", "request/response analysis", "evidence store", *profile_tools],
                next_actions=["Import in-scope proxy history", "Analyze selected requests", "Flag IDOR/auth/SSRF/GraphQL/JWT/CORS/secret risks"],
                max_tokens=2048,
            )
        return (
            "generic_domain",
            ["subfinder", "dnsx", "httpx", "katana", "whatweb", "nuclei safe templates"],
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

        if any(k in raw for k in ["agentic", "autonomous", "plan workflow", "operate", "browser", "caido"]):
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

        if any(k in raw for k in ["dollar rate", "usd rate", "exchange rate", "bitcoin price", "btc price", "ethereum price", "eth price", "latest cve", "recent cve", "today cve", "vulnerability news", "public ip", "what is my ip"]):
            return self._route(
                expert="live_data_expert",
                provider="tool",
                model=self.live_model,
                workload="current_live_data_lookup",
                reason="Current/live-data lookup; use deterministic connector instead of model guessing.",
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
                reason="Report writing needs strongest model for clarity, impact, and reproduction detail.",
                target_profile=profile,
                selected_tools=profile_tools,
                next_actions=["Summarize evidence", "Write reproduction steps", "Validate impact and remediation"],
                max_tokens=4096,
            )

        exploit_terms = any(k in raw for k in ["exploit", "idor", "ssrf", "sqli", "sql injection", "graphql authorization", "jwt", "auth bypass", "rce", "bypass", "validate", "proof", "poc", "critical", "high", "false positive", "severity"])
        planning_only = any(k in raw for k in ["passive", "recon", "classify", "plan"]) and not any(k in raw for k in ["validate", "proof", "poc", "exploit"])
        if exploit_terms and not planning_only:
            return self._route(
                expert="exploit_validation_expert",
                model=self.exploit_model if "false positive" not in raw and "severity" not in raw else self.validation_model,
                workload="evidence_driven_bug_reasoning",
                reason="High-impact exploitability or validation keywords detected; route to strongest reasoning model.",
                target_profile=profile,
                selected_tools=profile_tools + ["least-intrusive validation checklist", "evidence store"],
                next_actions=["Review existing evidence", "Choose least-intrusive verification", "Request approval before active validation"],
                max_tokens=4096,
                requires_approval=any(k in raw for k in ["exploit", "validate", "proof", "poc", "sqlmap", "active"]),
                approval_reason="Active or intrusive validation may affect the target; explicit approval is required before execution.",
                fallback_model=self.bug_fallback_model,
            )

        if any(k in raw for k in ["parse", "extract", "tool output", "stdout", "json", "findings"]):
            return self._route(
                expert="parser_expert",
                model=self.parser_model,
                workload="tool_output_parsing",
                reason="Parsing/classification workload; use fastest Flash-class model.",
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

        if any(k in raw for k in ["passive", "recon", "subdomain", "wayback", "crt", "plan", "tools", "select tool", "classify target"]):
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
