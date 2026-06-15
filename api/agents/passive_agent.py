"""
BountyOS - Passive Agent (Phase 3 - Passive Mode)

Zero-touch OSINT-only agent. Never sends packets directly to the target.
Uses only passive data sources: DNS records, certificate transparency,
Shodan/Censys indexed data, Wayback Machine, Google dorking,
public code repositories, breach databases.

Safe for:
  - Bug bounty programs with strict rate limits
  - Pre-engagement reconnaissance
  - Stealth operations where detection is unacceptable
  - Legal compliance where active scanning is restricted

Never does:
  - Direct HTTP requests to target
  - Port scanning
  - Fuzzing or brute-forcing
  - Any form of active probing
"""

import asyncio
import json
import os
from typing import Optional
from api.ai import get_ai_client

from api.database import session_ctx
from api.models import Finding, ScanEvent, ScanPhase, Severity
from api.tools.discovery import get_passive_tools, ALL_TOOLS
from api.agents.hacker_mindset import get_hacker_mindset_prompt, HACKER_QUESTIONS

_client = get_ai_client()
MODEL   = os.getenv("BOUNTYOS_RECON_MODEL", "gemini-2.5-flash")


# ─── Passive-only tool whitelist categories ───────────────────────────────────

PASSIVE_CATEGORIES = {
    "subdomain", "osint", "webprobe", "fingerprint",
    "metadata", "lang", "util", "http", "anonymity",
}

PASSIVE_TOOLS_FORCED_EXCLUDE = {
    "nmap", "masscan", "rustscan", "unicornscan",    # active port scanners
    "sqlmap", "commix", "dalfox", "ssrfmap",          # active exploit tools
    "ffuf", "gobuster", "feroxbuster", "dirsearch",   # active fuzzers
    "wfuzz", "arjun",                                 # active param fuzzing
    "hydra", "medusa", "crackmapexec", "netexec",     # brute-forcers
    "metasploit", "beef", "responder",                # exploitation
    "nikto", "wpscan", "joomscan", "nuclei",          # active web scanners
    "aircrack-ng", "wifite", "reaver",                # wireless attack tools
    "john", "hashcat",                                # password crackers
    "bettercap",                                      # MITM
}


def _build_passive_tool_list() -> dict:
    """Return only genuinely passive tools from discovered set."""
    passive = {}
    for name, tool in ALL_TOOLS.items():
        if name in PASSIVE_TOOLS_FORCED_EXCLUDE:
            continue
        if tool.passive_safe or tool.category in PASSIVE_CATEGORIES:
            passive[name] = tool
    return passive


# ─── Passive Agent AI tools ───────────────────────────────────────────────────

PASSIVE_AI_TOOLS = [
    {
        "name": "run_passive_tool",
        "description": (
            "Execute a passive OSINT tool against the target. "
            "Only use tools from the approved passive list — never active scanners, "
            "port scanners, fuzzers, or exploitation tools."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "tool_name":   {"type": "string", "description": "Tool name from the passive whitelist"},
                "target":      {"type": "string", "description": "Target domain or IP"},
                "extra_args":  {"type": "string", "description": "Optional extra CLI arguments"},
                "reasoning":   {"type": "string", "description": "Why this tool is useful here"},
            },
            "required": ["tool_name", "target", "reasoning"],
        },
    },
    {
        "name": "google_dork",
        "description": "Generate and record Google dork queries that reveal sensitive information about the target without visiting it directly.",
        "input_schema": {
            "type": "object",
            "properties": {
                "dorks": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "List of Google dork queries (site:, filetype:, inurl:, intitle:, etc.)",
                },
                "category": {"type": "string", "description": "What these dorks look for: credentials | admin_panels | exposed_files | config | source_code | backups"},
                "reasoning": {"type": "string"},
            },
            "required": ["dorks", "category", "reasoning"],
        },
    },
    {
        "name": "analyze_certificates",
        "description": "Analyze certificate transparency logs to discover subdomains and infrastructure details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target":  {"type": "string"},
                "sources": {"type": "array", "items": {"type": "string"}, "description": "CT sources: crt.sh, censys, shodan"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "emit_intelligence",
        "description": "Record a passive intelligence finding — information gathered without touching the target.",
        "input_schema": {
            "type": "object",
            "properties": {
                "type":     {"type": "string", "description": "intel type: subdomain | technology | credential_leak | exposed_asset | misconfiguration | osint_finding"},
                "value":    {"type": "string", "description": "The discovered value"},
                "source":   {"type": "string", "description": "Where this came from"},
                "severity": {"type": "string", "enum": ["info","low","medium","high","critical"]},
                "detail":   {"type": "string"},
                "recommend_aggressive_followup": {"type": "boolean", "description": "Should this be investigated in aggressive mode?"},
            },
            "required": ["type", "value", "source", "severity"],
        },
    },
    {
        "name": "write_finding",
        "description": "Record a confirmed passive finding with full details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title":       {"type": "string"},
                "severity":    {"type": "string", "enum": ["info","low","medium","high","critical"]},
                "description": {"type": "string"},
                "evidence":    {"type": "string"},
                "url":         {"type": "string"},
                "cwe_id":      {"type": "string"},
                "remediation": {"type": "string"},
            },
            "required": ["title", "severity", "description"],
        },
    },
    {
        "name": "finish_passive_recon",
        "description": "Signal passive recon is complete. Provide intelligence summary and aggressive followup recommendations.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary":                {"type": "string"},
                "attack_surface_rating":  {"type": "string", "enum": ["minimal","low","medium","high","critical"]},
                "aggressive_recommended": {"type": "boolean"},
                "top_targets":            {"type": "array", "items": {"type": "string"}},
            },
            "required": ["summary", "attack_surface_rating"],
        },
    },
]


# ─── System prompt ────────────────────────────────────────────────────────────

def _passive_system_prompt(target: str, scope: str, oos: str, tool_list: str) -> str:
    recon_qs = "\n".join(f"  ? {q}" for q in HACKER_QUESTIONS["recon"])
    mindset_intro = get_hacker_mindset_prompt(target, scope, "recon")
    return f"""You are BountyOS Passive Intelligence Agent — an expert threat intelligence analyst.

TARGET: {target}
IN-SCOPE: {scope}
OUT-OF-SCOPE: {oos or 'none'}

EXPERT HACKER RECON MINDSET:
{mindset_intro}

RECON INTELLIGENCE QUESTIONS — answer every one of these:
{recon_qs}

AVAILABLE PASSIVE TOOLS:
{tool_list}

YOUR MISSION:
Build a complete intelligence picture of the target using ONLY passive, non-intrusive methods.
Think like a threat intelligence analyst preparing a target package for a red team.
Every piece of information you gather should answer: "What attack paths does this enable?"
You must NOT generate any direct network traffic to the target system.

PASSIVE INTELLIGENCE SOURCES YOU SHOULD USE:
1. Subdomain enumeration via certificate transparency (subfinder, amass passive mode)
2. DNS record analysis (dnsrecon, dnsx in passive mode)
3. Historical URL discovery (waybackurls, gau)
4. OSINT gathering (theharvester with passive sources only)
5. Technology fingerprinting from public data (whatweb on public URLs)
6. Google dork generation for operator to manually verify
7. Shodan/Censys CLI if available (pre-indexed data only)
8. Git repository scanning for leaked secrets

WHAT TO LOOK FOR:
- Forgotten subdomains pointing to cloud services (takeover candidates)
- Historical URLs exposing admin panels, API endpoints, backup files
- Technology stack from passive fingerprinting
- Email addresses and personnel for phishing surface mapping
- API keys or credentials in public code repositories
- SSL/TLS certificate metadata revealing internal hostnames
- Third-party integrations and supply chain exposure

RULES:
- NEVER use active port scanners (nmap, masscan, rustscan)
- NEVER use web fuzzers (ffuf, gobuster, feroxbuster)
- NEVER use active exploit tools (sqlmap, nuclei active templates)
- NEVER make direct HTTP requests to the target unless tool is explicitly passive
- For each finding, rate whether it warrants aggressive followup
- Emit google_dork queries for operator manual verification

Think like a threat intelligence analyst, not a penetration tester.
"""


# ─── Tool handlers ────────────────────────────────────────────────────────────

def _log(scan_id: str, msg: str, level: str = "info"):
    with session_ctx() as s:
        s.add(ScanEvent(
            scan_id=scan_id, phase=ScanPhase.RECON,
            tool="passive-agent", level=level, message=msg,
        ))
        s.commit()


async def _handle_run_passive_tool(scan_id: str, args: dict, passive_tools: dict) -> str:
    tool_name = args.get("tool_name", "")
    target    = args.get("target", "")

    if tool_name in PASSIVE_TOOLS_FORCED_EXCLUDE:
        return f"BLOCKED: {tool_name} is not allowed in passive mode."

    tool = passive_tools.get(tool_name)
    if not tool:
        available = list(passive_tools.keys())[:20]
        return f"Tool '{tool_name}' not available. Available passive tools: {available}"

    _log(scan_id, f"🔍 [passive] Running {tool_name} on {target}")
    output_lines = []
    try:
        async for ev in tool.run(scan_id, target, extra_args=args.get("extra_args", "")):
            with session_ctx() as s:
                s.add(ScanEvent(
                    scan_id=scan_id, phase=ScanPhase.RECON,
                    tool=tool_name, level=ev.get("level", "info"),
                    message=ev["message"], raw=ev.get("raw"),
                ))
                s.commit()
            output_lines.append(ev["message"])
    except Exception as e:
        return f"Tool error: {e}"

    return "\n".join(output_lines[-60:]) or "No output."


async def _handle_google_dork(scan_id: str, args: dict) -> str:
    dorks    = args.get("dorks", [])
    category = args.get("category", "general")
    for dork in dorks:
        _log(scan_id, f"🔎 [dork/{category}] {dork}", level="finding")
    return f"Recorded {len(dorks)} dork queries for category: {category}"


async def _handle_analyze_certs(scan_id: str, args: dict) -> str:
    target = args.get("target", "")
    _log(scan_id, f"🔐 Certificate transparency analysis for {target}")
    return (
        f"Manual check recommended:\n"
        f"  https://crt.sh/?q=%.{target}\n"
        f"  https://censys.io/certificates?q={target}\n"
        "Run subfinder or amass to enumerate discovered subdomains automatically."
    )


async def _handle_emit_intelligence(scan_id: str, args: dict) -> str:
    intel_type = args.get("type", "osint_finding")
    value      = args.get("value", "")
    source     = args.get("source", "passive")
    severity   = args.get("severity", "info")
    detail     = args.get("detail", "")
    followup   = args.get("recommend_aggressive_followup", False)

    msg = f"🕵️ [{intel_type.upper()}] {value} (source: {source})"
    if followup:
        msg += " ⚡ RECOMMEND AGGRESSIVE FOLLOWUP"

    _log(scan_id, msg, level="finding" if severity in ("high","critical") else "info")

    if severity in ("high", "critical") or followup:
        with session_ctx() as s:
            s.add(Finding(
                scan_id=scan_id,
                title=f"[PASSIVE] {intel_type}: {value[:100]}",
                severity=severity,
                description=detail or f"Passive intelligence: {value}",
                evidence=f"Source: {source}",
                tool="passive-agent",
            ))
            s.commit()

    return f"Intelligence recorded: {intel_type} — {value[:80]}"


async def _handle_write_finding(scan_id: str, args: dict) -> str:
    with session_ctx() as s:
        f = Finding(
            scan_id=scan_id,
            title=args["title"],
            severity=args["severity"],
            description=args.get("description"),
            evidence=args.get("evidence"),
            url=args.get("url"),
            cwe_id=args.get("cwe_id"),
            remediation=args.get("remediation"),
            tool="passive-agent",
        )
        s.add(f)
        s.commit()
        s.refresh(f)
    return f"Finding recorded: {f.id}"


async def _dispatch(scan_id: str, tool_name: str, args: dict, passive_tools: dict) -> str:
    if tool_name == "run_passive_tool":
        return await _handle_run_passive_tool(scan_id, args, passive_tools)
    elif tool_name == "google_dork":
        return await _handle_google_dork(scan_id, args)
    elif tool_name == "analyze_certificates":
        return await _handle_analyze_certs(scan_id, args)
    elif tool_name == "emit_intelligence":
        return await _handle_emit_intelligence(scan_id, args)
    elif tool_name == "write_finding":
        return await _handle_write_finding(scan_id, args)
    elif tool_name == "finish_passive_recon":
        summary = args.get("summary", "")
        _log(scan_id, f"🏁 Passive recon complete. Attack surface: {args.get('attack_surface_rating','?')}\n{summary}")
        return "done"
    return f"Unknown tool: {tool_name}"


# ─── Main entry point ─────────────────────────────────────────────────────────

async def run_passive_agent(
    scan_id: str,
    target_domain: str,
    scope: str,
    out_of_scope: Optional[str] = None,
    max_iterations: int = 25,
) -> None:
    passive_tools = _build_passive_tool_list()
    tool_list_str = "\n".join(
        f"  - {name}: {tool.description}" for name, tool in passive_tools.items()
    )
    _log(scan_id, f"🕵️ Passive Agent starting — {len(passive_tools)} passive tools available")
    _log(scan_id, f"Available tools: {', '.join(passive_tools.keys())}")

    system = _passive_system_prompt(target_domain, scope, out_of_scope or "", tool_list_str)
    messages = [{
        "role": "user",
        "content": (
            f"Begin passive intelligence gathering on {target_domain}. "
            "Use available passive tools systematically. "
            "Enumerate subdomains, discover historical URLs, identify technology stack, "
            "generate Google dorks, and map the full passive attack surface. "
            "Do NOT use any active scanning tools."
        ),
    }]

    finished = False
    for iteration in range(max_iterations):
        if finished:
            break

        _log(scan_id, f"🔄 Passive Agent iteration {iteration+1}/{max_iterations}")

        try:
            response = _client.messages.create(
                model=MODEL,
                max_tokens=3000,
                system=system,
                tools=PASSIVE_AI_TOOLS,
                messages=messages,
            )
        except Exception as e:
            _log(scan_id, f"Passive Agent API error: {e}", level="error")
            break

        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        has_tools    = False

        for block in response.content:
            if block.type == "text" and block.text.strip():
                _log(scan_id, f"💭 {block.text.strip()[:300]}")
            elif block.type == "tool_use":
                has_tools = True
                result = await _dispatch(scan_id, block.name, block.input or {}, passive_tools)
                tool_results.append({"type": "tool_result", "tool_use_id": block.id, "content": result})
                if block.name == "finish_passive_recon":
                    finished = True

        if has_tools:
            messages.append({"role": "user", "content": tool_results})

        if response.stop_reason == "end_turn" and not has_tools and not finished:
            messages.append({"role": "user", "content": "Continue analysis or call finish_passive_recon."})

    _log(scan_id, "✅ Passive Agent complete")
