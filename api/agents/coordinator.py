"""
BountyOS - AI Coordinator Agent (Phase 2)

Uses Gemini with function calling to:
  1. Ingest recon + vulnscan findings from the DB
  2. Reason over attack surface and prioritise targets
  3. Build a step-by-step exploit chain
  4. Gate each destructive action through the human approval system
  5. Stream its reasoning as ScanEvents in real-time

Flow:
  recon output → AI analysis → exploit plan →
    for each step:
      if destructive → create Approval, wait for human decision
      if safe        → execute immediately via tool wrapper
      → emit ScanEvent for each action + result
"""

import asyncio
import json
import os
from datetime import datetime
from typing import AsyncIterator, Optional

from api.ai import get_ai_client

from api.database import session_ctx
from api.models import (
    Approval, ApprovalStatus, Finding, Scan,
    ScanEvent, ScanPhase, ScanStatus,
)

# ─── Gemini / Vertex AI client ─────────────────────────────────────────────

_client = get_ai_client()

MODEL = os.getenv("BOUNTYOS_MAIN_MODEL", "gemini-1.5-pro")

# ─── Tool definitions exposed to Gemini ──────────────────────────────────────
# These are the actions Gemini can request. Each maps to a handler below.

AI_TOOLS = [
    {
        "name": "read_findings",
        "description": (
            "Read all findings collected so far for this scan, "
            "including subdomain list, open ports, technologies, and vuln scanner output."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "severity_filter": {
                    "type": "string",
                    "description": "Optional: filter by severity (info/low/medium/high/critical)",
                }
            },
            "required": [],
        },
    },
    {
        "name": "read_events",
        "description": "Read the raw event log for this scan to understand what tools have run and what output they produced.",
        "input_schema": {
            "type": "object",
            "properties": {
                "phase": {
                    "type": "string",
                    "description": "Optional: filter by phase (recon/vulnscan/exploit)",
                },
                "tool": {
                    "type": "string",
                    "description": "Optional: filter by tool name",
                },
            },
            "required": [],
        },
    },
    {
        "name": "propose_exploit_step",
        "description": (
            "Propose a single exploit step. If destructive=true the step will be "
            "queued for human approval before execution. Safe steps (passive enumeration, "
            "read-only checks) execute immediately."
        ),
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {
                    "type": "string",
                    "description": "Short title, e.g. 'Test SQLi on /login?id= parameter'",
                },
                "tool": {
                    "type": "string",
                    "description": "Tool to use: sqlmap | ffuf | nuclei | nmap | headers | custom",
                },
                "target_url": {
                    "type": "string",
                    "description": "Exact URL or host to target",
                },
                "command_args": {
                    "type": "object",
                    "description": "Key-value args passed to the tool wrapper (e.g. {level: 2, risk: 1})",
                },
                "destructive": {
                    "type": "boolean",
                    "description": "True if this step could modify data, trigger WAF bans, or cause side-effects",
                },
                "reasoning": {
                    "type": "string",
                    "description": "Explain why this step is worthwhile based on findings so far",
                },
                "severity_estimate": {
                    "type": "string",
                    "enum": ["info", "low", "medium", "high", "critical"],
                    "description": "Estimated severity if this step yields a finding",
                },
            },
            "required": ["title", "tool", "target_url", "destructive", "reasoning", "severity_estimate"],
        },
    },
    {
        "name": "emit_reasoning",
        "description": "Stream a reasoning note or intermediate conclusion to the event log so the operator can follow the AI's thought process.",
        "input_schema": {
            "type": "object",
            "properties": {
                "thought": {
                    "type": "string",
                    "description": "The reasoning note to emit",
                }
            },
            "required": ["thought"],
        },
    },
    {
        "name": "write_finding",
        "description": "Directly record a confirmed vulnerability finding with full details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title":       {"type": "string"},
                "severity":    {"type": "string", "enum": ["info", "low", "medium", "high", "critical"]},
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
        "name": "finish_analysis",
        "description": "Signal that the AI has completed its exploit chain analysis. Provide a final summary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {
                    "type": "string",
                    "description": "High-level summary of attack surface, key findings, and recommended next steps",
                },
                "critical_count": {"type": "integer"},
                "high_count":     {"type": "integer"},
                "medium_count":   {"type": "integer"},
            },
            "required": ["summary"],
        },
    },
]


# ─── System prompt ────────────────────────────────────────────────────────────

def _build_system_prompt(target_domain: str, scope: str, out_of_scope: str) -> str:
    return f"""You are BountyOS Coordinator — an autonomous bug bounty reasoning agent.

TARGET: {target_domain}
IN-SCOPE: {scope}
OUT-OF-SCOPE: {out_of_scope or 'none specified'}

Your mission:
1. Read the recon and vulnerability scan findings collected so far using read_findings and read_events.
2. Reason over the attack surface systematically — emit your thoughts with emit_reasoning.
3. Prioritise the highest-impact attack paths based on the technology stack, exposed services, and known vuln patterns.
4. For each attack path, call propose_exploit_step. Mark steps as destructive=true when they involve:
   - Active exploitation (SQLi, XSS injection, auth bypass attempts)
   - Anything that modifies server state or could trigger alerts
   - Brute-forcing or fuzzing beyond passive enumeration
5. Confirmed findings should be recorded with write_finding including CWE IDs and remediation advice.
6. Call finish_analysis when your chain is complete.

Rules you must follow:
- NEVER propose steps targeting out-of-scope assets.
- NEVER propose steps that could cause data destruction or denial of service.
- Always explain your reasoning before proposing a destructive step.
- Prefer chaining findings: a subdomain takeover + leaked credential is more impactful than each alone.
- Think like a senior penetration tester preparing a report for a client, not a CTF player.
"""


# ─── Tool handlers ────────────────────────────────────────────────────────────

async def _handle_read_findings(scan_id: str, args: dict) -> str:
    severity_filter = args.get("severity_filter")
    with session_ctx() as s:
        from sqlmodel import select
        q = select(Finding).where(Finding.scan_id == scan_id)
        if severity_filter:
            q = q.where(Finding.severity == severity_filter)
        findings = s.exec(q).all()
        if not findings:
            return "No findings recorded yet."
        rows = []
        for f in findings:
            rows.append({
                "id":       f.id,
                "title":    f.title,
                "severity": f.severity,
                "tool":     f.tool,
                "url":      f.url,
                "evidence": (f.evidence or "")[:300],
            })
        return json.dumps(rows, indent=2)


async def _handle_read_events(scan_id: str, args: dict) -> str:
    phase  = args.get("phase")
    tool   = args.get("tool")
    with session_ctx() as s:
        from sqlmodel import select
        q = select(ScanEvent).where(ScanEvent.scan_id == scan_id)
        if phase:
            q = q.where(ScanEvent.phase == phase)
        if tool:
            q = q.where(ScanEvent.tool == tool)
        events = s.exec(q.order_by(ScanEvent.created_at)).all()
        if not events:
            return "No events for that filter."
        lines = [f"[{e.level.upper()}][{e.tool}] {e.message}" for e in events[-100:]]
        return "\n".join(lines)


async def _handle_emit_reasoning(scan_id: str, args: dict) -> str:
    thought = args.get("thought", "")
    with session_ctx() as s:
        ev = ScanEvent(
            scan_id=scan_id,
            phase=ScanPhase.EXPLOIT,
            tool="ai-coordinator",
            level="info",
            message=f"💭 {thought}",
        )
        s.add(ev)
        s.commit()
    return "Thought logged."


async def _handle_write_finding(scan_id: str, args: dict) -> str:
    with session_ctx() as s:
        finding = Finding(
            scan_id=scan_id,
            title=args["title"],
            severity=args["severity"],
            description=args.get("description"),
            evidence=args.get("evidence"),
            url=args.get("url"),
            cwe_id=args.get("cwe_id"),
            remediation=args.get("remediation"),
            tool="ai-coordinator",
        )
        s.add(finding)
        s.commit()
        s.refresh(finding)
    return f"Finding recorded: {finding.id}"


async def _handle_propose_exploit_step(
    scan_id: str, args: dict,
    approval_timeout: int = 300
) -> str:
    """
    Non-destructive steps: run the tool immediately and return output.
    Destructive steps: create an Approval record and poll until decided.
    """
    title         = args["title"]
    tool_name     = args["tool"]
    target_url    = args["target_url"]
    destructive   = args["destructive"]
    reasoning     = args["reasoning"]
    command_args  = args.get("command_args", {})

    # Emit a log entry so the operator sees what's coming
    with session_ctx() as s:
        ev = ScanEvent(
            scan_id=scan_id,
            phase=ScanPhase.EXPLOIT,
            tool="ai-coordinator",
            level="warn" if destructive else "info",
            message=(
                f"{'⚠️ DESTRUCTIVE' if destructive else '✅ SAFE'} step proposed: {title} "
                f"[tool={tool_name}] [target={target_url}]"
            ),
            raw=json.dumps(args),
        )
        s.add(ev)
        s.commit()

    # ── Destructive path: wait for human approval ─────────────────────────────
    if destructive:
        with session_ctx() as s:
            approval = Approval(
                scan_id=scan_id,
                phase=ScanPhase.EXPLOIT,
                action=title,
                context=f"Reasoning: {reasoning}\n\nTool: {tool_name}\nTarget: {target_url}\nArgs: {json.dumps(command_args)}",
                status=ApprovalStatus.PENDING,
            )
            s.add(approval)
            s.commit()
            s.refresh(approval)
            approval_id = approval.id

        # Poll DB for decision (operator uses /api/v1/approvals/{id}/decide)
        deadline = asyncio.get_event_loop().time() + approval_timeout
        while asyncio.get_event_loop().time() < deadline:
            await asyncio.sleep(5)
            with session_ctx() as s:
                a = s.get(Approval, approval_id)
                if a and a.status == ApprovalStatus.APPROVED:
                    break
                if a and a.status == ApprovalStatus.REJECTED:
                    return f"Step REJECTED by operator: {title}"

        with session_ctx() as s:
            a = s.get(Approval, approval_id)
            if not a or a.status != ApprovalStatus.APPROVED:
                return f"Step timed out waiting for approval: {title}"

    # ── Delegate to Exploit Agent ─────────────────────────────────────────────
    from api.agents.exploit_agent import run_exploit_agent

    # Build scan context for the exploit agent
    scan_context = await _handle_read_findings(scan_id, {})

    result = await run_exploit_agent(
        scan_id=scan_id,
        step_title=title,
        tool_name=tool_name,
        target_url=target_url,
        tech_context=reasoning,
        scan_context=scan_context,
        command_args=command_args,
    )

    return (
        f"Exploit Agent result: {result.status.upper()}\n"
        f"Attempts: {result.attempts}\n"
        f"Evidence: {result.evidence or 'none'}\n"
        f"Finding ID: {result.finding_id or 'none'}\n"
        f"Summary: {result.summary}"
    )


async def _handle_finish_analysis(scan_id: str, args: dict) -> str:
    summary = args.get("summary", "")
    with session_ctx() as s:
        ev = ScanEvent(
            scan_id=scan_id,
            phase=ScanPhase.EXPLOIT,
            tool="ai-coordinator",
            level="info",
            message=f"🏁 Analysis complete.\n{summary}",
        )
        s.add(ev)
        s.commit()
    return "done"


# ─── Tool dispatcher ──────────────────────────────────────────────────────────

async def _dispatch(scan_id: str, tool_name: str, args: dict) -> str:
    dispatch = {
        "read_findings":        _handle_read_findings,
        "read_events":          _handle_read_events,
        "emit_reasoning":       _handle_emit_reasoning,
        "write_finding":        _handle_write_finding,
        "propose_exploit_step": _handle_propose_exploit_step,
        "finish_analysis":      _handle_finish_analysis,
    }
    handler = dispatch.get(tool_name)
    if not handler:
        return f"Unknown tool: {tool_name}"
    return await handler(scan_id, args)


# ─── Main agent entry point ───────────────────────────────────────────────────

async def run_ai_coordinator(
    scan_id: str,
    target_domain: str,
    scope: str,
    out_of_scope: Optional[str] = None,
    max_iterations: int = 30,
) -> None:
    """
    Agentic loop: sends messages to Gemini, handles tool calls,
    feeds results back, loops until finish_analysis is called or
    the iteration cap is hit.
    """

    def _log(msg: str, level: str = "info"):
        with session_ctx() as s:
            s.add(ScanEvent(
                scan_id=scan_id,
                phase=ScanPhase.EXPLOIT,
                tool="ai-coordinator",
                level=level,
                message=msg,
            ))
            s.commit()

    _log("🤖 AI Coordinator starting — reading attack surface...")

    system = _build_system_prompt(target_domain, scope, out_of_scope or "")
    messages = [
        {
            "role": "user",
            "content": (
                f"Begin analysis of {target_domain}. "
                "Read the collected findings and events, reason over the attack surface, "
                "then build and execute your exploit chain. "
                "Use emit_reasoning liberally so the operator can follow your thinking."
            ),
        }
    ]

    finished = False
    for iteration in range(max_iterations):
        if finished:
            break

        _log(f"🔄 AI iteration {iteration + 1}/{max_iterations}")

        try:
            response = await asyncio.to_thread(
                _client.messages.create,
                model=MODEL,
                max_tokens=4096,
                system=system,
                tools=AI_TOOLS,
                messages=messages,
            )
        except Exception as e:
            _log(f"Gemini API error: {e}", level="error")
            break

        # Build assistant message for history
        assistant_msg = {"role": "assistant", "content": response.content}
        messages.append(assistant_msg)

        # Collect tool results to send back in one user turn
        tool_results = []
        has_tool_use = False

        for block in response.content:
            # Emit text blocks as reasoning logs
            if block.type == "text" and block.text.strip():
                _log(f"🧠 {block.text.strip()}")

            elif block.type == "tool_use":
                has_tool_use = True
                tool_name = block.name
                tool_args  = block.input or {}

                _log(f"🔧 Calling tool: {tool_name}({json.dumps(tool_args)[:120]})")

                result = await _dispatch(scan_id, tool_name, tool_args)

                tool_results.append({
                    "type":        "tool_result",
                    "tool_use_id": block.id,
                    "content":     result,
                })

                if tool_name == "finish_analysis":
                    finished = True

        # If Gemini made tool calls, feed results back
        if has_tool_use:
            messages.append({"role": "user", "content": tool_results})

        # If Gemini stopped without tool calls and without finishing, nudge it
        if response.stop_reason == "end_turn" and not has_tool_use and not finished:
            _log("⚠️ Gemini stopped without finishing — prompting continuation")
            messages.append({
                "role": "user",
                "content": (
                    "Continue your analysis. If you have finished, call finish_analysis."
                ),
            })

    if not finished:
        _log("⚠️ AI Coordinator reached iteration limit without calling finish_analysis", level="warn")

    _log("✅ AI Coordinator complete")
