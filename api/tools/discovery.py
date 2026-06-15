"""
BountyOS - Tool Auto-Discovery System

Scans the system PATH at startup and registers every installed security tool.
Works on any OS: Parrot OS, Kali Linux, BlackArch, Ubuntu, macOS, etc.

Flow:
  startup → discover_all_tools()
    for each entry in TOOL_CATALOGUE:
      shutil.which(binary) → found?
      run binary --version → confirm functional?
      register wrapper class dynamically
  → ALL_TOOLS, RECON_TOOLS, VULNSCAN_TOOLS populated
  → /api/v1/tools returns live availability + install hints for missing ones
"""

import asyncio
import shlex
import shutil
import json
import re
import subprocess
import os
from datetime import datetime
from typing import Optional, AsyncIterator

from api.tools.catalogue import TOOL_CATALOGUE


# ─── Discovered tool registry ─────────────────────────────────────────────────

DISCOVERED_TOOLS: dict = {}        # name → { meta + "available": bool, "version": str }
ALL_TOOLS: dict = {}               # name → DynamicTool instance (only available)
RECON_TOOLS: dict = {}
VULNSCAN_TOOLS: dict = {}
EXPLOIT_TOOLS_MAP: dict = {}
FORENSIC_TOOLS: dict = {}
UTIL_TOOLS: dict = {}


# ─── Base tool class ──────────────────────────────────────────────────────────

class DynamicTool:
    """
    A dynamically generated tool wrapper built from catalogue metadata.
    Handles any CLI tool uniformly — command construction, output streaming,
    finding detection via regex patterns.
    """

    def __init__(self, meta: dict, binary_path: str, version: str):
        self.name          = meta["name"]
        self.binary        = meta["binary"]
        self.binary_path   = binary_path
        self.phase         = meta["phase"]
        self.category      = meta.get("category", "")
        self.description   = meta.get("description", "")
        self.version       = version
        self.timeout       = meta.get("timeout", 300)
        self.output_fmt    = meta.get("output_fmt", "raw")
        self.finding_pats  = [re.compile(p, re.I) for p in meta.get("finding_patterns", [])]
        self.default_args  = meta.get("default_args", "")
        self.target_flag   = meta.get("target_flag", "")
        self.install_hint  = meta.get("install_hint", "")
        # Passive-safe: tools that only do read-only/OSINT operations
        self.passive_safe  = meta.get("passive_safe", self._infer_passive_safe(meta))

    def _infer_passive_safe(self, meta: dict) -> bool:
        """Infer whether a tool is safe for passive mode based on phase/category."""
        passive_categories = {
            "subdomain", "osint", "webprobe", "fingerprint",
            "metadata", "vcs", "lang", "util", "http",
            "network", "capture", "wordlist", "anonymity",
        }
        passive_phases = {"recon", "util", "forensics"}
        if meta["phase"] in passive_phases:
            return True
        if meta.get("category", "") in passive_categories:
            return True
        return False

    def event(self, scan_id: str, message: str, level: str = "info", raw: str = None) -> dict:
        return {
            "scan_id":    scan_id,
            "phase":      self.phase,
            "tool":       self.name,
            "level":      level,
            "message":    message,
            "raw":        raw,
            "created_at": datetime.utcnow().isoformat(),
        }

    def _is_finding(self, line: str) -> bool:
        return any(p.search(line) for p in self.finding_pats)

    def _build_command(self, target: str, **kwargs) -> str:
        """
        Build the command string for this tool.
        kwargs override default_args values.
        Supports: extra_args, wordlist, ports, output_file, etc.
        """
        parts = [self.binary_path or self.binary]

        # Append default args
        if self.default_args:
            parts.append(self.default_args)

        # Append target with flag if defined
        if target:
            if self.target_flag:
                parts.append(f"{self.target_flag} {shlex.quote(target)}")
            else:
                # Some tools take target as positional arg
                parts.append(shlex.quote(target))

        # Append any extra_args from kwargs
        extra = kwargs.get("extra_args", "")
        if extra:
            parts.append(extra)

        # Handle common kwargs
        if "wordlist" in kwargs and kwargs["wordlist"]:
            wl = kwargs["wordlist"]
            if os.path.isfile(wl):
                if self.name in ("ffuf",):
                    parts.append(f"-w {shlex.quote(wl)}")
                elif self.name in ("gobuster",):
                    parts.append(f"-w {shlex.quote(wl)}")
                elif self.name in ("feroxbuster",):
                    parts.append(f"--wordlist {shlex.quote(wl)}")

        if "ports" in kwargs and kwargs["ports"]:
            if self.name == "nmap":
                parts.append(f"-p {shlex.quote(str(kwargs['ports']))}")
            elif self.name == "masscan":
                parts.append(f"-p {shlex.quote(str(kwargs['ports']))}")

        return " ".join(parts)

    async def run(self, scan_id: str, target: str, **kwargs) -> AsyncIterator[dict]:
        cmd = self._build_command(target, **kwargs)
        yield self.event(scan_id, f"▶ {self.name} v{self.version} starting on {target}")
        yield self.event(scan_id, f"CMD: {cmd}", level="info")

        from api.tools.executor import stream_command
        async for item in stream_command(
            tool_name=self.name,
            command=cmd,
            scan_id=scan_id,
            target=target,
            timeout=self.timeout,
            execution_mode=kwargs.get("execution_mode"),
            runner_id=kwargs.get("runner_id"),
            metadata={"phase": self.phase, "category": self.category},
        ):
            itype = item.get("type")
            if itype == "started":
                source = item.get("runner_name") or item.get("source", "local")
                yield self.event(scan_id, f"Execution source: {source}")
                continue
            if itype == "line":
                decoded = str(item.get("line") or "").rstrip()
                if not decoded:
                    continue
                level = "finding" if self._is_finding(decoded) else "info"
                if self.output_fmt == "json":
                    try:
                        data = json.loads(decoded)
                        decoded = self._format_json_line(data)
                        level = "finding"
                    except (json.JSONDecodeError, TypeError):
                        pass
                yield self.event(scan_id, decoded, level=level, raw=str(item.get("line") or ""))
                continue
            if itype == "result" and item.get("status") not in {"completed", "success"}:
                yield self.event(scan_id, f"{self.name} {item.get('status')}: {item.get('error') or 'exit code ' + str(item.get('exit_code'))}", level="error")

        yield self.event(scan_id, f"■ {self.name} complete")

    def _format_json_line(self, data: dict) -> str:
        """Extract readable summary from JSON tool output."""
        # Nuclei JSON format
        if "info" in data and "matched-at" in data:
            sev  = data.get("info", {}).get("severity", "?").upper()
            name = data.get("info", {}).get("name", "?")
            url  = data.get("matched-at", "?")
            return f"[{sev}] {name} — {url}"
        # Generic
        return json.dumps(data)


# ─── Custom overrides for tools needing special command construction ───────────

class NmapTool(DynamicTool):
    async def run(self, scan_id: str, target: str, ports: str = "80,443,8080,8443,8888,3000,5000,22,21,25,3306,5432", stealth: bool = False, **kwargs):
        flags = "-sS -sV --open" if stealth else "-sV --open -T4"
        cmd = f"nmap {flags} -p {shlex.quote(ports)} {shlex.quote(target)}"
        yield self.event(scan_id, f"▶ nmap v{self.version} on {target} (ports: {ports})")
        yield self.event(scan_id, f"CMD: {cmd}")
        async for ev in self._stream(cmd, scan_id, target=target, execution_mode=kwargs.get("execution_mode"), runner_id=kwargs.get("runner_id")):
            yield ev
        yield self.event(scan_id, "■ nmap complete")

    async def _stream(self, cmd, scan_id, target=None, execution_mode=None, runner_id=None):
        from api.tools.executor import stream_command
        async for item in stream_command(
            tool_name=self.name, command=cmd, scan_id=scan_id, target=target,
            timeout=self.timeout, execution_mode=execution_mode, runner_id=runner_id,
            metadata={"phase": self.phase, "category": self.category},
        ):
            if item.get("type") == "started":
                yield self.event(scan_id, f"Execution source: {item.get('runner_name') or item.get('source')}")
            elif item.get("type") == "line":
                d = str(item.get("line") or "").rstrip()
                if d:
                    lvl = "finding" if re.search(r"\d+/tcp\s+open|\d+/udp\s+open", d) else "info"
                    yield self.event(scan_id, d, level=lvl, raw=d)
            elif item.get("type") == "result" and item.get("status") not in {"completed", "success"}:
                yield self.event(scan_id, f"nmap {item.get('status')}: {item.get('error')}", level="error")


class SqlmapTool(DynamicTool):
    async def run(self, scan_id: str, target: str, level: int = 1, risk: int = 1, **kwargs):
        url = target if target.startswith("http") else f"https://{target}"
        cmd = f"sqlmap -u {shlex.quote(url)} --level={level} --risk={risk} --batch --output-dir=/tmp/sqlmap_out"
        yield self.event(scan_id, f"▶ sqlmap v{self.version} on {url} (level={level} risk={risk})")
        from api.tools.executor import stream_command
        async for item in stream_command(
            tool_name=self.name, command=cmd, scan_id=scan_id, target=url,
            timeout=self.timeout, execution_mode=kwargs.get("execution_mode"), runner_id=kwargs.get("runner_id"),
            metadata={"phase": self.phase, "category": self.category},
        ):
            if item.get("type") == "started":
                yield self.event(scan_id, f"Execution source: {item.get('runner_name') or item.get('source')}")
            elif item.get("type") == "line":
                d = str(item.get("line") or "").rstrip()
                if d:
                    low = d.lower()
                    lvl = "finding" if any(x in low for x in ["injectable", "sql injection", "parameter"]) else "info"
                    yield self.event(scan_id, d, level=lvl, raw=d)
            elif item.get("type") == "result" and item.get("status") not in {"completed", "success"}:
                yield self.event(scan_id, f"sqlmap {item.get('status')}: {item.get('error')}", level="error")
        yield self.event(scan_id, "■ sqlmap complete")


class NucleiTool(DynamicTool):
    async def run(self, scan_id: str, target: str, severity: str = "medium,high,critical", tags: str = "cve,misconfig,exposure", **kwargs):
        url = target if target.startswith("http") else f"https://{target}"
        cmd = f"nuclei -u {shlex.quote(url)} -severity {shlex.quote(severity)} -tags {shlex.quote(tags)} -silent -jsonl"
        yield self.event(scan_id, f"▶ nuclei v{self.version} on {url}")
        from api.tools.executor import stream_command
        async for item in stream_command(
            tool_name=self.name, command=cmd, scan_id=scan_id, target=url,
            timeout=self.timeout, execution_mode=kwargs.get("execution_mode"), runner_id=kwargs.get("runner_id"),
            metadata={"phase": self.phase, "category": self.category},
        ):
            if item.get("type") == "started":
                yield self.event(scan_id, f"Execution source: {item.get('runner_name') or item.get('source')}")
            elif item.get("type") == "line":
                d = str(item.get("line") or "").rstrip()
                if not d:
                    continue
                try:
                    data = json.loads(d)
                    msg = f"[{data.get('info',{}).get('severity','?').upper()}] {data.get('info',{}).get('name','?')} — {data.get('matched-at') or data.get('matched_at') or '?'}"
                    yield self.event(scan_id, msg, level="finding", raw=d)
                except Exception:
                    yield self.event(scan_id, d)
            elif item.get("type") == "result" and item.get("status") not in {"completed", "success"}:
                yield self.event(scan_id, f"nuclei {item.get('status')}: {item.get('error')}", level="error")
        yield self.event(scan_id, "■ nuclei complete")


class HeadersTool(DynamicTool):
    """HTTP header security check that can execute locally or on a remote runner."""
    REQUIRED = ["strict-transport-security", "content-security-policy", "x-frame-options", "x-content-type-options", "referrer-policy", "permissions-policy"]

    async def run(self, scan_id: str, target: str, **kwargs):
        url = target if target.startswith("http") else f"https://{target}"
        yield self.event(scan_id, f"▶ headers check on {url}")
        cmd = ["curl", "-sI", "--max-time", "15", url]
        raw_lines = []
        from api.tools.executor import stream_command
        async for item in stream_command(
            tool_name=self.name, command=cmd, scan_id=scan_id, target=url,
            timeout=self.timeout, execution_mode=kwargs.get("execution_mode"), runner_id=kwargs.get("runner_id"),
            metadata={"phase": self.phase, "category": self.category},
        ):
            if item.get("type") == "started":
                yield self.event(scan_id, f"Execution source: {item.get('runner_name') or item.get('source')}")
            elif item.get("type") == "line":
                d = str(item.get("line") or "").rstrip()
                raw_lines.append(d.lower())
                yield self.event(scan_id, d, raw=d)
            elif item.get("type") == "result" and item.get("status") not in {"completed", "success"}:
                yield self.event(scan_id, f"headers {item.get('status')}: {item.get('error')}", level="error")
                return
        present = {h for h in self.REQUIRED if any(l.startswith(h) for l in raw_lines)}
        for h in self.REQUIRED:
            if h not in present:
                yield self.event(scan_id, f"MISSING security header: {h}", level="finding")
        yield self.event(scan_id, f"■ headers complete — {len(self.REQUIRED)-len(present)} missing")


# ─── Custom overrides registry ────────────────────────────────────────────────

CUSTOM_CLASSES = {
    "nmap":    NmapTool,
    "sqlmap":  SqlmapTool,
    "nuclei":  NucleiTool,
    "headers": None,   # special — not binary-dependent, always available
}


# ─── Discovery engine ─────────────────────────────────────────────────────────

def _get_version(binary: str, flag: str) -> Optional[str]:
    """Run `binary flag` and extract version string from first line of output."""
    try:
        result = subprocess.run(
            [binary, flag],
            capture_output=True, text=True, timeout=8
        )
        out = (result.stdout + result.stderr).strip()
        # Extract first version-like string
        match = re.search(r"(\d+[\.\d]+)", out)
        return match.group(1) if match else "?"
    except Exception:
        return None


def discover_all_tools() -> dict:
    """
    Scan PATH for every tool in the catalogue.
    Returns the full DISCOVERED_TOOLS registry (available + unavailable).
    """
    global ALL_TOOLS, RECON_TOOLS, VULNSCAN_TOOLS, EXPLOIT_TOOLS_MAP, FORENSIC_TOOLS, UTIL_TOOLS, DISCOVERED_TOOLS

    found_count  = 0
    missed_count = 0
    seen_names   = set()

    # Always register the pure-Python headers tool
    headers_meta = {
        "binary": "curl",
        "name": "headers",
        "phase": "vulnscan",
        "category": "misconfiguration",
        "description": "HTTP security header audit",
        "version_flag": "--version",
        "timeout": 60,
        "output_fmt": "raw",
        "finding_patterns": [r"MISSING"],
        "install_hint": "apt install curl",
        "default_args": "",
        "target_flag": "",
        "passive_safe": True,
    }
    curl_path = shutil.which("curl")
    h_tool = HeadersTool(headers_meta, curl_path or "curl", "built-in")
    ALL_TOOLS["headers"]       = h_tool
    VULNSCAN_TOOLS["headers"]  = h_tool
    DISCOVERED_TOOLS["headers"] = {**headers_meta, "available": True, "version": "built-in", "path": curl_path}
    seen_names.add("headers")

    for meta in TOOL_CATALOGUE:
        name   = meta["name"]
        binary = meta["binary"]

        # Deduplicate by name (catalogue may have same name in multiple phases)
        if name in seen_names:
            continue
        seen_names.add(name)

        binary_path = shutil.which(binary)

        if binary_path:
            version = _get_version(binary_path, meta.get("version_flag", "--version")) or "?"
            DISCOVERED_TOOLS[name] = {
                **meta,
                "available":    True,
                "version":      version,
                "path":         binary_path,
            }

            # Instantiate: use custom class if defined, else generic DynamicTool
            cls = CUSTOM_CLASSES.get(name, DynamicTool)
            if cls is None:
                continue  # headers already handled above
            tool = cls(meta, binary_path, version)

            ALL_TOOLS[name] = tool
            phase = meta["phase"]
            if phase == "recon":
                RECON_TOOLS[name] = tool
            elif phase == "vulnscan":
                VULNSCAN_TOOLS[name] = tool
            elif phase == "exploit":
                EXPLOIT_TOOLS_MAP[name] = tool
            elif phase == "forensics":
                FORENSIC_TOOLS[name] = tool
            else:
                UTIL_TOOLS[name] = tool

            found_count += 1
            print(f"  ✅ [{phase:10}] {name:25} v{version} — {binary_path}")
        else:
            DISCOVERED_TOOLS[name] = {
                **meta,
                "available":    False,
                "version":      None,
                "path":         None,
            }
            missed_count += 1

    print(f"\n  BountyOS Tool Discovery complete:")
    print(f"  ✅ {found_count} tools available")
    print(f"  ⚠  {missed_count} tools not installed")
    return DISCOVERED_TOOLS



def refresh_remote_tools() -> dict:
    """Register proxy wrappers for tools currently advertised by online runners."""
    try:
        from api.runners.manager import runner_manager
        remote = runner_manager.aggregate_tools()
    except Exception:
        return {}
    by_name = {item.get("name"): item for item in TOOL_CATALOGUE}
    by_name["headers"] = {
        "binary": "curl", "name": "headers", "phase": "vulnscan",
        "category": "misconfiguration", "description": "HTTP security header audit",
        "timeout": 60, "output_fmt": "raw", "finding_patterns": [r"MISSING"],
        "default_args": "", "target_flag": "", "passive_safe": True,
    }
    for name, remote_meta in remote.items():
        meta = by_name.get(name)
        if not meta:
            continue
        if name in ALL_TOOLS:
            info = DISCOVERED_TOOLS.setdefault(name, {**meta, "available": True, "version": getattr(ALL_TOOLS[name], "version", "?")})
            info["locations"] = remote_meta.get("runners", [])
            info["remote_only"] = False
            continue
        cls = CUSTOM_CLASSES.get(name, DynamicTool)
        if cls is None:
            cls = HeadersTool
        tool = cls(meta, meta.get("binary", name), f"remote:{remote_meta.get('version','?')}")
        ALL_TOOLS[name] = tool
        DISCOVERED_TOOLS[name] = {
            **meta, "available": True, "version": tool.version, "path": None,
            "locations": remote_meta.get("runners", []), "remote_only": True,
        }
        phase = meta.get("phase")
        if phase == "recon": RECON_TOOLS[name] = tool
        elif phase == "vulnscan": VULNSCAN_TOOLS[name] = tool
        elif phase == "exploit": EXPLOIT_TOOLS_MAP[name] = tool
        elif phase == "forensics": FORENSIC_TOOLS[name] = tool
        else: UTIL_TOOLS[name] = tool
    return remote


def get_tool(name: str) -> Optional[DynamicTool]:
    return ALL_TOOLS.get(name)


def get_passive_tools() -> dict:
    """Return only tools safe for passive scanning mode."""
    return {n: t for n, t in ALL_TOOLS.items() if t.passive_safe}


def get_aggressive_tools() -> dict:
    """Return all available tools including destructive ones."""
    return ALL_TOOLS


def get_discovery_report() -> dict:
    """Full report for local and connected remote tools."""
    refresh_remote_tools()
    report = {}
    for name, info in DISCOVERED_TOOLS.items():
        report[name] = {
            "name":        info["name"],
            "binary":      info["binary"],
            "phase":       info["phase"],
            "category":    info.get("category", ""),
            "description": info.get("description", ""),
            "available":   info["available"],
            "version":     info.get("version"),
            "path":        info.get("path"),
            "passive_safe": info.get("passive_safe", False),
            "install_hint": info.get("install_hint", ""),
            "locations": info.get("locations", []),
            "remote_only": info.get("remote_only", False),
        }
    return report
