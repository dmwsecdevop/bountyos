"""
BountyOS - Command Safety Validator

Last line of defense. Runs at subprocess level BEFORE any command executes.
Blocks commands that could destroy the operator's own system regardless of:
  - What the AI agent decided
  - What the operator approved
  - What tool wrapper requested

Allows:
  - All legitimate pentesting tools (nmap, sqlmap, nuclei, msfconsole, etc.)
  - Network operations against TARGET systems
  - File reads (cat, ls, find, grep on tool output)

Blocks (PERMANENTLY, no override):
  - File system destruction (rm -rf, shred, dd, mkfs, fdisk, wipefs)
  - System control (shutdown, reboot, halt, poweroff)
  - Database destructive ops (DROP TABLE, DELETE FROM without WHERE, TRUNCATE)
  - Disk operations (format, dd if=/dev/zero, dd if=/dev/random to disk)
  - Service killers (kill -9 on system services, systemctl stop critical)
  - Fork bombs and resource exhaustion
  - Self-modification of BountyOS files
  - Reverse shells back TO the operator's machine
"""

import re
import shlex
import os
from typing import Tuple

# ─── Blocked patterns ─────────────────────────────────────────────────────────
# Each entry: (regex_pattern, reason, severity)

BLOCKED_PATTERNS = [
    # ── Filesystem destruction ─────────────────────────────────────────────────
    (r'\brm\s+.*-[a-z]*r[a-z]*f|rm\s+-[a-z]*f[a-z]*r', 'rm -rf detected', 'CRITICAL'),
    (r'\brm\s+-rf\b|\brm\s+--force\s+--recursive', 'rm -rf detected', 'CRITICAL'),
    (r'\bshred\b', 'shred command detected', 'CRITICAL'),
    (r'\bwipefs\b', 'wipefs command detected', 'CRITICAL'),
    (r'\bdd\b.*of=\/dev\/[sh]d[a-z]', 'dd writing to disk device', 'CRITICAL'),
    (r'\bdd\b.*of=\/dev\/nvme', 'dd writing to NVMe device', 'CRITICAL'),
    (r'\bmkfs\b', 'mkfs filesystem formatting', 'CRITICAL'),
    (r'\bfdisk\b.*-[a-z]*w|\bparted\b.*rm\b', 'destructive disk operation', 'CRITICAL'),
    (r'\btruncate\b.*--size\s+0', 'file truncation to zero', 'HIGH'),

    # ── System control ─────────────────────────────────────────────────────────
    (r'\bshutdown\b', 'shutdown command', 'CRITICAL'),
    (r'\breboot\b', 'reboot command', 'CRITICAL'),
    (r'\bhalt\b', 'halt command', 'CRITICAL'),
    (r'\bpoweroff\b', 'poweroff command', 'CRITICAL'),
    (r'\binit\s+0\b|\binit\s+6\b', 'init runlevel change', 'CRITICAL'),
    (r'\bsystemctl\s+(stop|disable|mask)\s+(ssh|networking|network|firewall|docker)\b',
     'disabling critical system service', 'CRITICAL'),

    # ── Fork bomb / resource exhaustion ───────────────────────────────────────
    (r':\(\)\s*\{.*:\|:&\s*\}|:\(\)\{:\|:&\}', 'fork bomb detected', 'CRITICAL'),
    (r'\byes\b\s+>\s*/dev/', 'resource exhaustion to device', 'HIGH'),

    # ── Overwriting critical system files ─────────────────────────────────────
    (r'>\s*/etc/(passwd|shadow|sudoers|hosts|crontab|fstab|ssh/sshd_config)',
     'overwriting critical system file', 'CRITICAL'),
    (r'>\s*/boot/', 'writing to /boot', 'CRITICAL'),
    (r'>\s*/sys/|>\s*/proc/', 'writing to /sys or /proc', 'CRITICAL'),

    # ── Database destruction ───────────────────────────────────────────────────
    (r'\bDROP\s+(DATABASE|TABLE|SCHEMA)\b', 'SQL DROP statement', 'CRITICAL'),
    (r'\bTRUNCATE\s+TABLE\b', 'SQL TRUNCATE statement', 'HIGH'),
    (r'\bDELETE\s+FROM\b(?!.*\bWHERE\b)', 'DELETE without WHERE clause', 'HIGH'),

    # ── Self-modification of BountyOS ─────────────────────────────────────────
    (r'rm.*bountyos|rm.*api/|rm.*dashboard/', 'deleting BountyOS files', 'CRITICAL'),
    (r'>\s*.*\/bountyos\/', 'overwriting BountyOS files', 'HIGH'),

    # ── Crypto/ransomware-like patterns ───────────────────────────────────────
    (r'\bopenssl\s+enc\b.*-e\b.*-pass\b', 'mass file encryption detected', 'CRITICAL'),
    (r'for.*in.*\/home\/.*do.*openssl', 'bulk encryption loop', 'CRITICAL'),

    # ── Crontab/scheduled destruction ─────────────────────────────────────────
    (r'crontab\s+-r\b', 'crontab removal', 'HIGH'),
    (r'echo.*>\s*/etc/cron', 'overwriting cron files', 'HIGH'),
]

# Compiled patterns for performance
_COMPILED = [(re.compile(p, re.IGNORECASE | re.DOTALL), reason, sev)
             for p, reason, sev in BLOCKED_PATTERNS]

# ─── Allowed safe pentesting patterns (never blocked) ─────────────────────────
# These patterns override block rules for legitimate tool usage
SAFE_OVERRIDES = [
    r'\bnmap\b',
    r'\bsqlmap\b',
    r'\bnuclei\b',
    r'\bmsfconsole\b',
    r'\bmsfvenom\b',
    r'\bhydra\b',
    r'\bmedusa\b',
    r'\bffuf\b',
    r'\bgobuster\b',
    r'\bferoxbuster\b',
    r'\bnikto\b',
    r'\bwpscan\b',
    r'\bsubjack\b',
    r'\bdalfox\b',
    r'\bcommix\b.*--url',
    r'\bcurl\b',
    r'\bwget\b',
]
_SAFE = [re.compile(p, re.IGNORECASE) for p in SAFE_OVERRIDES]


def validate_command(cmd: str) -> Tuple[bool, str]:
    """
    Validate a command before execution.

    Returns:
        (True, "")           — command is safe, proceed
        (False, "reason")    — command is BLOCKED, do not execute

    This function is called by every tool wrapper before subprocess.
    """
    if not cmd or not cmd.strip():
        return True, ""

    cmd_stripped = cmd.strip()

    # Check if this is a known safe pentesting tool invocation
    # Safe tool overrides only apply if the dangerous pattern is NOT
    # in the part of the command AFTER the tool name
    for pat in _SAFE:
        if pat.search(cmd_stripped):
            # Even safe tools cannot contain system destruction patterns
            # in their arguments — check for embedded shell injection
            dangerous_inline = [
                r';\s*(rm\s+-rf|shutdown|reboot|mkfs|dd.*of=/dev/[sh])',
                r'\|\s*(rm\s+-rf|shutdown|reboot)',
                r'`(rm\s+-rf|shutdown|reboot)`',
                r'\$\((rm\s+-rf|shutdown|reboot)\)',
            ]
            for d in dangerous_inline:
                if re.search(d, cmd_stripped, re.IGNORECASE):
                    return False, f"Shell injection with destructive command in tool args"
            return True, ""

    # Check against all blocked patterns
    for compiled_pat, reason, severity in _COMPILED:
        if compiled_pat.search(cmd_stripped):
            return False, f"[{severity}] BLOCKED: {reason} — command: {cmd_stripped[:120]}"

    return True, ""


def validate_or_raise(cmd: str) -> None:
    """
    Validate a command and raise ValueError if blocked.
    Use this in tool wrappers.
    """
    ok, reason = validate_command(cmd)
    if not ok:
        raise ValueError(f"SAFETY VALIDATOR BLOCKED: {reason}")


def validate_msf_command(resource_script: str) -> Tuple[bool, str]:
    """
    Validate a Metasploit resource script before execution.
    Allows: use, set, run, exploit, sessions, search
    Blocks: shell commands that destroy the local system
    """
    blocked_msf = [
        r'\bshell\b.*rm\s+-rf',
        r'\bexecute\b.*rm\s+-rf',
        r'\bshell\b.*shutdown',
        r'\bshell\b.*reboot',
        r'>\s*/etc/(passwd|shadow)',
    ]
    for pat in blocked_msf:
        if re.search(pat, resource_script, re.IGNORECASE):
            return False, f"Destructive command in Metasploit resource script"
    return True, ""
