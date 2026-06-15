from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Optional

@dataclass(frozen=True)
class Skill:
    name: str
    display_name: str
    category: str
    phase: str
    risk_level: str
    passive_safe: bool
    requires_approval: bool
    local_command: Optional[str]
    remote_supported: bool
    description: str
    expected_outputs: list[str]
    ui_badge: str
    enabled_by_default: bool = True


def _skill(name, category, phase="recon", risk="low", passive=True, approval=False, cmd=None, remote=True, desc="", outputs=None, badge=None, enabled=True):
    return Skill(name, name.replace("_", " ").title(), category, phase, risk, passive, approval, cmd, remote, desc or f"Metadata for {name}; registry does not execute tools.", outputs or [], badge or category, enabled)

_SKILLS = [
    # Recon/passive
    _skill("subfinder","recon/passive",cmd="subfinder",outputs=["subdomains"]), _skill("amass","recon/passive",cmd="amass",outputs=["subdomains"]),
    _skill("assetfinder","recon/passive",cmd="assetfinder",outputs=["subdomains"]), _skill("dnsx","recon/passive",cmd="dnsx",outputs=["dns records"]),
    _skill("httpx","recon/passive",cmd="httpx",outputs=["live hosts"]), _skill("naabu","recon/passive",risk="medium",cmd="naabu",outputs=["open ports"]),
    _skill("gau","recon/passive",cmd="gau",outputs=["urls"]), _skill("waybackurls","recon/passive",cmd="waybackurls",outputs=["archived urls"]),
    _skill("katana","recon/passive",cmd="katana",outputs=["crawled urls"]), _skill("hakrawler","recon/passive",cmd="hakrawler",outputs=["links"]),
    _skill("whatweb","recon/passive",cmd="whatweb",outputs=["technologies"]), _skill("wafw00f","recon/passive",cmd="wafw00f",outputs=["waf types"]),
    _skill("whois","recon/passive",cmd="whois",outputs=["registration data"]), _skill("dig","recon/passive",cmd="dig",outputs=["dns records"]),
    _skill("crtsh_lookup","recon/passive",cmd=None,outputs=["certificate subdomains"]), _skill("github_dork_passive","recon/passive",cmd=None,outputs=["public code references"]),
    _skill("js_link_finder","recon/passive",cmd=None,outputs=["javascript endpoints"]),
    # Scanning/validation
    _skill("nuclei","scanning/validation","vulnscan","high",False,True,"nuclei",outputs=["template findings"],badge="approval"),
    _skill("ffuf","scanning/validation","vulnscan","high",False,True,"ffuf",outputs=["content discovery"],badge="approval"),
    _skill("feroxbuster","scanning/validation","vulnscan","medium",False,False,"feroxbuster",outputs=["content discovery"]),
    _skill("dirsearch","scanning/validation","vulnscan","medium",False,False,"dirsearch",outputs=["content discovery"]),
    _skill("dalfox","scanning/validation","vulnscan","high",False,True,"dalfox",outputs=["xss validation"],badge="approval"),
    _skill("sqlmap","scanning/validation","exploit","critical",False,True,"sqlmap",outputs=["sqli validation"],badge="approval"),
    _skill("nmap","scanning/validation","vulnscan","high",False,True,"nmap",outputs=["ports/services"],badge="approval"),
    _skill("testssl","scanning/validation","vulnscan","medium",True,False,"testssl",outputs=["tls issues"]),
    _skill("nikto","scanning/validation","vulnscan","medium",False,False,"nikto",outputs=["web server issues"]),
    # Cloud/misconfig
    _skill("s3_bucket_checks","cloud/misconfig","vulnscan","medium",True,False,None,outputs=["bucket exposure"]),
    _skill("firebase_checks","cloud/misconfig","vulnscan","medium",True,False,None,outputs=["firebase risks"]),
    _skill("cors_checks","cloud/misconfig","vulnscan","medium",True,False,None,outputs=["cors findings"]),
    _skill("takeover_monitor","cloud/misconfig","recon","medium",True,False,None,outputs=["takeover candidates"],enabled=False),
    # Mobile
    _skill("apktool","mobile","mobile","low",True,False,"apktool",outputs=["manifest/resources"]), _skill("jadx","mobile","mobile","low",True,False,"jadx",outputs=["decompiled code"]),
    _skill("mobsf_import","mobile","mobile","low",True,False,None,outputs=["imported static findings"]), _skill("adb","mobile","mobile","high",False,True,"adb",outputs=["device observations"],badge="approval"),
    _skill("frida_checklist","mobile","mobile","critical",False,True,"frida",outputs=["dynamic checklist"],badge="approval"),
    # Reporting/AI
    _skill("report_generator","reporting/ai","reporting","low",True,False,None,outputs=["bounty report"]), _skill("debate_engine","reporting/ai","review","low",True,False,None,outputs=["debate records"],enabled=False),
    _skill("knowledge_graph","reporting/ai","memory","low",True,False,None,outputs=["agent context"]), _skill("severity_calculator","reporting/ai","reporting","low",True,False,None,outputs=["severity estimate"]),
]
SKILLS = {s.name: s for s in _SKILLS}

def all_skills() -> list[dict]: return [asdict(s) for s in _SKILLS]
def get_skill(name: str) -> dict | None:
    s = SKILLS.get(name); return asdict(s) if s else None
def categories() -> list[str]: return sorted({s.category for s in _SKILLS})
def passive_skills() -> list[dict]: return [asdict(s) for s in _SKILLS if s.passive_safe]
def approval_required_skills() -> list[dict]: return [asdict(s) for s in _SKILLS if s.requires_approval]
def requires_approval(name: str) -> bool: return bool(SKILLS.get(name) and SKILLS[name].requires_approval)
def skill_count() -> int: return len(_SKILLS)
