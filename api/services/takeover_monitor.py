from __future__ import annotations
import os, uuid
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel, select
from api.database import session_ctx
from api.models import Target
from api.services.scope_guard import is_target_in_scope, normalize_host
PROVIDERS = ["GitHub Pages","Heroku","AWS S3","Azure Web Apps","Netlify","Vercel","Fastly","Shopify/myshopify","Tumblr","WordPress.com","Ghost","Surge","Readme.io","Zendesk","HubSpot","Intercom","Freshdesk","Bitbucket","GitLab Pages","Wix","Squarespace","Webflow","Fly.io","Render","Railway","Pantheon","Unbounce","Launchrock"]
def utcnow(): return datetime.now(timezone.utc)
def takeover_enabled(): return os.getenv("BOUNTYOS_TAKEOVER_ENABLED","false").lower() in {"1","true","yes","on"}
def verify_tls(): return os.getenv("BOUNTYOS_VERIFY_TLS","true").lower() not in {"0","false","no","off"}
class TakeoverCandidate(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    domain: str
    target_id: Optional[str] = None
    service: Optional[str] = None
    cname: Optional[str] = None
    status: str = "candidate"
    severity: Optional[str] = None
    confidence: float = 0.0
    first_seen: datetime = Field(default_factory=utcnow)
    last_checked: datetime = Field(default_factory=utcnow)
    confirmed: bool = False
    evidence: Optional[str] = None
def scope_guard_domain(domain: str, allowed_roots: list[str]) -> bool: return is_target_in_scope(domain, allowed_roots)
def scan_target_metadata_only(target_id: str):
    if not takeover_enabled(): return {"enabled":False,"detail":"Takeover monitor disabled by BOUNTYOS_TAKEOVER_ENABLED=false"}
    with session_ctx() as s:
        target=s.get(Target,target_id)
        if not target: return {"enabled":True,"error":"target not found"}
        roots=[target.domain]+[x.strip() for x in (target.scope or "").replace(',', '\n').splitlines() if x.strip()]
        root=normalize_host(target.domain)
        if not scope_guard_domain(root, roots): return {"enabled":True,"blocked":True,"reason":"target outside allowed roots"}
        cand=TakeoverCandidate(domain=root,target_id=target_id,status="candidate",evidence="Metadata-only takeover monitor candidate; no claim or destructive action performed.")
        s.add(cand); s.commit(); s.refresh(cand); return cand.model_dump()
