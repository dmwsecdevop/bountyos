from __future__ import annotations
import os, uuid
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel

def utcnow(): return datetime.now(timezone.utc)
def browser_enabled(): return os.getenv("BOUNTYOS_BROWSER_AGENT_ENABLED","false").lower() in {"1","true","yes","on"}
class BrowserSession(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    target_id: Optional[str] = None
    url: str
    status: str = "metadata_only"
    created_at: datetime = Field(default_factory=utcnow)
    notes: Optional[str] = None
CAPABILITIES=["console inspection","network request capture","screenshot evidence","CORS issue detection","JS endpoint extraction","auth flow observation"]
def capabilities(): return {"enabled":browser_enabled(),"mode":"metadata-only","capabilities":CAPABILITIES,"safety":"No navigation or browser automation is executed; future navigation must pass scope validation."}
