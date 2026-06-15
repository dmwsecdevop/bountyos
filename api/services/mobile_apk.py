from __future__ import annotations
import json, uuid
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel

def utcnow(): return datetime.now(timezone.utc)
class APKAnalysis(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    filename: str
    status: str = "metadata_recorded"
    package_name: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    permissions: Optional[str] = None
    exported_components: Optional[str] = None
    findings: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
CAPABILITIES=["manifest analysis","permissions review","exported activities/services/receivers","deep link checks","Firebase config leak checks","hardcoded secret scan","WebView risk checklist","backup/debuggable flag checks","JADX/APKTool integration planned","ADB/Frida checklist planned"]
def capabilities(): return {"enabled":True,"mode":"static metadata only","capabilities":CAPABILITIES,"safety":"Does not run adb or frida by default."}
def to_json(value): return json.dumps(value or [])
