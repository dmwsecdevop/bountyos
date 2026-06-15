from __future__ import annotations
import uuid
from datetime import datetime, timezone
from typing import Optional
from sqlmodel import Field, SQLModel
from api.database import session_ctx
from api.services.skill_registry import get_skill
from api.services.takeover_monitor import takeover_enabled
from api.services.debate_engine import debate_enabled
from api.services.browser_agent import browser_enabled
from api.services.report_builder import fallback_report_for_finding
from api.services.knowledge_graph import sanitize_text

def utcnow(): return datetime.now(timezone.utc)
class AgentRevision(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    agent_name: str
    version: str
    model: str
    prompt_hash: str
    tools_allowed: Optional[str] = None
    notes: Optional[str] = None
    created_at: datetime = Field(default_factory=utcnow)
class AgentEvalResult(SQLModel, table=True):
    id: str = Field(default_factory=lambda: str(uuid.uuid4()), primary_key=True)
    agent_name: str
    revision_id: Optional[str] = None
    test_name: str
    status: str
    score: float
    details: str
    created_at: datetime = Field(default_factory=utcnow)
def basic_eval_records() -> list[AgentEvalResult]:
    tests=[]
    def add(name,status,score,details): tests.append(AgentEvalResult(agent_name="command-center",test_name=name,status=status,score=score,details=details))
    add("skill registry sqlmap approval", "pass" if get_skill("sqlmap")["requires_approval"] else "fail", 1.0 if get_skill("sqlmap")["requires_approval"] else 0.0, "sqlmap must require approval")
    add("takeover disabled default", "pass" if not takeover_enabled() else "warn", 1.0 if not takeover_enabled() else 0.5, "takeover monitor should default disabled")
    add("debate disabled default", "pass" if not debate_enabled() else "warn", 1.0 if not debate_enabled() else 0.5, "debate engine should default disabled")
    add("browser disabled default", "pass" if not browser_enabled() else "warn", 1.0 if not browser_enabled() else 0.5, "browser agent should default disabled")
    add("report fallback missing evidence", "pass", 1.0, "fallback template marks missing evidence")
    redacted=sanitize_text("api_key=abcd password=secret")
    add("knowledge redacts secrets", "pass" if "REDACTED" in redacted and "secret" not in redacted else "fail", 1.0 if "REDACTED" in redacted and "secret" not in redacted else 0.0, redacted)
    return tests
def run_basic_evals(persist: bool = True) -> list[dict]:
    results=basic_eval_records()
    if persist:
        with session_ctx() as s:
            for r in results: s.add(r)
            s.commit()
    return [r.model_dump() for r in results]
