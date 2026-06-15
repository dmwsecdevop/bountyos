"""Shared, durable memory for specialist agents."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from sqlmodel import Session, select
from api.models import AgentMemory


class SharedMemory:
    def add(self, session: Session, agent: str, kind: str, content: str,
            scan_id: Optional[str] = None, metadata: Optional[dict] = None,
            confidence: float = 0.5) -> AgentMemory:
        row = AgentMemory(
            scan_id=scan_id, agent=agent, kind=kind, content=content,
            metadata_json=json.dumps(metadata or {}, default=str), confidence=confidence,
        )
        session.add(row); session.commit(); session.refresh(row)
        return row

    def list(self, session: Session, scan_id: Optional[str] = None,
             kind: Optional[str] = None, agent: Optional[str] = None,
             limit: int = 200) -> List[Dict[str, Any]]:
        q = select(AgentMemory)
        if scan_id:
            q = q.where(AgentMemory.scan_id == scan_id)
        if kind:
            q = q.where(AgentMemory.kind == kind)
        if agent:
            q = q.where(AgentMemory.agent == agent)
        rows = session.exec(q.order_by(AgentMemory.created_at.desc()).limit(limit)).all()
        result = []
        for row in rows:
            item = row.model_dump(mode="json")
            try: item["metadata"] = json.loads(row.metadata_json or "{}")
            except Exception: item["metadata"] = {}
            result.append(item)
        return result

    def summary(self, session: Session, scan_id: str) -> Dict[str, Any]:
        rows = self.list(session, scan_id=scan_id, limit=500)
        by_agent: Dict[str, int] = {}
        by_kind: Dict[str, int] = {}
        for row in rows:
            by_agent[row["agent"]] = by_agent.get(row["agent"], 0) + 1
            by_kind[row["kind"]] = by_kind.get(row["kind"], 0) + 1
        return {"total": len(rows), "by_agent": by_agent, "by_kind": by_kind, "recent": rows[:20]}


shared_memory = SharedMemory()
