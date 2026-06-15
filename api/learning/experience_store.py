"""Experience and utility store for BountyOS adaptive planning."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional
from sqlmodel import Session, select
from api.models import ExperienceRecord


class ExperienceStore:
    def record(self, session: Session, action: str, result: str,
               scan_id: Optional[str] = None, context: Optional[dict] = None,
               novelty_reward: float = 0.0, impact_reward: float = 0.0,
               cost_penalty: float = 0.0, false_positive_penalty: float = 0.0) -> ExperienceRecord:
        utility = novelty_reward + impact_reward - cost_penalty - false_positive_penalty
        row = ExperienceRecord(
            scan_id=scan_id, context_json=json.dumps(context or {}, default=str),
            action=action, result=result, utility=utility,
            novelty_reward=novelty_reward, impact_reward=impact_reward,
            cost_penalty=cost_penalty, false_positive_penalty=false_positive_penalty,
        )
        session.add(row); session.commit(); session.refresh(row)
        return row

    def action_prior(self, session: Session, action: str) -> Dict[str, float]:
        rows = session.exec(select(ExperienceRecord).where(ExperienceRecord.action == action)).all()
        if not rows:
            return {"count": 0, "average_utility": 0.0, "success_rate": 0.5}
        avg = sum(r.utility for r in rows) / len(rows)
        successes = sum(1 for r in rows if r.result in {"confirmed", "useful", "completed", "likely"})
        return {"count": len(rows), "average_utility": round(avg, 3), "success_rate": round(successes / len(rows), 3)}

    def list(self, session: Session, scan_id: Optional[str] = None, limit: int = 200) -> List[Dict[str, Any]]:
        q = select(ExperienceRecord)
        if scan_id:
            q = q.where(ExperienceRecord.scan_id == scan_id)
        rows = session.exec(q.order_by(ExperienceRecord.created_at.desc()).limit(limit)).all()
        out = []
        for row in rows:
            item = row.model_dump(mode="json")
            try: item["context"] = json.loads(row.context_json or "{}")
            except Exception: item["context"] = {}
            out.append(item)
        return out

    def summary(self, session: Session) -> Dict[str, Any]:
        rows = session.exec(select(ExperienceRecord)).all()
        by_action: Dict[str, List[float]] = {}
        for row in rows:
            by_action.setdefault(row.action, []).append(row.utility)
        actions = [
            {"action": a, "count": len(vals), "average_utility": round(sum(vals)/len(vals), 3)}
            for a, vals in by_action.items()
        ]
        actions.sort(key=lambda x: x["average_utility"], reverse=True)
        return {"records": len(rows), "actions": actions}


experience_store = ExperienceStore()
