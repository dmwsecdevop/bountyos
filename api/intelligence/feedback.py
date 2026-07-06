"""Feedback management system for agent optimization."""
from __future__ import annotations

import json
from typing import Any, Dict, Optional
from sqlmodel import Session
from api.models import AgentMemory
from api.intelligence.memory import shared_memory

class FeedbackManager:
    def record_feedback(self, session: Session, scan_id: str,
                        finding_id: Optional[str],
                        is_positive: bool,
                        notes: str = "") -> AgentMemory:
        """Records feedback on a finding for agent optimization."""
        kind = "positive_feedback" if is_positive else "negative_feedback"
        metadata = {"finding_id": finding_id, "notes": notes}
        confidence = 1.0 if is_positive else 0.0
        
        return shared_memory.add(
            session=session,
            agent="feedback_agent",
            kind=kind,
            content=f"Feedback on finding {finding_id}: {notes}",
            scan_id=scan_id,
            metadata=metadata,
            confidence=confidence
        )

feedback_manager = FeedbackManager()
