"""IDOR cross-correlation and session management service."""

from typing import Dict, List, Optional
from api.models import SessionState
from api.database import session_ctx

class IDORCorrelator:
    """Service to track and manipulate multi-user session parameters."""
    
    def register_session(self, scan_id: str, user_id: str, token: str, metadata: Dict = None):
        with session_ctx() as s:
            session = SessionState(
                scan_id=scan_id,
                user_id=user_id,
                session_token=token,
                metadata_json=str(metadata or {})
            )
            s.add(session)
            s.commit()

    def get_sessions(self, scan_id: str) -> List[SessionState]:
        with session_ctx() as s:
            from sqlmodel import select
            return s.exec(select(SessionState).where(SessionState.scan_id == scan_id)).all()

    def generate_idor_payloads(self, scan_id: str, target_param: str) -> List[Dict[str, str]]:
        # Logic to return swapped session tokens/parameters for IDOR testing
        sessions = self.get_sessions(scan_id)
        if len(sessions) < 2:
            return []
        
        # Example logic: pair sessions
        return [{"param": target_param, "value": s.session_token} for s in sessions]

idor_correlator = IDORCorrelator()
