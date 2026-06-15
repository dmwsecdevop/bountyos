"""Evidence capture, redaction and integrity hashing."""
from __future__ import annotations

import hashlib
import json
import re
from typing import Any, Dict, List, Optional
from sqlmodel import Session, select
from api.models import EvidenceArtifact

SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization:\s*(?:bearer|basic)\s+)[^\s]+"),
    re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)[^\s,;\"']+"),
    re.compile(r"(?i)(cookie:\s*)[^\r\n]+"),
]


def redact(text: str) -> str:
    out = text or ""
    for pattern in SECRET_PATTERNS:
        out = pattern.sub(r"\1[REDACTED]", out)
    return out


class EvidenceStore:
    def add(self, session: Session, scan_id: str, title: str, content: str,
            artifact_type: str = "text", validation_attempt_id: Optional[str] = None,
            finding_id: Optional[str] = None, do_redact: bool = True) -> EvidenceArtifact:
        stored = redact(content) if do_redact else content
        digest = hashlib.sha256(stored.encode("utf-8", errors="replace")).hexdigest()
        row = EvidenceArtifact(
            scan_id=scan_id, validation_attempt_id=validation_attempt_id,
            finding_id=finding_id, artifact_type=artifact_type, title=title,
            content=stored, sha256=digest, redacted=do_redact,
        )
        session.add(row); session.commit(); session.refresh(row)
        return row

    def list(self, session: Session, scan_id: str, limit: int = 200) -> List[Dict[str, Any]]:
        rows = session.exec(
            select(EvidenceArtifact).where(EvidenceArtifact.scan_id == scan_id)
            .order_by(EvidenceArtifact.created_at.desc()).limit(limit)
        ).all()
        return [r.model_dump(mode="json") for r in rows]


evidence_store = EvidenceStore()
