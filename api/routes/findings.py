"""
BountyOS - Findings routes
Manage vulnerability findings and human approval gate
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from datetime import datetime
from typing import List

from api.database import get_session
from api.models import Finding, FindingUpdate, Approval, ApprovalDecision, ApprovalStatus

# ─── Findings ─────────────────────────────────────────────────────────────────

findings_router = APIRouter(prefix="/findings", tags=["findings"])


@findings_router.get("/", response_model=List[Finding])
def list_findings(severity: str = None, session: Session = Depends(get_session)):
    q = select(Finding)
    if severity:
        q = q.where(Finding.severity == severity)
    return session.exec(q.order_by(Finding.created_at.desc())).all()


@findings_router.get("/{finding_id}", response_model=Finding)
def get_finding(finding_id: str, session: Session = Depends(get_session)):
    f = session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    return f


@findings_router.patch("/{finding_id}", response_model=Finding)
def update_finding(finding_id: str, data: FindingUpdate,
                   session: Session = Depends(get_session)):
    f = session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(f, k, v)
    session.add(f)
    session.commit()
    session.refresh(f)
    return f


@findings_router.delete("/{finding_id}", status_code=204)
def delete_finding(finding_id: str, session: Session = Depends(get_session)):
    f = session.get(Finding, finding_id)
    if not f:
        raise HTTPException(404, "Finding not found")
    session.delete(f)
    session.commit()


# ─── Approvals ────────────────────────────────────────────────────────────────

approvals_router = APIRouter(prefix="/approvals", tags=["approvals"])


@approvals_router.get("/", response_model=List[Approval])
def list_approvals(status: str = None, session: Session = Depends(get_session)):
    q = select(Approval)
    if status:
        q = q.where(Approval.status == status)
    return session.exec(q.order_by(Approval.created_at.desc())).all()


@approvals_router.get("/pending", response_model=List[Approval])
def pending_approvals(session: Session = Depends(get_session)):
    return session.exec(
        select(Approval).where(Approval.status == ApprovalStatus.PENDING)
        .order_by(Approval.created_at)
    ).all()


@approvals_router.post("/{approval_id}/decide", response_model=Approval)
def decide_approval(approval_id: str, decision: ApprovalDecision,
                    session: Session = Depends(get_session)):
    a = session.get(Approval, approval_id)
    if not a:
        raise HTTPException(404, "Approval not found")
    if a.status != ApprovalStatus.PENDING:
        raise HTTPException(400, f"Already decided: {a.status}")
    a.status = decision.status
    a.decided_at = datetime.utcnow()
    session.add(a)
    session.commit()
    session.refresh(a)
    return a
