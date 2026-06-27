"""
BountyOS - Findings routes
Manage vulnerability findings and human approval gate
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from datetime import datetime
from typing import List, Dict, Any, Optional

from api.database import get_session
from api.models import Finding, FindingUpdate, Approval, ApprovalDecision, ApprovalStatus

# ─── Findings ──────────────────────────────────────────────────────────────────

findings_router = APIRouter(prefix="/findings", tags=["findings"])


@findings_router.get("/", response_model=List[Finding])
def list_findings(
    severity: Optional[str] = None,
    session: Session = Depends(get_session),
) -> List[Finding]:
    """List all findings, optionally filtered by severity."""
    query = select(Finding)
    if severity:
        query = query.where(Finding.severity == severity)
    return session.exec(query.order_by(Finding.created_at.desc())).all()


@findings_router.get("/{finding_id}", response_model=Finding)
def get_finding(
    finding_id: str,
    session: Session = Depends(get_session),
) -> Finding:
    """Get a specific finding by ID."""
    finding_obj = session.get(Finding, finding_id)
    if not finding_obj:
        raise HTTPException(status_code=404, detail="Finding not found")
    return finding_obj


@findings_router.patch("/{finding_id}", response_model=Finding)
def update_finding(
    finding_id: str,
    data: FindingUpdate,
    session: Session = Depends(get_session),
) -> Finding:
    """Update a finding."""
    finding_obj = session.get(Finding, finding_id)
    if not finding_obj:
        raise HTTPException(status_code=404, detail="Finding not found")
    for key, value in data.model_dump(exclude_unset=True).items():
        setattr(finding_obj, key, value)
    session.add(finding_obj)
    session.commit()
    session.refresh(finding_obj)
    return finding_obj


@findings_router.delete("/{finding_id}", status_code=204)
def delete_finding(
    finding_id: str,
    session: Session = Depends(get_session),
) -> None:
    """Delete a finding."""
    finding_obj = session.get(Finding, finding_id)
    if not finding_obj:
        raise HTTPException(status_code=404, detail="Finding not found")
    session.delete(finding_obj)
    session.commit()


# ─── Approvals ──────────────────────────────────────────────────────────────────

approvals_router = APIRouter(prefix="/approvals", tags=["approvals"])


@approvals_router.get("/", response_model=List[Approval])
def list_approvals(
    status: Optional[str] = None,
    session: Session = Depends(get_session),
) -> List[Approval]:
    """List all approvals, optionally filtered by status."""
    query = select(Approval)
    if status:
        query = query.where(Approval.status == status)
    return session.exec(query.order_by(Approval.created_at.desc())).all()


@approvals_router.get("/pending", response_model=List[Approval])
def pending_approvals(
    session: Session = Depends(get_session),
) -> List[Approval]:
    """Get all pending approvals."""
    return session.exec(
        select(Approval)
        .where(Approval.status == ApprovalStatus.PENDING)
        .order_by(Approval.created_at)
    ).all()


@approvals_router.post("/{approval_id}/decide", response_model=Approval)
def decide_approval(
    approval_id: str,
    decision: ApprovalDecision,
    session: Session = Depends(get_session),
) -> Approval:
    """Make a decision on an approval request."""
    approval_obj = session.get(Approval, approval_id)
    if not approval_obj:
        raise HTTPException(status_code=404, detail="Approval not found")
    if approval_obj.status != ApprovalStatus.PENDING:
        raise HTTPException(
            status_code=400,
            detail=f"Already decided: {approval_obj.status}",
        )
    approval_obj.status = decision.status
    approval_obj.decided_at = datetime.utcnow()
    session.add(approval_obj)
    session.commit()
    session.refresh(approval_obj)
    return approval_obj
