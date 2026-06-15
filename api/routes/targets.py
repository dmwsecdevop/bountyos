"""
BountyOS - Targets routes
CRUD for bug bounty targets + scope management
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlmodel import Session, select
from typing import List

from api.database import get_session
from api.models import Target, TargetCreate

router = APIRouter(prefix="/targets", tags=["targets"])


@router.get("/", response_model=List[Target])
def list_targets(session: Session = Depends(get_session)):
    return session.exec(select(Target).order_by(Target.created_at.desc())).all()


@router.post("/", response_model=Target, status_code=201)
def create_target(data: TargetCreate, session: Session = Depends(get_session)):
    target = Target(**data.model_dump())
    session.add(target)
    session.commit()
    session.refresh(target)
    return target


@router.get("/{target_id}", response_model=Target)
def get_target(target_id: str, session: Session = Depends(get_session)):
    t = session.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    return t


@router.patch("/{target_id}", response_model=Target)
def update_target(target_id: str, data: TargetCreate,
                  session: Session = Depends(get_session)):
    t = session.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    for k, v in data.model_dump(exclude_unset=True).items():
        setattr(t, k, v)
    session.add(t)
    session.commit()
    session.refresh(t)
    return t


@router.delete("/{target_id}", status_code=204)
def delete_target(target_id: str, session: Session = Depends(get_session)):
    t = session.get(Target, target_id)
    if not t:
        raise HTTPException(404, "Target not found")
    session.delete(t)
    session.commit()
