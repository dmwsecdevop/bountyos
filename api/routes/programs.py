"""Bounty Program Radar routes."""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlmodel import Session, select

from api.database import get_session
from api.models import BountyProgram
from api.agents.program_radar import radar
from api.agents.opportunity_scorer import opportunity_scorer

router = APIRouter(prefix="/programs", tags=["program-radar"])


class CheckProgramsRequest(BaseModel):
    max_programs: int = 500


class AddTargetsRequest(BaseModel):
    limit: int = 25


@router.get("/sources")
def sources():
    return {"sources": radar.sources()}


@router.get("/")
def list_programs(platform: Optional[str] = None, bounty_only: bool = False, limit: int = 100, session: Session = Depends(get_session)):
    q = select(BountyProgram).order_by(BountyProgram.value_score.desc(), BountyProgram.last_seen_at.desc())
    if platform:
        q = select(BountyProgram).where(BountyProgram.platform == platform).order_by(BountyProgram.value_score.desc(), BountyProgram.last_seen_at.desc())
    programs = session.exec(q).all()
    if bounty_only:
        programs = [p for p in programs if p.offers_bounty]
    return [p.model_dump(mode="json") for p in programs[: max(1, min(limit, 500))]]


@router.get("/snapshot")
def snapshot(session: Session = Depends(get_session)):
    programs = session.exec(select(BountyProgram).order_by(BountyProgram.value_score.desc(), BountyProgram.last_seen_at.desc())).all()
    bounty = [p for p in programs if p.offers_bounty]
    platforms = {}
    for p in programs:
        platforms[p.platform] = platforms.get(p.platform, 0) + 1
    return {
        "total_programs": len(programs),
        "bounty_programs": len(bounty),
        "platforms": platforms,
        "top_programs": [p.model_dump(mode="json") for p in programs[:20]],
        "recent_changes": [p.model_dump(mode="json") for p in sorted(programs, key=lambda x: x.last_changed_at or x.created_at, reverse=True)[:20]],
        "sources": radar.sources(),
    }


@router.post("/check")
def check_programs(req: CheckProgramsRequest, session: Session = Depends(get_session)):
    try:
        return radar.check_sources(session, max_programs=max(1, min(req.max_programs, 2000)))
    except Exception as exc:
        raise HTTPException(500, str(exc))


@router.get("/opportunities")
def opportunities(platform: Optional[str] = None, bounty_only: bool = True, limit: int = 20, session: Session = Depends(get_session)):
    """Rank stored programs by likely effort vs bounty upside."""
    programs = session.exec(select(BountyProgram).order_by(BountyProgram.value_score.desc(), BountyProgram.last_seen_at.desc())).all()
    return {
        "message": "Opportunity ranking is a probability estimate, not a bounty guarantee.",
        "platform": platform,
        "bounty_only": bounty_only,
        "opportunities": opportunity_scorer.rank(programs, platform=platform, bounty_only=bounty_only, limit=limit),
    }


@router.get("/recommend-easy")
def recommend_easy(platform: Optional[str] = None, limit: int = 5, session: Session = Depends(get_session)):
    """Return easiest/highest-upside programs from stored radar/account data."""
    programs = session.exec(select(BountyProgram).order_by(BountyProgram.value_score.desc(), BountyProgram.last_seen_at.desc())).all()
    ranked = opportunity_scorer.rank(programs, platform=platform, bounty_only=True, limit=max(1, min(limit, 25)))
    return {
        "message": "Best low-effort/high-upside candidates. No target can be guaranteed to pay.",
        "platform": platform,
        "count": len(ranked),
        "recommendations": ranked,
    }


@router.get("/{program_id}/opportunity")
def program_opportunity(program_id: str, session: Session = Depends(get_session)):
    program = session.get(BountyProgram, program_id)
    if not program:
        raise HTTPException(404, "Program not found")
    return opportunity_scorer.score(program).as_dict()


@router.get("/{program_id}")
def get_program(program_id: str, session: Session = Depends(get_session)):
    program = session.get(BountyProgram, program_id)
    if not program:
        raise HTTPException(404, "Program not found")
    return program.model_dump(mode="json")


@router.post("/{program_id}/add-targets")
def add_targets(program_id: str, req: AddTargetsRequest, session: Session = Depends(get_session)):
    try:
        return radar.add_program_targets(session, program_id, limit=max(1, min(req.limit, 200)))
    except ValueError as exc:
        raise HTTPException(404, str(exc))
