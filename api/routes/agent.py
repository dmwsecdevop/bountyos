"""Chat/voice tool command route for BountyOS Architect Agent."""

from __future__ import annotations

from typing import Optional
from fastapi import APIRouter, Depends, BackgroundTasks, HTTPException
from pydantic import BaseModel
from sqlmodel import Session

from api.database import get_session
from api.agents.architect_agent import ArchitectAgent
from api.agents.model_router import router as model_router

router = APIRouter(prefix="/agent", tags=["agent"])
agent = ArchitectAgent()


class AgentCommandRequest(BaseModel):
    transcript: str
    selected_target_id: Optional[str] = None
    selected_scan_id: Optional[str] = None
    approve: bool = False
    source: str = "chat"  # chat | voice | api


@router.get("/capabilities")
def capabilities():
    return {
        "name": "BountyOS Architect Agent",
        "architecture": "Observe -> Reason -> Think -> Act",
        "can_run": [
            "passive recon",
            "approved aggressive scan",
            "AI bug reasoning / hacker mindset analysis",
            "show findings",
            "show scans/status",
            "show targets",
            "cancel scan",
            "check online bug bounty programs",
            "connect/sync bounty accounts",
            "show private/invited programs where API permissions allow",
            "show stored bounty programs",
            "import program scope as targets",
            "rank easy/high-upside bounty programs with Opportunity Scorer",
            "answer general chat questions",
            "live data: USD/currency, BTC/ETH, recent CVEs, public IP",
            "full Hunter workflow: graph -> hypotheses -> adaptive plan -> validation -> evidence -> report",
            "attack-surface graph and shared specialist memory",
            "controlled validation attempts with approval and dry-run",
            "bounty-ready Markdown/JSON/HTML reports",
            "parse bug bounty target pages and extract scope/rules/rewards/tech",
        ],
        "model_routing": {
            "local_recon_expert": "recon/status/dashboard/program-radar commands",
            "light_triage_expert": "simple Q&A and command parsing",
            "bug_reasoning_expert": "post-scan bug/finding analysis",
            "exploit_validation_expert": "approved active validation planning",
            "bounty_account_hub_expert": "connected bounty account sync/private invite import",
            "program_opportunity_expert": "rank programs by effort vs reward; no guarantee of bounty",
        },
    }


@router.get("/model-route")
def model_route(q: str = "", action: str = "", has_scan_context: bool = False):
    return model_router.route(q, action, has_scan_context).as_dict()


@router.post("/command")
async def command(req: AgentCommandRequest, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    if not req.transcript.strip():
        raise HTTPException(400, "Transcript is empty")
    try:
        return await agent.handle(
            session=session,
            background_tasks=background_tasks,
            transcript=req.transcript,
            selected_target_id=req.selected_target_id,
            selected_scan_id=req.selected_scan_id,
            approve=req.approve,
        )
    except ValueError as e:
        raise HTTPException(400, str(e))


@router.post("/voice-command")
async def voice_command(req: AgentCommandRequest, background_tasks: BackgroundTasks, session: Session = Depends(get_session)):
    req.source = "voice"
    return await command(req, background_tasks, session)
