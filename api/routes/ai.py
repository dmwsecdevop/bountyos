"""
BountyOS - AI routes (Phase 2)

Two endpoints:
  POST /ai/chat          — free-form security Q&A with context injection
  POST /ai/analyze/{id}  — manually trigger AI coordinator on a completed scan
"""

import os
import json
import logging
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlmodel import Session, select
from pydantic import BaseModel
from typing import Optional, List
from api.ai import AIProviderError, get_ai_client, provider_status

from api.database import get_session, session_ctx
from api.models import Scan, Target, Finding, ScanEvent, ScanPhase, ScanStatus
from api.agents.coordinator import run_ai_coordinator
from api.agents.live_data_agent import live_data_agent
from api.integrations.gemini_client import GeminiClient

router = APIRouter(prefix="/ai", tags=["ai"])
logger = logging.getLogger(__name__)

_client = get_ai_client()
MODEL   = os.getenv("BOUNTYOS_MAIN_MODEL", "gemini-2.5-pro")


# ─── Schemas ──────────────────────────────────────────────────────────────────

class ChatMessage(BaseModel):
    role:    str          # "user" | "assistant"
    content: str

class ChatRequest(BaseModel):
    scan_id:  Optional[str]       = None    # inject scan context if provided
    messages: List[ChatMessage]
    system:   Optional[str]       = None    # optional system override

class AnalyzeRequest(BaseModel):
    max_iterations: int = 20
    skip_vuln_gate: bool = False            # skip approval gate for all steps


# ─── Context builder ─────────────────────────────────────────────────────────

def _build_scan_context(scan_id: str, session: Session) -> str:
    """Produce a compact text summary of a scan to inject into the chat system prompt."""
    scan = session.get(Scan, scan_id)
    if not scan:
        return ""

    target = session.get(Target, scan.target_id)
    findings = session.exec(
        select(Finding).where(Finding.scan_id == scan_id)
        .order_by(Finding.created_at.desc())
    ).all()

    lines = [
        f"=== SCAN CONTEXT: {scan_id} ===",
        f"Target: {target.domain if target else 'unknown'}",
        f"Scope: {target.scope if target else 'unknown'}",
        f"Status: {scan.status} | Phase: {scan.phase}",
        f"Findings ({len(findings)} total):",
    ]
    for f in findings[:30]:  # cap at 30 to stay within context
        lines.append(f"  [{f.severity.upper()}] {f.title} (tool: {f.tool})")

    return "\n".join(lines)




def _last_user_text(messages: List[ChatMessage]) -> str:
    for m in reversed(messages):
        if m.role == "user":
            return m.content
    return ""


# ─── Routes ───────────────────────────────────────────────────────────────────

@router.get("/models")
def get_model_config():
    """Return the non-secret Gemini/Vertex model routing configuration."""
    vertex = os.getenv("GOOGLE_GENAI_USE_VERTEXAI", "false").strip().lower()
    return {
        "provider": os.getenv("BOUNTYOS_AI_PROVIDER", "gemini"),
        "main_model": os.getenv("BOUNTYOS_MAIN_MODEL", "gemini-2.5-pro"),
        "light_model": os.getenv("BOUNTYOS_LIGHT_MODEL", "gemini-2.5-flash-lite"),
        "recon_model": os.getenv("BOUNTYOS_RECON_MODEL", "gemini-2.5-flash"),
        "aggressive_model": os.getenv("BOUNTYOS_AGGRESSIVE_MODEL", "gemini-2.5-pro"),
        "exploit_model": os.getenv("BOUNTYOS_EXPLOIT_MODEL", "gemini-2.5-pro"),
        "vertex": vertex in {"1", "true", "yes", "on"},
    }


@router.post("/chat")
async def ai_chat(req: ChatRequest, session: Session = Depends(get_session)):
    """
    Free-form security Q&A. Optionally injects scan context so operators
    can ask questions like "what are the most critical findings?" or
    "suggest a PoC for the SQLi finding".
    """
    system_parts = [
        "You are BountyOS AI — a senior penetration testing assistant. "
        "Answer concisely and technically. Format findings in Markdown.",
    ]

    if req.scan_id:
        ctx = _build_scan_context(req.scan_id, session)
        if ctx:
            system_parts.append(ctx)

    if req.system:
        system_parts.append(req.system)

    system_prompt = "\n\n".join(system_parts)

    from api.agents.model_router import router as moe_router
    user_text = _last_user_text(req.messages)
    selected = moe_router.route(user_text, "chat", has_scan_context=bool(req.scan_id))

    # Live/current questions must use live-data connectors instead of model guessing.
    if selected.expert == "live_data_expert" or live_data_agent.detect(user_text):
        live = live_data_agent.answer(user_text)
        return {
            "response": live.answer,
            "model_route": selected.as_dict(),
            "input_tokens": 0,
            "output_tokens": 0,
            "local": True,
            "live_data": live.as_dict(),
        }

    model = selected.model
    if selected.provider in ("local", "tool"):
        model = os.getenv("BOUNTYOS_LIGHT_MODEL", "gemini-2.5-flash-lite")
    if selected.expert == "local_recon_expert":
        model = os.getenv("BOUNTYOS_RECON_MODEL", "gemini-2.5-flash")
    if not model:
        model = MODEL

    try:
        gemini = GeminiClient()
        ai = await gemini.chat(
            [{"role": m.role, "content": m.content} for m in req.messages],
            context={"system": system_prompt, "scan_context": ctx if req.scan_id else "", "model_route": selected.as_dict()},
            model=model,
        )
        return {
            "response": ai.text,
            "provider": ai.provider,
            "model": ai.model,
            "model_route": selected.as_dict(),
        }
    except Exception as e:
        raise HTTPException(502, str(e))


@router.post("/analyze/{scan_id}")
def trigger_analysis(
    scan_id: str,
    req: AnalyzeRequest,
    background_tasks: BackgroundTasks,
    session: Session = Depends(get_session),
):
    """
    Manually kick off the AI coordinator on an existing scan.
    Useful when you want to re-run the AI phase after adding more findings,
    or when a scan was started with skip_ai=true.
    """
    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    target = session.get(Target, scan.target_id)
    if not target:
        raise HTTPException(404, "Target not found for this scan")

    if scan.status == ScanStatus.RUNNING and scan.phase == ScanPhase.EXPLOIT:
        raise HTTPException(409, "AI analysis already running for this scan")

    # Update to exploit phase
    scan.phase  = ScanPhase.EXPLOIT
    scan.status = ScanStatus.RUNNING
    session.add(scan)
    session.commit()

    background_tasks.add_task(
        run_ai_coordinator,
        scan_id=scan_id,
        target_domain=target.domain,
        scope=target.scope,
        out_of_scope=target.out_of_scope,
        max_iterations=req.max_iterations,
    )

    return {"detail": "AI analysis started", "scan_id": scan_id}


@router.get("/scan/{scan_id}/summary")
def get_ai_summary(scan_id: str, session: Session = Depends(get_session)):
    """
    Returns a quick AI-generated summary of the scan — severity breakdown,
    top findings, and recommended remediation priority.
    """
    ctx = _build_scan_context(scan_id, session)
    if not ctx:
        raise HTTPException(404, "Scan not found")

    try:
        response = _client.messages.create(
            model=MODEL,
            max_tokens=1024,
            system="You are a penetration testing report writer. Be concise, precise, and technical.",
            messages=[
                {
                    "role": "user",
                    "content": (
                        f"{ctx}\n\n"
                        "Produce a concise executive summary of this scan: "
                        "overall risk rating, top 3 critical findings, "
                        "and immediate remediation actions. Use Markdown."
                    ),
                }
            ],
        )
        text = "".join(b.text for b in response.content if b.type == "text")
        return {"summary": text, "scan_id": scan_id}
    except AIProviderError as e:
        raise HTTPException(502, str(e))



@router.get("/provider")
def get_provider_status():
    """Return the active AI provider and model routing configuration."""
    return provider_status()


@router.post("/provider/test")
def test_provider():
    """Make a minimal Gemini request using the configured runtime identity."""
    status = provider_status()
    model = status["light_model"]
    try:
        response = _client.messages.create(
            model=model,
            max_tokens=64,
            system="You are the BountyOS provider health check.",
            messages=[{"role": "user", "content": "Reply with exactly: Gemini connection working"}],
        )
        text = "".join(
            block.text for block in response.content if block.type == "text"
        ).strip()
        return {"ok": True, "response": text, "provider": status}
    except AIProviderError as exc:
        raise HTTPException(502, str(exc))

# ─── Hacker mindset endpoints ─────────────────────────────────────────────────

@router.get("/mindset/questions/{phase}")
def get_mindset_questions(phase: str):
    """Return the expert hacker questions for a given phase."""
    from api.agents.hacker_mindset import HACKER_QUESTIONS
    questions = HACKER_QUESTIONS.get(phase, HACKER_QUESTIONS.get("recon", []))
    return {"phase": phase, "questions": questions}


@router.get("/mindset/playbook/{technology}")
def get_playbook(technology: str):
    """Return the attack playbook for a specific technology."""
    from api.agents.hacker_mindset import get_technology_playbook, TECHNOLOGY_PLAYBOOKS
    playbook = get_technology_playbook(technology)
    return {
        "technology":        technology,
        "playbook":          playbook or "No specific playbook for this technology.",
        "available_techs":   list(TECHNOLOGY_PLAYBOOKS.keys()),
    }


@router.get("/mindset/technologies/{scan_id}")
def detect_technologies(scan_id: str, session: Session = Depends(get_session)):
    """Detect technologies from a scan's events and return relevant playbooks."""
    from sqlmodel import select as sel
    from api.models import ScanEvent
    from api.agents.hacker_mindset import infer_technologies_from_events, get_technology_playbook

    events = session.exec(sel(ScanEvent).where(ScanEvent.scan_id == scan_id)).all()
    ev_dicts = [{"message": e.message, "raw": e.raw or ""} for e in events]
    techs = infer_technologies_from_events(ev_dicts)

    return {
        "scan_id":      scan_id,
        "detected":     techs,
        "playbooks":    {t: get_technology_playbook(t) for t in techs},
    }


@router.post("/mindset/analyze/{scan_id}")
def analyze_with_mindset(scan_id: str, session: Session = Depends(get_session)):
    """
    Run a quick AI analysis using the hacker mindset framework.
    Returns targeted questions and attack hypotheses for the current scan state.
    """
    from api.agents.hacker_mindset import (
        get_hacker_mindset_prompt, infer_technologies_from_events,
        BUSINESS_LOGIC_PATTERNS, TRUST_ABUSE_PATTERNS
    )
    from sqlmodel import select as sel
    from api.models import ScanEvent, Finding, Target, Scan

    scan = session.get(Scan, scan_id)
    if not scan:
        raise HTTPException(404, "Scan not found")

    target   = session.get(Target, scan.target_id)
    events   = session.exec(sel(ScanEvent).where(ScanEvent.scan_id == scan_id)).all()
    findings = session.exec(sel(Finding).where(Finding.scan_id == scan_id)).all()

    ev_dicts = [{"message": e.message, "raw": e.raw or ""} for e in events]
    techs    = infer_technologies_from_events(ev_dicts)

    # Ask Gemini to generate targeted hypotheses
    context = _build_scan_context(scan_id, session)
    try:
        response = _client.messages.create(
            model=MODEL, max_tokens=2000,
            system=(
                "You are an expert hacker analyzing a penetration test in progress. "
                "Based on the scan findings and detected technologies, generate:\n"
                "1. Top 5 attack hypotheses ranked by potential impact\n"
                "2. Business logic flaws specific to this application type\n"
                "3. Trust relationships that could be abused\n"
                "4. Specific payloads to test next\n"
                "5. Chain opportunities from existing findings\n"
                "Be specific and technical. Think like an APT operator."
            ),
            messages=[{
                "role": "user",
                "content": (
                    f"Target: {target.domain if target else scan_id}\n"
                    f"Technologies detected: {techs}\n"
                    f"Current findings: {len(findings)}\n\n"
                    f"{context}\n\n"
                    f"Generate specific attack hypotheses and next steps."
                ),
            }],
        )
        analysis = "".join(b.text for b in response.content if b.type == "text")
    except Exception:
        logger.exception("AI mindset analysis failed for scan_id=%s", scan_id)
        analysis = "Analysis temporarily unavailable. Please try again later."

    return {
        "scan_id":     scan_id,
        "technologies":techs,
        "analysis":    analysis,
        "findings":    len(findings),
    }
