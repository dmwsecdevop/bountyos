from __future__ import annotations

import asyncio
import json
from datetime import datetime
from typing import Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field
from sqlmodel import Session, select

from api.database import get_session, session_ctx
from api.models import ToolRunner, ToolJob
from api.realtime import publish_sync
from api.runners.manager import hash_runner_token, new_runner_token, runner_manager
from api.tools.catalogue import TOOL_CATALOGUE
from api.tools.executor import get_execution_mode, set_execution_mode

router = APIRouter(prefix="/runners", tags=["runners"])
ws_router = APIRouter(tags=["runner-websocket"])


class RunnerCreate(BaseModel):
    name: str = Field(min_length=2, max_length=80)
    labels: list[str] = []
    notes: Optional[str] = None


class ModeUpdate(BaseModel):
    mode: str


class JobCreate(BaseModel):
    tool: str
    target: str
    args: list[str] = []
    runner_id: Optional[str] = None
    approved: bool = False
    timeout: int = Field(default=300, ge=5, le=3600)


def _runner_payload(runner: ToolRunner) -> dict:
    try:
        tools = json.loads(runner.tools_json or "{}")
    except Exception:
        tools = {}
    return {
        "id": runner.id,
        "name": runner.name,
        "status": runner.status,
        "platform": runner.platform,
        "hostname": runner.hostname,
        "labels": json.loads(runner.labels_json or "[]"),
        "tool_count": len(tools),
        "tools": tools,
        "enabled": runner.enabled,
        "connected_at": runner.connected_at,
        "last_seen_at": runner.last_seen_at,
        "last_error": runner.last_error,
        "notes": runner.notes,
        "created_at": runner.created_at,
        "updated_at": runner.updated_at,
    }


@router.get("/capabilities")
def capabilities():
    return {
        "execution_modes": ["local", "remote", "hybrid"],
        "current_mode": get_execution_mode(),
        "transport": "outbound authenticated WebSocket",
        "protocol": 1,
        "online": runner_manager.list_online(),
        "supported_features": ["inventory", "jobs", "streaming_output", "heartbeats", "cancellation", "hybrid_fallback"],
    }


@router.get("/")
def list_runners(session: Session = Depends(get_session)):
    rows = session.exec(select(ToolRunner).order_by(ToolRunner.created_at.desc())).all()
    online_ids = {x["runner_id"] for x in runner_manager.list_online()}
    result = []
    for row in rows:
        if row.id not in online_ids and row.status == "online":
            row.status = "offline"
        result.append(_runner_payload(row))
    return result


@router.post("/", status_code=201)
def create_runner(data: RunnerCreate, session: Session = Depends(get_session)):
    token = new_runner_token()
    runner = ToolRunner(
        name=data.name,
        token_hash=hash_runner_token(token),
        labels_json=json.dumps(data.labels),
        notes=data.notes,
        status="created",
    )
    session.add(runner)
    session.commit()
    session.refresh(runner)
    return {
        "runner": _runner_payload(runner),
        "token": token,
        "warning": "The token is shown once. Store it securely.",
        "connect_path": "/ws/runners/connect",
    }


@router.get("/settings")
def runner_settings():
    return {"execution_mode": get_execution_mode()}


@router.put("/settings")
def update_runner_settings(data: ModeUpdate):
    try:
        mode = set_execution_mode(data.mode)
    except ValueError as exc:
        raise HTTPException(400, str(exc))
    publish_sync("runner.mode.changed", {"execution_mode": mode})
    return {"execution_mode": mode}


@router.post("/{runner_id}/rotate-token")
def rotate_token(runner_id: str, session: Session = Depends(get_session)):
    runner = session.get(ToolRunner, runner_id)
    if not runner:
        raise HTTPException(404, "Runner not found")
    token = new_runner_token()
    runner.token_hash = hash_runner_token(token)
    runner.updated_at = datetime.utcnow()
    session.add(runner)
    session.commit()
    return {"runner_id": runner_id, "token": token, "warning": "The token is shown once."}


@router.delete("/{runner_id}", status_code=204)
async def delete_runner(runner_id: str, session: Session = Depends(get_session)):
    runner = session.get(ToolRunner, runner_id)
    if not runner:
        raise HTTPException(404, "Runner not found")
    conn = runner_manager.connections.get(runner_id)
    if conn:
        try:
            await conn.websocket.close(code=1008)
        except Exception:
            pass
    session.delete(runner)
    session.commit()


def _tool_meta(name: str) -> Optional[dict]:
    if name == "headers":
        return {"name": "headers", "binary": "curl", "passive_safe": True, "default_args": ["-sI", "--max-time", "15"], "target_flag": ""}
    for item in TOOL_CATALOGUE:
        if item.get("name") == name:
            return item
    return None


async def _run_manual_job(job_request: JobCreate, job_id_holder: dict):
    meta = _tool_meta(job_request.tool)
    binary = meta.get("binary", job_request.tool)
    argv = [binary]
    defaults = meta.get("default_args", "")
    if isinstance(defaults, str) and defaults:
        import shlex
        argv.extend(shlex.split(defaults))
    elif isinstance(defaults, list):
        argv.extend(defaults)
    flag = meta.get("target_flag", "")
    if flag:
        argv.extend([flag, job_request.target])
    else:
        argv.append(job_request.target)
    argv.extend(job_request.args)

    output = []
    async for item in runner_manager.execute_stream(
        tool_name=job_request.tool,
        argv=argv,
        target=job_request.target,
        scan_id=None,
        timeout=job_request.timeout,
        runner_id=job_request.runner_id,
        metadata={"manual": True},
    ):
        if item.get("job_id"):
            job_id_holder["job_id"] = item["job_id"]
        if item.get("type") == "line":
            output.append(item.get("line", ""))


@router.post("/jobs", status_code=202)
def create_job(data: JobCreate, background_tasks: BackgroundTasks):
    meta = _tool_meta(data.tool)
    if not meta:
        raise HTTPException(400, "Unknown or unsupported tool")
    passive_safe = bool(meta.get("passive_safe"))
    if not passive_safe:
        category = str(meta.get("category") or "")
        phase = str(meta.get("phase") or "")
        passive_safe = phase == "recon" and category in {"subdomain", "osint", "webprobe", "fingerprint", "metadata"}
    if not passive_safe and not data.approved:
        raise HTTPException(status_code=409, detail={"code": "approval_required", "message": "This active tool job requires approved=true."})
    conn = runner_manager.choose_runner(data.tool, data.runner_id)
    if not conn:
        raise HTTPException(409, f"No online runner provides {data.tool}")
    holder = {}
    background_tasks.add_task(_run_manual_job, data, holder)
    return {"accepted": True, "runner_id": conn.runner_id, "runner_name": conn.name, "tool": data.tool, "target": data.target}


@router.get("/jobs")
def list_jobs(limit: int = Query(default=100, ge=1, le=500), session: Session = Depends(get_session)):
    return session.exec(select(ToolJob).order_by(ToolJob.created_at.desc()).limit(limit)).all()


@router.get("/jobs/{job_id}")
def get_job(job_id: str, session: Session = Depends(get_session)):
    job = session.get(ToolJob, job_id)
    if not job:
        raise HTTPException(404, "Job not found")
    return job


@router.post("/jobs/{job_id}/cancel")
async def cancel_job(job_id: str):
    if not await runner_manager.cancel_job(job_id):
        raise HTTPException(404, "Job not found")
    return {"cancelled": True, "job_id": job_id}


@ws_router.websocket("/ws/runners/connect")
async def runner_connect(websocket: WebSocket, runner_id: str):
    await websocket.accept()
    try:
        auth = await asyncio.wait_for(websocket.receive_json(), timeout=10)
    except Exception:
        await websocket.close(code=1008, reason="Runner authentication required")
        return
    token = str(auth.get("token") or "") if auth.get("type") == "auth" else ""
    runner = runner_manager.verify_token(runner_id, token)
    if not runner:
        await websocket.close(code=1008, reason="Invalid runner credentials")
        return
    await runner_manager.connect(runner, websocket, accepted=True)
    try:
        while True:
            message = await websocket.receive_json()
            await runner_manager.handle_message(runner_id, message)
    except WebSocketDisconnect:
        await runner_manager.disconnect(runner_id, "WebSocket disconnected")
    except Exception as exc:
        await runner_manager.disconnect(runner_id, str(exc))
        try:
            await websocket.close(code=1011)
        except Exception:
            pass
