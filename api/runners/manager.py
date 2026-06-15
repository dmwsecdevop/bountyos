from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import secrets
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, AsyncIterator, Dict, Optional

from fastapi import WebSocket
from sqlmodel import select

from api.database import session_ctx
from api.models import ToolRunner, ToolJob
from api.realtime import publish_sync


def hash_runner_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def new_runner_token() -> str:
    return secrets.token_urlsafe(36)


@dataclass
class RunnerConnection:
    runner_id: str
    websocket: WebSocket
    name: str
    tools: Dict[str, Dict[str, Any]] = field(default_factory=dict)
    platform: str = "linux"
    hostname: str = "unknown"
    connected_at: datetime = field(default_factory=datetime.utcnow)
    last_seen_at: datetime = field(default_factory=datetime.utcnow)


@dataclass
class JobChannel:
    queue: asyncio.Queue
    done: asyncio.Future


class RunnerManager:
    def __init__(self) -> None:
        self.connections: Dict[str, RunnerConnection] = {}
        self.jobs: Dict[str, JobChannel] = {}
        self._lock = asyncio.Lock()

    def verify_token(self, runner_id: str, token: str) -> Optional[ToolRunner]:
        with session_ctx() as session:
            runner = session.get(ToolRunner, runner_id)
            if not runner or not runner.enabled or not runner.token_hash:
                return None
            if not hmac.compare_digest(runner.token_hash, hash_runner_token(token)):
                return None
            return runner

    async def connect(self, runner: ToolRunner, websocket: WebSocket, *, accepted: bool = False) -> None:
        if not accepted:
            await websocket.accept()
        async with self._lock:
            old = self.connections.get(runner.id)
            if old:
                try:
                    await old.websocket.close(code=1012)
                except Exception:
                    pass
            self.connections[runner.id] = RunnerConnection(
                runner_id=runner.id,
                websocket=websocket,
                name=runner.name,
            )
        now = datetime.utcnow()
        with session_ctx() as session:
            db_runner = session.get(ToolRunner, runner.id)
            if db_runner:
                db_runner.status = "online"
                db_runner.connected_at = now
                db_runner.last_seen_at = now
                db_runner.updated_at = now
                db_runner.last_error = None
                session.add(db_runner)
                session.commit()
        publish_sync("runner.connected", {"runner_id": runner.id, "name": runner.name})
        await websocket.send_json({
            "type": "welcome",
            "runner_id": runner.id,
            "heartbeat_seconds": 20,
            "protocol": 1,
        })

    async def disconnect(self, runner_id: str, reason: str = "disconnected") -> None:
        async with self._lock:
            self.connections.pop(runner_id, None)
        now = datetime.utcnow()
        with session_ctx() as session:
            runner = session.get(ToolRunner, runner_id)
            if runner:
                runner.status = "offline"
                runner.updated_at = now
                runner.last_error = reason
                session.add(runner)
                session.commit()
        publish_sync("runner.disconnected", {"runner_id": runner_id, "reason": reason})

        for job_id, channel in list(self.jobs.items()):
            with session_ctx() as session:
                job = session.get(ToolJob, job_id)
                if job and job.runner_id == runner_id and job.status in {"queued", "running"}:
                    if not channel.done.done():
                        channel.done.set_result({"status": "failed", "exit_code": None, "error": reason})
                    await channel.queue.put({"type": "error", "message": reason})
                    await channel.queue.put(None)

    async def handle_message(self, runner_id: str, message: Dict[str, Any]) -> None:
        conn = self.connections.get(runner_id)
        if not conn:
            return
        conn.last_seen_at = datetime.utcnow()
        mtype = message.get("type")

        if mtype == "hello":
            tools = message.get("tools") or {}
            conn.tools = tools if isinstance(tools, dict) else {}
            conn.platform = str(message.get("platform") or "linux")
            conn.hostname = str(message.get("hostname") or "unknown")
            now = datetime.utcnow()
            with session_ctx() as session:
                runner = session.get(ToolRunner, runner_id)
                if runner:
                    runner.status = "online"
                    runner.platform = conn.platform
                    runner.hostname = conn.hostname
                    runner.tools_json = json.dumps(conn.tools)
                    runner.last_seen_at = now
                    runner.updated_at = now
                    session.add(runner)
                    session.commit()
            publish_sync("runner.inventory", {
                "runner_id": runner_id,
                "name": conn.name,
                "tool_count": len(conn.tools),
                "platform": conn.platform,
                "hostname": conn.hostname,
            })
            await conn.websocket.send_json({"type": "hello_ack", "tool_count": len(conn.tools)})
            return

        if mtype == "heartbeat":
            now = datetime.utcnow()
            with session_ctx() as session:
                runner = session.get(ToolRunner, runner_id)
                if runner:
                    runner.last_seen_at = now
                    runner.status = "online"
                    runner.updated_at = now
                    session.add(runner)
                    session.commit()
            await conn.websocket.send_json({"type": "heartbeat_ack", "at": now.isoformat()})
            return

        job_id = str(message.get("job_id") or "")
        channel = self.jobs.get(job_id)
        if not job_id or not channel:
            return

        if mtype == "job_started":
            with session_ctx() as session:
                job = session.get(ToolJob, job_id)
                if job:
                    job.status = "running"
                    job.started_at = datetime.utcnow()
                    session.add(job)
                    session.commit()
            publish_sync("runner.job.started", {"job_id": job_id, "runner_id": runner_id})
            return

        if mtype == "job_output":
            line = str(message.get("line") or "")
            stream = str(message.get("stream") or "stdout")
            await channel.queue.put({"type": "line", "line": line, "stream": stream})
            with session_ctx() as session:
                job = session.get(ToolJob, job_id)
                if job:
                    existing = job.output or ""
                    if len(existing) < 5_000_000:
                        job.output = (existing + line + "\n")[-5_000_000:]
                    session.add(job)
                    session.commit()
            return

        if mtype == "job_result":
            result = {
                "status": str(message.get("status") or "failed"),
                "exit_code": message.get("exit_code"),
                "error": message.get("error"),
                "duration_ms": message.get("duration_ms"),
            }
            if not channel.done.done():
                channel.done.set_result(result)
            await channel.queue.put({"type": "result", **result})
            await channel.queue.put(None)
            with session_ctx() as session:
                job = session.get(ToolJob, job_id)
                if job:
                    job.status = result["status"]
                    job.exit_code = result["exit_code"]
                    job.error = result["error"]
                    job.finished_at = datetime.utcnow()
                    session.add(job)
                    session.commit()
            publish_sync("runner.job.finished", {"job_id": job_id, "runner_id": runner_id, **result})

    def list_online(self) -> list[Dict[str, Any]]:
        result = []
        for conn in self.connections.values():
            result.append({
                "runner_id": conn.runner_id,
                "name": conn.name,
                "platform": conn.platform,
                "hostname": conn.hostname,
                "tools": conn.tools,
                "tool_count": len(conn.tools),
                "connected_at": conn.connected_at.isoformat(),
                "last_seen_at": conn.last_seen_at.isoformat(),
            })
        return result

    def aggregate_tools(self) -> Dict[str, Dict[str, Any]]:
        aggregate: Dict[str, Dict[str, Any]] = {}
        for conn in self.connections.values():
            for name, meta in conn.tools.items():
                entry = aggregate.setdefault(name, {
                    "name": name,
                    "version": meta.get("version", "?"),
                    "binary": meta.get("binary", name),
                    "runners": [],
                })
                entry["runners"].append({
                    "runner_id": conn.runner_id,
                    "runner_name": conn.name,
                    "hostname": conn.hostname,
                })
        return aggregate

    def choose_runner(self, tool_name: str, runner_id: Optional[str] = None) -> Optional[RunnerConnection]:
        if runner_id:
            conn = self.connections.get(runner_id)
            if conn and tool_name in conn.tools:
                return conn
            return None
        candidates = [c for c in self.connections.values() if tool_name in c.tools]
        if not candidates:
            return None
        return sorted(candidates, key=lambda c: (len(c.tools), c.last_seen_at), reverse=True)[0]

    async def execute_stream(
        self,
        *,
        tool_name: str,
        argv: list[str],
        target: Optional[str],
        scan_id: Optional[str],
        timeout: int,
        runner_id: Optional[str] = None,
        metadata: Optional[Dict[str, Any]] = None,
    ) -> AsyncIterator[Dict[str, Any]]:
        conn = self.choose_runner(tool_name, runner_id)
        if not conn:
            raise RuntimeError(f"No online runner provides {tool_name}")

        job = ToolJob(
            runner_id=conn.runner_id,
            scan_id=scan_id,
            tool_name=tool_name,
            target=target,
            argv_json=json.dumps(argv),
            metadata_json=json.dumps(metadata or {}),
            execution_location="remote",
            status="queued",
            timeout_seconds=timeout,
        )
        with session_ctx() as session:
            session.add(job)
            session.commit()
            session.refresh(job)
        channel = JobChannel(queue=asyncio.Queue(), done=asyncio.get_running_loop().create_future())
        self.jobs[job.id] = channel

        payload = {
            "type": "job",
            "job_id": job.id,
            "tool": tool_name,
            "argv": argv,
            "target": target,
            "timeout": timeout,
            "metadata": metadata or {},
        }
        await conn.websocket.send_json(payload)
        publish_sync("runner.job.queued", {
            "job_id": job.id,
            "runner_id": conn.runner_id,
            "runner_name": conn.name,
            "tool": tool_name,
            "scan_id": scan_id,
            "target": target,
        })

        try:
            while True:
                item = await asyncio.wait_for(channel.queue.get(), timeout=timeout + 30)
                if item is None:
                    break
                yield {**item, "job_id": job.id, "runner_id": conn.runner_id, "runner_name": conn.name}
        except asyncio.TimeoutError:
            try:
                await conn.websocket.send_json({"type": "cancel_job", "job_id": job.id})
            except Exception:
                pass
            with session_ctx() as session:
                db_job = session.get(ToolJob, job.id)
                if db_job:
                    db_job.status = "timeout"
                    db_job.error = f"Timed out after {timeout}s"
                    db_job.finished_at = datetime.utcnow()
                    session.add(db_job)
                    session.commit()
            yield {
                "type": "result",
                "status": "timeout",
                "exit_code": None,
                "error": f"Timed out after {timeout}s",
                "job_id": job.id,
                "runner_id": conn.runner_id,
                "runner_name": conn.name,
            }
        finally:
            self.jobs.pop(job.id, None)

    async def cancel_scan_jobs(self, scan_id: str) -> int:
        cancelled = 0
        with session_ctx() as session:
            jobs = session.exec(select(ToolJob).where(ToolJob.scan_id == scan_id).where(ToolJob.status.in_(["queued", "running"]))).all()
            ids = [job.id for job in jobs]
        for job_id in ids:
            if await self.cancel_job(job_id):
                cancelled += 1
        return cancelled

    async def cancel_job(self, job_id: str) -> bool:
        with session_ctx() as session:
            job = session.get(ToolJob, job_id)
            if not job:
                return False
            conn = self.connections.get(job.runner_id or "")
            if conn:
                await conn.websocket.send_json({"type": "cancel_job", "job_id": job_id})
            job.status = "cancelled"
            job.finished_at = datetime.utcnow()
            session.add(job)
            session.commit()
        channel = self.jobs.get(job_id)
        if channel:
            await channel.queue.put({"type": "result", "status": "cancelled", "exit_code": None, "error": "Cancelled"})
            await channel.queue.put(None)
        publish_sync("runner.job.cancelled", {"job_id": job_id})
        return True


runner_manager = RunnerManager()
