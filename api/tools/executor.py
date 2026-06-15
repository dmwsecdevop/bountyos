from __future__ import annotations

import asyncio
import json
import os
import shlex
from pathlib import Path
from typing import AsyncIterator, Dict, Optional

from api.database import session_ctx
from api.models import SystemSetting
from api.runners.manager import runner_manager

_ALLOWED_MODES = {"local", "remote", "hybrid"}


def get_execution_mode(explicit: Optional[str] = None) -> str:
    if explicit and explicit.lower() in _ALLOWED_MODES:
        return explicit.lower()
    try:
        with session_ctx() as session:
            row = session.get(SystemSetting, "execution_mode")
            if row and row.value.lower() in _ALLOWED_MODES:
                return row.value.lower()
    except Exception:
        pass
    env_mode = os.getenv("BOUNTYOS_EXECUTION_MODE", "").lower()
    if env_mode in _ALLOWED_MODES:
        return env_mode
    return "hybrid"


def set_execution_mode(mode: str) -> str:
    mode = mode.lower().strip()
    if mode not in _ALLOWED_MODES:
        raise ValueError("execution mode must be local, remote, or hybrid")
    with session_ctx() as session:
        row = session.get(SystemSetting, "execution_mode") or SystemSetting(key="execution_mode", value=mode)
        row.value = mode
        session.add(row)
        session.commit()
    return mode


def _argv_from_command(command: str | list[str]) -> list[str]:
    if isinstance(command, list):
        argv = [str(x) for x in command]
    else:
        argv = shlex.split(command)
    if not argv:
        raise ValueError("empty command")
    if len(argv) > 256:
        raise ValueError("too many command arguments")
    if any("\x00" in arg or len(arg) > 8192 for arg in argv):
        raise ValueError("invalid command argument")
    return argv


def _remote_argv(tool_name: str, argv: list[str]) -> list[str]:
    aliases = {"headers": "curl"}
    expected = aliases.get(tool_name, tool_name)
    clean = list(argv)
    clean[0] = expected
    return clean


async def _local_stream(argv: list[str], timeout: int) -> AsyncIterator[Dict]:
    proc = await asyncio.create_subprocess_exec(
        *argv,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.STDOUT,
    )
    yield {"type": "started", "source": "local", "pid": proc.pid}
    try:
        while True:
            line = await asyncio.wait_for(proc.stdout.readline(), timeout=timeout)
            if not line:
                break
            yield {"type": "line", "line": line.decode(errors="replace").rstrip(), "stream": "stdout", "source": "local"}
        code = await asyncio.wait_for(proc.wait(), timeout=5)
        yield {"type": "result", "status": "completed" if code == 0 else "failed", "exit_code": code, "error": None, "source": "local"}
    except asyncio.TimeoutError:
        proc.kill()
        await proc.wait()
        yield {"type": "result", "status": "timeout", "exit_code": None, "error": f"Timed out after {timeout}s", "source": "local"}


async def stream_command(
    *,
    tool_name: str,
    command: str | list[str],
    scan_id: Optional[str],
    target: Optional[str],
    timeout: int,
    execution_mode: Optional[str] = None,
    runner_id: Optional[str] = None,
    metadata: Optional[Dict] = None,
) -> AsyncIterator[Dict]:
    argv = _argv_from_command(command)
    mode = get_execution_mode(execution_mode)

    if mode in {"remote", "hybrid"}:
        conn = runner_manager.choose_runner(tool_name, runner_id)
        if conn:
            yield {"type": "started", "source": "remote", "runner_id": conn.runner_id, "runner_name": conn.name}
            async for item in runner_manager.execute_stream(
                tool_name=tool_name,
                argv=_remote_argv(tool_name, argv),
                target=target,
                scan_id=scan_id,
                timeout=timeout,
                runner_id=conn.runner_id,
                metadata=metadata,
            ):
                item.setdefault("source", "remote")
                yield item
            return
        if mode == "remote":
            yield {"type": "result", "status": "failed", "exit_code": None, "error": f"No online runner provides {tool_name}", "source": "remote"}
            return

    yield {"type": "dispatch", "source": "local"}
    async for item in _local_stream(argv, timeout):
        yield item
