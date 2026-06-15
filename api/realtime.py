"""
BountyOS realtime event bus.

Narrow upgrade: live dashboard + agent event streaming only.
It does not add new scope validation or change existing scanner safety behavior.
"""

from __future__ import annotations

import asyncio
from collections import deque
from datetime import datetime
from typing import Any, Deque, Dict, List, Optional
from fastapi import WebSocket

_MAX_EVENTS = 300
_LIVE_EVENTS: Deque[Dict[str, Any]] = deque(maxlen=_MAX_EVENTS)
_AGENT_STATE: Dict[str, Any] = {
    "status": "idle",
    "stage": "observe",
    "model_expert": "local_recon",
    "last_action": "waiting",
    "updated_at": datetime.utcnow().isoformat(),
}


class LiveHub:
    def __init__(self) -> None:
        self.connections: List[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        await ws.accept()
        self.connections.append(ws)
        await ws.send_json({"type": "hello", "message": "BountyOS live stream connected"})
        for event in list(_LIVE_EVENTS)[-50:]:
            await ws.send_json(event)

    def disconnect(self, ws: WebSocket) -> None:
        if ws in self.connections:
            self.connections.remove(ws)

    async def broadcast(self, event: Dict[str, Any]) -> None:
        dead: List[WebSocket] = []
        for ws in self.connections:
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


hub = LiveHub()


def _event(event_type: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    return {
        "type": event_type,
        "payload": payload or {},
        "created_at": datetime.utcnow().isoformat(),
    }


def set_agent_state(**kwargs: Any) -> Dict[str, Any]:
    _AGENT_STATE.update(kwargs)
    _AGENT_STATE["updated_at"] = datetime.utcnow().isoformat()
    publish_sync("agent.state", dict(_AGENT_STATE))
    return dict(_AGENT_STATE)


def get_agent_state() -> Dict[str, Any]:
    return dict(_AGENT_STATE)


async def publish(event_type: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ev = _event(event_type, payload)
    _LIVE_EVENTS.append(ev)
    await hub.broadcast(ev)
    return ev


def publish_sync(event_type: str, payload: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    ev = _event(event_type, payload)
    _LIVE_EVENTS.append(ev)
    try:
        loop = asyncio.get_running_loop()
        loop.create_task(hub.broadcast(ev))
    except RuntimeError:
        # No running loop; event is still available in /live/snapshot.
        pass
    return ev


def recent_events(limit: int = 100) -> List[Dict[str, Any]]:
    return list(_LIVE_EVENTS)[-limit:]
