"""
BountyOS - WebSocket live stream
Clients subscribe to a scan_id and receive ScanEvent JSON in real-time.
"""

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from sqlmodel import Session, select
from typing import Dict, List
import asyncio
import json

from api.database import engine
from api.models import ScanEvent

router = APIRouter(tags=["websocket"])

# Connection manager
class ConnectionManager:
    def __init__(self):
        # scan_id -> list of connected websockets
        self._connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, scan_id: str, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(scan_id, []).append(ws)

    def disconnect(self, scan_id: str, ws: WebSocket):
        conns = self._connections.get(scan_id, [])
        if ws in conns:
            conns.remove(ws)

    async def broadcast(self, scan_id: str, data: dict):
        conns = self._connections.get(scan_id, [])
        dead = []
        for ws in conns:
            try:
                await ws.send_json(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(scan_id, ws)


manager = ConnectionManager()


@router.websocket("/ws/scans/{scan_id}")
async def scan_stream(websocket: WebSocket, scan_id: str):
    """
    WebSocket endpoint — streams live ScanEvents for a given scan_id.
    On connect, replays all existing events, then tails new ones.
    """
    await manager.connect(scan_id, websocket)
    try:
        # Replay historical events
        with Session(engine) as s:
            events = s.exec(
                select(ScanEvent)
                .where(ScanEvent.scan_id == scan_id)
                .order_by(ScanEvent.created_at)
            ).all()
            for ev in events:
                await websocket.send_json({
                    "id":         ev.id,
                    "scan_id":    ev.scan_id,
                    "phase":      ev.phase,
                    "tool":       ev.tool,
                    "level":      ev.level,
                    "message":    ev.message,
                    "created_at": ev.created_at.isoformat(),
                })

        # Keep connection alive — client ping/pong
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                await websocket.send_text("pong")  # keep-alive

    except WebSocketDisconnect:
        manager.disconnect(scan_id, websocket)
