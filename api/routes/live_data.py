"""Live data routes for BountyOS AI chat and Architect Agent."""

from __future__ import annotations

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from api.agents.live_data_agent import live_data_agent

router = APIRouter(prefix="/live-data", tags=["live-data"])


class LiveDataQuery(BaseModel):
    query: str


@router.get("/capabilities")
def capabilities():
    return {
        "name": "Live Data Expert",
        "supports": [
            "USD/currency exchange rates",
            "BTC/ETH crypto prices",
            "recent CVEs via NVD",
            "public IP lookup",
        ],
        "examples": [
            "what is today us dollar rate",
            "usd to inr rate",
            "bitcoin price in usd",
            "latest CVEs for nginx",
            "what is my public IP",
        ],
    }


@router.post("/query")
def query(req: LiveDataQuery):
    if not req.query.strip():
        raise HTTPException(400, "Query is empty")
    return live_data_agent.answer(req.query).as_dict()
