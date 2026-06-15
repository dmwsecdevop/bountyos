"""Connector health endpoints for API tokens, rate limits, and provider outages."""

from fastapi import APIRouter

from api.integrations.resilient_http import connector_health

router = APIRouter(prefix="/connector-health", tags=["connector-health"])


@router.get("/")
def health_snapshot():
    return connector_health.snapshot()


@router.get("/{provider}")
def provider_health(provider: str):
    return connector_health.get(provider) or {
        "provider": provider,
        "status": "unknown",
        "message": "No outbound request has been made for this connector in the current process.",
    }


@router.post("/reset")
def reset_health():
    connector_health.reset()
    return {"ok": True, "message": "Connector health state reset."}


@router.post("/{provider}/reset")
def reset_provider_health(provider: str):
    connector_health.reset(provider)
    return {"ok": True, "provider": provider}
