"""BountyOS v6 frontend compatibility metadata."""

from fastapi import APIRouter


router = APIRouter(prefix="/upgrades", tags=["upgrades"])


@router.get("", include_in_schema=False)
@router.get("/")
def get_upgrades():
    """Describe the stable v6 modules exposed by this self-hosted edition."""
    return {
        "version": "6.0.0",
        "edition": "self-hosted",
        "modules": {
            "hunter_brain": "enabled",
            "gemini_router": "enabled",
            "runner_bridge": "enabled",
            "knowledge_graph": "available",
            "program_radar": "available",
            "self_host_stack": "enabled",
        },
    }
