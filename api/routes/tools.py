"""Tool discovery routes.

Expose the installed and remote security-tool catalogue to the dashboard.
"""

from fastapi import APIRouter

from api.tools.discovery import DISCOVERED_TOOLS, discover_all_tools, get_discovery_report

router = APIRouter(prefix="/tools", tags=["tools"])


def _tool_report() -> dict:
    """Return a populated tool discovery report."""
    if not DISCOVERED_TOOLS:
        discover_all_tools()
    return get_discovery_report()


@router.get("")
@router.get("/")
def list_tools() -> dict:
    """List available and unavailable tools with metadata and install hints."""
    return _tool_report()


@router.get("/available")
def available_tools() -> dict:
    """Compatibility endpoint used by the scan-launch modal."""
    return _tool_report()
