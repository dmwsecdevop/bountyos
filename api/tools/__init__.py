"""
BountyOS - Tools package
Re-exports everything from the discovery module for backward compatibility.
"""
from api.tools.discovery import (
    discover_all_tools,
    get_tool,
    get_passive_tools,
    get_aggressive_tools,
    get_discovery_report,
    ALL_TOOLS,
    RECON_TOOLS,
    VULNSCAN_TOOLS,
    EXPLOIT_TOOLS_MAP,
    FORENSIC_TOOLS,
    UTIL_TOOLS,
    DISCOVERED_TOOLS,
    DynamicTool,
)
