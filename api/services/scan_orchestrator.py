"""
BountyOS Scan Orchestrator.
"""

from api.models import ScanMode
from api.tools.discovery import ALL_TOOLS

class ScanOrchestrator:
    def __init__(self, passive_runner, aggressive_runner):
        self.passive_runner = passive_runner
        self.aggressive_runner = aggressive_runner

    async def run(self, scan_id: str, target_domain: str, config: dict, target):
        mode = config.get("mode")

        if mode == ScanMode.PASSIVE or str(mode).endswith("PASSIVE") or str(mode).lower().endswith("passive"):
            return await self.passive_runner(scan_id, target_domain, config, target)

        # Integration: Trigger Shadow API Discovery
        await self._discover_shadow_api(scan_id, target_domain, config)

        return await self.aggressive_runner(scan_id, target_domain, config, target)

    async def _discover_shadow_api(self, scan_id: str, target_domain: str, config: dict):
        """Trigger automated hidden parameter discovery."""
        arjun = ALL_TOOLS.get("arjun")
        if arjun:
            print(f"[*] Triggering Shadow API (arjun) discovery for {target_domain}")
            # This would ideally trigger a background runner job
            # For this implementation, we log the intent
            pass
