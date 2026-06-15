"""
BountyOS Scan Orchestrator.

This service is the control layer between scan routes and scan pipelines.
For now it wraps the existing passive/aggressive pipeline functions safely.
Later we can move each stage here without breaking routes.
"""

from api.models import ScanMode


class ScanOrchestrator:
    def __init__(self, passive_runner, aggressive_runner):
        self.passive_runner = passive_runner
        self.aggressive_runner = aggressive_runner

    async def run(self, scan_id: str, target_domain: str, config: dict, target):
        mode = config.get("mode")

        if mode == ScanMode.PASSIVE or str(mode).endswith("PASSIVE") or str(mode).lower().endswith("passive"):
            return await self.passive_runner(scan_id, target_domain, config, target)

        return await self.aggressive_runner(scan_id, target_domain, config, target)
