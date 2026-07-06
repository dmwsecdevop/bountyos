"""Caido analysis agent for autonomous proxy traffic monitoring."""

from typing import Any, Optional
from api.integrations.caido_client import CaidoClient, CaidoAnalysis

class CaidoAnalysisAgent:
    """Agentic wrapper to intelligently analyze Caido proxy traffic."""
    
    def __init__(self):
        self.client = CaidoClient()

    async def analyze(self, request: dict[str, Any], target: Optional[dict[str, Any]] = None) -> Optional[CaidoAnalysis]:
        # Simple heuristic filtering: avoid noise
        if not self._is_interesting(request):
            return None
            
        return await self.client.analyze_request(request, target)
        
    def _is_interesting(self, request: dict[str, Any]) -> bool:
        # Example filtering: skip static assets, focus on API/Auth/Sensitive paths
        path = request.get("path", "").lower()
        if any(ext in path for ext in [".js", ".css", ".png", ".jpg", ".ico"]):
            return False
            
        # Example: prioritize auth or api paths
        if any(keyword in path for keyword in ["/api/", "/auth/", "/login", "/register", "/admin"]):
            return True
            
        return True # Default to analyze for now until we have more refined filtering

caido_analysis_agent = CaidoAnalysisAgent()
