from fastapi.testclient import TestClient

from api.agents.model_router import ModelExpertRouter
from api.main import app


def test_router_uses_gemini_35_for_agentic_browser_caido_tasks():
    router = ModelExpertRouter()
    assert router.route("plan autonomous browser workflow", "agentic_planning").model == "gemini-3.5-flash"
    browser = router.route("analyze browser current page", "analyze_browser")
    assert browser.model == "gemini-3.5-flash"
    assert browser.workload == "browser_reasoning"
    caido = router.route("check caido traffic for IDOR", "check_caido_traffic")
    assert caido.model == "gemini-3.5-flash"
    assert caido.workload == "caido_analysis"


def test_caido_missing_token_returns_clean_error(monkeypatch):
    monkeypatch.delenv("CAIDO_API_TOKEN", raising=False)
    with TestClient(app) as client:
        response = client.post("/api/v1/integrations/caido/import-history", json={"limit": 5})
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is False
    assert "CAIDO_API_TOKEN" in data["error"]


def test_browser_mcp_disabled_returns_clean_error(monkeypatch):
    monkeypatch.delenv("CHROME_DEVTOOLS_MCP_URL", raising=False)
    monkeypatch.delenv("BROWSER_MCP_URL", raising=False)
    with TestClient(app) as client:
        response = client.post("/api/v1/integrations/browser/analyze", json={})
    assert response.status_code == 200
    data = response.json()
    assert data["ok"] is False
    assert "disabled" in data["error"].lower() or "not configured" in data["error"].lower()
