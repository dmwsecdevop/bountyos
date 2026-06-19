from fastapi.testclient import TestClient

from api.main import app
from api.integrations.gemini_client import GeminiResult


class FakeGeminiClient:
    async def chat(self, transcript, *, context=None, model=None):
        assert "hello hunter" in transcript
        return GeminiResult(provider="gemini", model="gemini-2.5-flash-lite", text="REAL GEMINI OUTPUT", route="light_chat")

    async def summarize_scan(self, transcript, *, context=None, model=None):
        return GeminiResult(provider="gemini", model="gemini-2.5-pro", text="REAL SCAN SUMMARY", route="recon_summary")

    async def analyze_findings(self, transcript, *, context=None, model=None):
        return GeminiResult(provider="gemini", model="gemini-2.5-pro", text="REAL FINDING ANALYSIS", route="bug_reasoning")

    async def write_report(self, transcript, *, context=None, model=None):
        return GeminiResult(provider="gemini", model="gemini-2.5-pro", text="REAL REPORT", route="report_writing")


class FailingGeminiClient:
    async def chat(self, transcript, *, context=None, model=None):
        raise RuntimeError("gemini exploded")


def test_agent_command_calls_gemini_for_general_chat(monkeypatch):
    monkeypatch.setattr("api.agents.architect_agent.GeminiClient", FakeGeminiClient)

    with TestClient(app) as client:
        response = client.post("/api/v1/agent/command", json={"transcript": "hello hunter"})

    assert response.status_code == 200
    data = response.json()
    assert data["reason"]["action"] == "general_chat"
    assert data["act"]["ok"] is True
    assert data["act"]["provider"] == "gemini"
    assert data["act"]["model"] == "gemini-2.5-flash-lite"
    assert data["act"]["response"] == "REAL GEMINI OUTPUT"


def test_agent_command_returns_gemini_error_without_silent_response(monkeypatch):
    monkeypatch.setattr("api.agents.architect_agent.GeminiClient", FailingGeminiClient)

    with TestClient(app) as client:
        response = client.post("/api/v1/agent/command", json={"transcript": "hello hunter"})

    assert response.status_code == 200
    data = response.json()
    assert data["act"] == {"ok": False, "provider": "gemini", "error": "gemini exploded"}
