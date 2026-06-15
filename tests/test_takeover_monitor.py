import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.services.takeover_monitor import takeover_enabled, scope_guard_domain

def test_disabled_default_and_scope_guard(monkeypatch):
    monkeypatch.delenv('BOUNTYOS_TAKEOVER_ENABLED', raising=False)
    assert takeover_enabled() is False
    assert scope_guard_domain('app.example.com', ['example.com']) is True
    assert scope_guard_domain('evil.com', ['example.com']) is False
