import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.services.agent_revisions import run_basic_evals

def test_basic_evals_return_records(monkeypatch):
    monkeypatch.delenv('BOUNTYOS_DEBATE_ENABLED', raising=False)
    monkeypatch.delenv('BOUNTYOS_TAKEOVER_ENABLED', raising=False)
    monkeypatch.delenv('BOUNTYOS_BROWSER_AGENT_ENABLED', raising=False)
    rows=run_basic_evals(False)
    assert rows
    assert {r['status'] for r in rows} <= {'pass','fail','warn'}
    assert any(r['test_name']=='skill registry sqlmap approval' and r['status']=='pass' for r in rows)
