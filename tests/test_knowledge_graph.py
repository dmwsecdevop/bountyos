import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.services.knowledge_graph import sanitize_text

def test_secret_redaction():
    out=sanitize_text('api_key=abc123 password=hunter2 token: bearer')
    assert 'REDACTED' in out
    assert 'abc123' not in out
    assert 'hunter2' not in out
