"""Unit tests for debate engine parsing and configuration."""

import asyncio
import os
import pytest
from api.services.debate_engine import (
    DebateSession, DebateRecord, SKEPTIC_PROMPT, PROPONENT_PROMPT, VERDICT_PROMPT,
    DEBATE_ENABLED, DEBATE_MODEL
)

# Mock client to avoid real Gemini calls
class DummyClient:
    class _Resp:
        def __init__(self, text):
            self.content = [type('b',(object,),{'type':'text','text':text})]

    def __init__(self, responses=None):
        self.responses = responses or []
    def messages(self):
        return self
    def create(self, *args, **kwargs):
        # return last response or a default
        text = self.responses.pop(0) if self.responses else '{"verdict":"NEEDS_EVIDENCE","final_severity":"info","confidence":0.5,"summary":"no","key_reason":"none"}'
        return DummyClient._Resp(text)

@pytest.mark.parametrize("input_text,expected_verdict", [
    ('{"verdict":"CONFIRMED","final_severity":"high","confidence":0.9,"summary":"ok","key_reason":"proof"}', 'CONFIRMED'),
    ("garbage {notjson]", 'NEEDS_EVIDENCE'),
])
def test_parse_verdict(input_text, expected_verdict):
    # Use a real DebateSession with mocked client
    class _Fake:
        def __init__(self):
            self.id = 'fake'
            self.scan_id = 's'
            self.severity = 'high'
            self.description = ''
            self.evidence = ''
            self.remediation = ''
    sess = DebateSession(None, _Fake())
    parsed = sess._parse_verdict(input_text)
    assert parsed['verdict'] == expected_verdict


def test_confidence_clamping():
    class _Fake:
        def __init__(self):
            self.id = 'fake'
            self.scan_id = 's'
            self.severity = 'high'
            self.description = ''
            self.evidence = ''
            self.remediation = ''
    sess = DebateSession(None, _Fake())
    parsed = sess._parse_verdict('{"verdict":"CONFIRMED","final_severity":"high","confidence":2.5,"summary":"a","key_reason":"b"}')
    assert parsed['confidence'] == 1.0


def test_severity_validation():
    class _Fake:
        def __init__(self):
            self.id = 'fake'
            self.scan_id = 's'
            self.severity = 'high'
            self.description = ''
            self.evidence = ''
            self.remediation = ''
    sess = DebateSession(None, _Fake())
    parsed = sess._parse_verdict('{"verdict":"CONFIRMED","final_severity":"supercritical","confidence":0.5,"summary":"a","key_reason":"b"}')
    assert parsed['final_severity'] == 'info'


def test_debate_disabled_behavior(monkeypatch):
    # Ensure that debate_all_findings raises when disabled
    monkeypatch.setenv('BOUNTYOS_DEBATE_ENABLED', 'false')
    import importlib
    importlib.reload(__import__('api.services.debate_engine', fromlist=['']))
    from api.services.debate_engine import debate_enabled, debate_all_findings
    assert debate_enabled() is False
    with pytest.raises(RuntimeError):
        asyncio.run(debate_all_findings('scan-x'))
