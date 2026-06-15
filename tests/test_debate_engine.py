"""Tests for Debate Engine parsing and disabled config behavior."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from api.services.debate_engine import debate_enabled, parse_verdict_from_text


def test_parse_valid_json():
    txt = '{"verdict":"CONFIRMED","final_severity":"high","confidence":0.82,"summary":"ok","key_reason":"evidence shows data leak"}'
    out = parse_verdict_from_text(txt)
    assert out["verdict"] == "CONFIRMED"
    assert out["final_severity"] == "high"
    assert 0.8 < out["confidence"] <= 1.0
    assert out["key_reason"] == "evidence shows data leak"


def test_parse_json_embedded_in_model_text():
    txt = 'Here is the verdict:\n```json\n{"verdict":"DOWNGRADED","final_severity":"medium","confidence":0.4,"summary":"weak impact","key_reason":"impact not proven"}\n```'
    out = parse_verdict_from_text(txt)
    assert out["verdict"] == "DOWNGRADED"
    assert out["final_severity"] == "medium"


def test_parse_invalid_json_fallback():
    out = parse_verdict_from_text('I think {not valid json] end.')
    assert out["verdict"] == "NEEDS_EVIDENCE"
    assert out["final_severity"] == "info"
    assert out["confidence"] == 0.5


def test_invalid_verdict_fallback_and_confidence_clamping():
    txt = '{"verdict":"MAYBE","final_severity":"ultra","confidence":2.5,"summary":"x","key_reason":"y"}'
    out = parse_verdict_from_text(txt)
    assert out["verdict"] == "NEEDS_EVIDENCE"
    assert out["final_severity"] == "info"
    assert out["confidence"] == 1.0


def test_negative_confidence_clamping():
    txt = '{"verdict":"CONFIRMED","final_severity":"critical","confidence":-5}'
    out = parse_verdict_from_text(txt)
    assert out["confidence"] == 0.0


def test_debate_disabled_by_default(monkeypatch):
    monkeypatch.delenv("BOUNTYOS_DEBATE_ENABLED", raising=False)
    assert not debate_enabled()
