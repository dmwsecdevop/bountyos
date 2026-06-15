"""Tests for Debate Engine parsing and config behavior."""

import os
import pytest
from api.services.debate_engine import parse_verdict_from_text, debate_enabled


def test_parse_valid_json():
    txt = '{"verdict":"CONFIRMED","final_severity":"high","confidence":0.82,"summary":"ok","key_reason":"evidence shows data leak"}'
    out = parse_verdict_from_text(txt)
    assert out["verdict"] == "CONFIRMED"
    assert out["final_severity"] == "high"
    assert 0.8 < out["confidence"] <= 1.0


def test_parse_invalid_json_fallback():
    txt = 'I think {not valid json] end.'
    out = parse_verdict_from_text(txt)
    assert out["verdict"] == "NEEDS_EVIDENCE"
    assert 0.0 <= out["confidence"] <= 1.0


def test_invalid_verdict_fallback():
    txt = '{"verdict":"MAYBE","final_severity":"ultra","confidence":2.5,"summary":"x","key_reason":"y"}'
    out = parse_verdict_from_text(txt)
    assert out["verdict"] == "NEEDS_EVIDENCE"
    assert out["final_severity"] == "info"
    assert out["confidence"] <= 1.0


def test_confidence_clamping():
    txt = '{"verdict":"CONFIRMED","final_severity":"critical","confidence":-5}'
    out = parse_verdict_from_text(txt)
    assert out["confidence"] >= 0.0


def test_debate_disabled_by_default(monkeypatch):
    monkeypatch.delenv("BOUNTYOS_DEBATE_ENABLED", raising=False)
    assert not debate_enabled()

