import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from api.models import Finding, Severity
from api.services.report_builder import fallback_report_for_finding

def test_fallback_marks_missing_evidence():
    f=Finding(scan_id='s', title='XSS', severity=Severity.HIGH)
    report=fallback_report_for_finding(f)
    assert 'Missing evidence' in report['evidence']
    assert 'no evidence invented' in report['timeline_notes'].lower()
