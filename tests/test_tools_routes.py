from fastapi.testclient import TestClient
from sqlmodel import Session, select

from api.main import app
from api.models import Finding, Scan, Target
from api.database import engine


def test_tools_routes_return_tool_mapping():
    with TestClient(app) as client:
        response = client.get("/api/v1/tools/available")
    assert response.status_code == 200
    data = response.json()
    assert isinstance(data, dict)
    assert "headers" in data
    assert data["headers"]["available"] is True
    assert data["headers"]["phase"] == "vulnscan"


def test_finding_false_positive_filter_selects_only_real_findings():
    with Session(engine) as session:
        target = Target(name="Filter Test", domain="example.com", scope="example.com")
        session.add(target)
        session.commit()
        session.refresh(target)

        scan = Scan(target_id=target.id)
        session.add(scan)
        session.commit()
        session.refresh(scan)

        real = Finding(scan_id=scan.id, title="Real finding", severity="high", false_positive=False)
        false_positive = Finding(scan_id=scan.id, title="False positive", severity="low", false_positive=True)
        session.add(real)
        session.add(false_positive)
        session.commit()

        findings = session.exec(
            select(Finding)
            .where(Finding.scan_id == scan.id)
            .where(Finding.false_positive == False)  # noqa: E712
        ).all()

    assert [finding.title for finding in findings] == ["Real finding"]
