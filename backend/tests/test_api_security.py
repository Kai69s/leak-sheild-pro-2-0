from fastapi.testclient import TestClient

from app.main import app
from app.security import _rate_requests


SESSION_A = "98a89f3c-b1ee-4b53-93ee-ff0cd7660c54"
SESSION_B = "6e1e72a3-825e-479c-ab05-f46b7d6af742"


def test_scan_history_is_isolated_between_browser_sessions() -> None:
    _rate_requests.clear()
    with TestClient(app) as client:
        created = client.post(
            "/api/scans",
            headers={"X-LeakShield-Session": SESSION_A},
            json={
                "mode": "text",
                "source_name": "ownership-test.env",
                "content": "password='UniqueProductionOwnershipPassword2026!'",
            },
        )
        assert created.status_code == 201
        scan_id = created.json()["id"]

        own_history = client.get("/api/scans", headers={"X-LeakShield-Session": SESSION_A})
        other_history = client.get("/api/scans", headers={"X-LeakShield-Session": SESSION_B})
        other_detail = client.get(f"/api/scans/{scan_id}", headers={"X-LeakShield-Session": SESSION_B})

    assert any(item["id"] == scan_id for item in own_history.json())
    assert all(item["id"] != scan_id for item in other_history.json())
    assert other_detail.status_code == 404


def test_scan_requires_a_canonical_session_identifier() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/scans",
            headers={"X-LeakShield-Session": "not-a-session"},
            json={"mode": "text", "content": "safe text"},
        )

    assert response.status_code == 400


def test_request_body_limit_rejects_oversized_payloads() -> None:
    with TestClient(app) as client:
        response = client.post(
            "/api/scans",
            headers={"X-LeakShield-Session": SESSION_A},
            content=b"x" * 2_000_001,
        )

    assert response.status_code == 413
