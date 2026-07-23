from fastapi.testclient import TestClient

from app.api.admin import _authenticated_admin, _group_users
from app.main import app


def test_admin_login_creates_a_verifiable_session(monkeypatch) -> None:
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.test")
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-password")
    monkeypatch.setenv("ADMIN_SESSION_SECRET", "test-session-secret")

    response = TestClient(app).post(
        "/api/admin",
        json={"email": "admin@example.test", "password": "correct-password"},
    )

    assert response.status_code == 200
    assert _authenticated_admin(f"Bearer {response.json()['token']}") == "admin@example.test"


def test_admin_login_is_mounted_at_api_route(monkeypatch) -> None:
    monkeypatch.setenv("ADMIN_EMAIL", "admin@example.test")
    monkeypatch.setenv("ADMIN_PASSWORD", "correct-password")
    monkeypatch.setenv("ADMIN_SESSION_SECRET", "test-session-secret")

    response = TestClient(app).post(
        "/api/admin",
        json={"email": "admin@example.test", "password": "correct-password"},
    )

    assert response.status_code == 200
    assert response.json()["token"]


def test_audit_records_are_grouped_by_redacted_user_id() -> None:
    records = [
        {
            "user_id": "usr_one",
            "session_id": "browser-session",
            "created_at": "2026-07-19T12:00:00+00:00",
            "result_shown_to_user": {"finding_count": 2, "overall_level": "CRITICAL"},
        },
        {
            "user_id": "usr_one",
            "session_id": "browser-session",
            "created_at": "2026-07-19T11:00:00+00:00",
            "result_shown_to_user": {"finding_count": 1, "overall_level": "LOW"},
        },
    ]

    users = _group_users(records)

    assert users[0]["scan_count"] == 2
    assert users[0]["finding_count"] == 3
    assert users[0]["critical_count"] == 1
