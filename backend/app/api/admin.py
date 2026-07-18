import base64
import binascii
import hashlib
import hmac
import json
import os
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Annotated, Any

from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import delete, desc, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.database import get_session
from app.models import Finding, Scan


router = APIRouter(prefix="/admin", tags=["admin"])
SESSION_TTL_SECONDS = 8 * 60 * 60


class AdminLogin(BaseModel):
    email: str = Field(min_length=3, max_length=320)
    password: str = Field(min_length=1, max_length=1024)


def _credentials() -> list[tuple[str, str]]:
    credentials: list[tuple[str, str]] = []
    for email_key, password_key in (
        ("ADMIN_EMAIL", "ADMIN_PASSWORD"),
        ("ADMIN_EXTRA_EMAIL", "ADMIN_EXTRA_PASSWORD"),
    ):
        email = os.getenv(email_key, "")
        password = os.getenv(password_key, "")
        if email and password:
            credentials.append((email, password))

    try:
        additional = json.loads(os.getenv("ADMIN_ADDITIONAL_CREDENTIALS", "[]"))
    except json.JSONDecodeError:
        additional = []
    for item in additional if isinstance(additional, list) else []:
        if isinstance(item, dict) and item.get("email") and item.get("password"):
            credentials.append((str(item["email"]), str(item["password"])))
    return credentials


def _session_secret() -> bytes:
    configured = os.getenv("ADMIN_SESSION_SECRET", "")
    if configured:
        return configured.encode()
    seed = "|".join(f"{email}:{password}" for email, password in _credentials())
    return hashlib.sha256(seed.encode()).digest()


def _safe_equal(left: str, right: str) -> bool:
    return hmac.compare_digest(hashlib.sha256(left.encode()).digest(), hashlib.sha256(right.encode()).digest())


def _encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).decode().rstrip("=")


def _decode(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def _create_token(email: str) -> str:
    payload = _encode(
        json.dumps({"email": email, "exp": int(time.time()) + SESSION_TTL_SECONDS}, separators=(",", ":")).encode()
    )
    signature = _encode(hmac.new(_session_secret(), payload.encode(), hashlib.sha256).digest())
    return f"{payload}.{signature}"


def _authenticated_admin(authorization: Annotated[str | None, Header()] = None) -> str:
    token = authorization.removeprefix("Bearer ") if authorization else ""
    try:
        payload, signature = token.split(".", 1)
        expected = _encode(hmac.new(_session_secret(), payload.encode(), hashlib.sha256).digest())
        decoded = json.loads(_decode(payload))
        if not hmac.compare_digest(signature, expected) or decoded.get("exp", 0) < time.time():
            raise ValueError
        return str(decoded["email"])
    except (binascii.Error, KeyError, UnicodeDecodeError, ValueError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Admin authentication required") from None


def _iso(value: datetime | None) -> str:
    return (value or datetime.now(timezone.utc)).isoformat()


def _redacted_record(scan: Scan) -> dict[str, Any]:
    session_id = str(scan.scan_metadata.get("client_session_id") or "anonymous")
    user_id = f"usr_{hashlib.sha256(session_id.encode()).hexdigest()[:18]}"
    findings = [
        {
            "rule_id": finding.rule_id,
            "secret_type": finding.secret_type,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "risk_level": finding.risk_level,
            "file_path": None,
            "explanation": finding.explanation,
        }
        for finding in scan.findings
    ]
    return {
        "id": scan.id,
        "created_at": _iso(scan.created_at),
        "session_id": session_id,
        "user_id": user_id,
        "storage_scope": "redacted_user_box",
        "storage_path": f"database/{user_id}/{scan.id}",
        "consent": {"storage": "redacted_scan_summary"},
        "request_context": {"network_data": "not_collected"},
        "submitted_input": {"mode": "text", "source_name": scan.source_name},
        "result_shown_to_user": {
            "id": scan.id,
            "source_name": scan.source_name,
            "overall_score": scan.overall_score,
            "overall_level": scan.overall_level,
            "finding_count": scan.finding_count,
            "public_exposure_count": 0,
            "scanned_addresses": [],
            "recommendation": None,
            "findings": findings,
        },
    }


def _group_users(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    grouped: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for record in records:
        grouped[record["user_id"]].append(record)

    users = []
    for user_id, user_records in grouped.items():
        latest = user_records[0]
        users.append(
            {
                "id": user_id,
                "session_id": latest["session_id"],
                "first_seen_at": user_records[-1]["created_at"],
                "latest_seen_at": latest["created_at"],
                "scan_count": len(user_records),
                "finding_count": sum(item["result_shown_to_user"]["finding_count"] for item in user_records),
                "critical_count": sum(
                    item["result_shown_to_user"]["overall_level"] == "CRITICAL" for item in user_records
                ),
                "latest_risk": latest["result_shown_to_user"]["overall_level"],
                "records": user_records,
            }
        )
    return users


@router.post("")
async def login(payload: AdminLogin) -> dict[str, str]:
    credentials = _credentials()
    if not credentials:
        raise HTTPException(status_code=503, detail="Admin credentials are not configured")
    admin = next(
        (
            email
            for email, password in credentials
            if _safe_equal(payload.email.lower(), email.lower()) and _safe_equal(payload.password, password)
        ),
        None,
    )
    if not admin:
        raise HTTPException(status_code=401, detail="Invalid admin credentials")
    return {"token": _create_token(admin), "email": admin}


@router.get("")
async def audit_dashboard(
    admin: Annotated[str, Depends(_authenticated_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, Any]:
    result = await session.execute(
        select(Scan).options(selectinload(Scan.findings)).order_by(desc(Scan.created_at)).limit(500)
    )
    records = [_redacted_record(scan) for scan in result.scalars().all()]
    return {
        "admin": admin,
        "records": records,
        "users": _group_users(records),
        "storage": {"provider": "database", "grouping": "one_user_box_per_browser_session"},
    }


@router.delete("")
async def clear_audit_dashboard(
    _admin: Annotated[str, Depends(_authenticated_admin)],
    session: Annotated[AsyncSession, Depends(get_session)],
) -> dict[str, bool]:
    await session.execute(delete(Finding))
    await session.execute(delete(Scan))
    await session.commit()
    return {"ok": True}
