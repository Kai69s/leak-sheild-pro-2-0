import asyncio

import httpx
import pytest
from fastapi import HTTPException

from app.engines.assessment.website import (
    _assert_public_url,
    _clean_url,
    _finding,
    _grade,
    _header_assessment,
    _pinned_request,
    _subdomain_assessment,
)


def test_header_assessment_reports_missing_controls() -> None:
    headers = _header_assessment({"content-security-policy": "default-src 'self'"})

    csp = next(item for item in headers if item["name"] == "Content-Security-Policy")
    hsts = next(item for item in headers if item["name"] == "Strict-Transport-Security")

    assert csp["present"] is True
    assert hsts["present"] is False
    assert hsts["risk"] == "HIGH"


def test_finding_contains_learning_mode_and_official_references() -> None:
    finding = _finding(
        "missing-csp",
        "Missing Content-Security-Policy",
        "HIGH",
        "headers",
        "CSP is missing.",
        "Add a restrictive policy.",
        "https://example.com/",
        "Content-Security-Policy",
        "default-src 'self'",
    )

    learning = finding["explanation"]["learning"]
    assert learning["remediation_steps"]
    assert all(reference["url"].startswith("https://") for reference in learning["references"])
    assert finding["explanation"]["developer_fixes"]["snippets"]["Nginx"]


@pytest.mark.parametrize(("score", "grade"), [(95, "A"), (84, "B"), (72, "C"), (60, "D"), (20, "F")])
def test_security_grade(score: float, grade: str) -> None:
    assert _grade(score) == grade


def test_private_targets_are_rejected(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.engines.assessment.website.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )

    with pytest.raises(HTTPException, match="Private"):
        asyncio.run(_assert_public_url("http://internal.example"))


def test_url_credentials_and_query_values_are_not_retained() -> None:
    assert _clean_url("https://user:secret@example.com/path?token=private#section") == "https://example.com/path"


def test_validated_hostname_is_pinned_to_its_public_address() -> None:
    request_url, headers, extensions = _pinned_request("https://example.com:8443/path", "93.184.216.34")

    assert request_url == "https://93.184.216.34:8443/path"
    assert headers == {"Host": "example.com:8443"}
    assert extensions == {"sni_hostname": "example.com"}


def test_invalid_ports_are_rejected_as_validation_errors() -> None:
    with pytest.raises(HTTPException) as error:
        asyncio.run(_assert_public_url("https://example.com:99999/"))
    assert error.value.status_code == 400


def test_subdomain_resolver_exhaustion_does_not_abort_assessment(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.engines.assessment.website.socket.getaddrinfo",
        lambda *_args, **_kwargs: (_ for _ in ()).throw(OSError(16, "Device or resource busy")),
    )
    transport = httpx.MockTransport(lambda _request: httpx.Response(200, json=[]))

    async def run() -> list[dict]:
        async with httpx.AsyncClient(transport=transport) as client:
            return await _subdomain_assessment(client, "example.com")

    results = asyncio.run(run())
    assert results
    assert all(item["alive"] is False for item in results)


def test_private_subdomain_addresses_are_never_requested(monkeypatch) -> None:
    monkeypatch.setattr(
        "app.engines.assessment.website.socket.getaddrinfo",
        lambda *_args, **_kwargs: [(2, 1, 6, "", ("127.0.0.1", 0))],
    )
    requested: list[str] = []

    def respond(request: httpx.Request) -> httpx.Response:
        requested.append(str(request.url))
        return httpx.Response(200, json=[])

    async def run() -> list[dict]:
        async with httpx.AsyncClient(transport=httpx.MockTransport(respond)) as client:
            return await _subdomain_assessment(client, "example.com")

    results = asyncio.run(run())
    assert requested == ["https://crt.sh/?q=%25.example.com&output=json"]
    assert all(item.get("blocked") is True for item in results)
