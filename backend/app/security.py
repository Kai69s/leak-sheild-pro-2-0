import hashlib
import ipaddress
import os
import time
from collections import defaultdict, deque
from uuid import UUID

from fastapi import HTTPException, Request
from starlette.responses import JSONResponse


MAX_REQUEST_BYTES = 2_000_000
MAX_RATE_LIMIT_BUCKETS = 10_000
SCAN_LIMIT = 8
SCAN_WINDOW_SECONDS = 10 * 60
ADMIN_LOGIN_LIMIT = 5
ADMIN_LOGIN_WINDOW_SECONDS = 15 * 60
SESSION_HEADER = "x-leakshield-session"
_rate_requests: dict[str, deque[float]] = defaultdict(deque)


class RequestBodyLimitMiddleware:
    """Reject oversized request bodies before validation or scanning allocates more memory."""

    def __init__(self, app, max_bytes: int = MAX_REQUEST_BYTES) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        headers = dict(scope.get("headers", []))
        content_length = headers.get(b"content-length")
        if content_length:
            try:
                if int(content_length) > self.max_bytes:
                    await self._reject(scope, receive, send)
                    return
            except ValueError:
                await self._reject(scope, receive, send, status_code=400, detail="Invalid Content-Length header")
                return

        received = 0

        async def limited_receive():
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(status_code=413, detail="Request body is too large")
            return message

        try:
            await self.app(scope, limited_receive, send)
        except HTTPException as error:
            if error.status_code != 413:
                raise
            await self._reject(scope, receive, send)

    @staticmethod
    async def _reject(scope, receive, send, status_code: int = 413, detail: str = "Request body is too large") -> None:
        await JSONResponse({"detail": detail}, status_code=status_code)(scope, receive, send)


def _client_ip(request: Request) -> str:
    candidates = [request.client.host if request.client else ""]
    if os.getenv("VERCEL"):
        candidates = [
            request.headers.get("x-vercel-forwarded-for", ""),
            request.headers.get("x-real-ip", ""),
            *candidates,
        ]
    for candidate in candidates:
        value = candidate.split(",", 1)[0].strip().split("%", 1)[0]
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            continue
    return "unknown"


def _enforce_rate_limit(request: Request, namespace: str, limit: int, window_seconds: int) -> None:
    client = _client_ip(request)
    now = time.monotonic()
    stale_before = now - window_seconds
    bucket_key = f"{namespace}:{client}"
    bucket = _rate_requests[bucket_key]
    while bucket and bucket[0] <= stale_before:
        bucket.popleft()
    if len(bucket) >= limit:
        retry_after = max(1, int(window_seconds - (now - bucket[0])))
        raise HTTPException(
            status_code=429,
            detail="Too many requests. Please wait before trying again.",
            headers={"Retry-After": str(retry_after)},
        )
    bucket.append(now)

    if len(_rate_requests) > MAX_RATE_LIMIT_BUCKETS:
        for key in list(_rate_requests):
            values = _rate_requests[key]
            if not values or values[-1] <= stale_before:
                _rate_requests.pop(key, None)
        while len(_rate_requests) > MAX_RATE_LIMIT_BUCKETS:
            _rate_requests.pop(next(iter(_rate_requests)))


def enforce_scan_rate_limit(request: Request) -> None:
    _enforce_rate_limit(request, "scan", SCAN_LIMIT, SCAN_WINDOW_SECONDS)


def enforce_admin_login_rate_limit(request: Request) -> None:
    _enforce_rate_limit(request, "admin-login", ADMIN_LOGIN_LIMIT, ADMIN_LOGIN_WINDOW_SECONDS)


def scan_owner_id(request: Request) -> str:
    raw = request.headers.get(SESSION_HEADER, "").strip()
    try:
        parsed = UUID(raw)
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail=f"A valid {SESSION_HEADER} header is required") from None
    if parsed.version != 4 or str(parsed) != raw.lower():
        raise HTTPException(status_code=400, detail=f"A valid {SESSION_HEADER} header is required")
    return hashlib.sha256(f"leakshield-session:{parsed}".encode()).hexdigest()
