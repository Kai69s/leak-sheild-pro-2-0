import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request


SCAN_LIMIT = 20
SCAN_WINDOW_SECONDS = 10 * 60
_scan_requests: dict[str, deque[float]] = defaultdict(deque)


def enforce_scan_rate_limit(request: Request) -> None:
    forwarded = request.headers.get("x-forwarded-for", "").split(",", 1)[0].strip()
    client = forwarded or (request.client.host if request.client else "unknown")
    now = time.monotonic()
    bucket = _scan_requests[client]
    while bucket and bucket[0] <= now - SCAN_WINDOW_SECONDS:
        bucket.popleft()
    if len(bucket) >= SCAN_LIMIT:
        retry_after = max(1, int(SCAN_WINDOW_SECONDS - (now - bucket[0])))
        raise HTTPException(
            status_code=429,
            detail="Scan limit reached. Please wait before starting another assessment.",
            headers={"Retry-After": str(retry_after)},
        )
    bucket.append(now)
