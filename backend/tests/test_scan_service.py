from unittest.mock import AsyncMock

import pytest

from app.cache import cache_client
from app.schemas import ScanRequest
from app.services.scan_service import ScanService


@pytest.mark.asyncio
async def test_cached_scan_sets_cache_hit_without_duplicate_keyword(monkeypatch) -> None:
    cached = {
        "id": "b54bd2de-f465-48c4-9095-0d5e15b22fea",
        "source_name": "cached.env",
        "content_hash": "a" * 64,
        "overall_score": 0,
        "overall_level": "LOW",
        "finding_count": 0,
        "cache_hit": False,
        "created_at": None,
        "findings": [],
    }
    monkeypatch.setattr(cache_client, "get_json", AsyncMock(return_value=cached))

    response = await ScanService(AsyncMock(), "a" * 64).scan(
        ScanRequest(content="safe content", source_name="cached.env")
    )

    assert response.cache_hit is True
