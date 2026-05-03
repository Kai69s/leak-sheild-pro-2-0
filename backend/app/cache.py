import json
from typing import Any

from redis.asyncio import Redis

from app.config import get_settings


class CacheClient:
    def __init__(self) -> None:
        self._settings = get_settings()
        self._redis: Redis | None = None

    async def connect(self) -> None:
        self._redis = Redis.from_url(self._settings.redis_url, decode_responses=True)
        await self._redis.ping()

    async def close(self) -> None:
        if self._redis:
            await self._redis.aclose()

    async def get_json(self, key: str) -> dict[str, Any] | None:
        if not self._redis:
            return None
        raw = await self._redis.get(key)
        return json.loads(raw) if raw else None

    async def set_json(self, key: str, value: dict[str, Any], ttl: int | None = None) -> None:
        if not self._redis:
            return
        await self._redis.set(key, json.dumps(value), ex=ttl or self._settings.cache_ttl_seconds)


cache_client = CacheClient()

