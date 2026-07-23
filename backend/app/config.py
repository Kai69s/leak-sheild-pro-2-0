import os
from functools import lru_cache

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    app_name: str = "LeakShield Pro"
    environment: str = "development"
    database_url: str = "sqlite+aiosqlite:///./leakshield.db"
    redis_url: str = "redis://localhost:6379/0"
    cors_origins: list[str] = Field(
        default_factory=lambda: [
            "http://localhost:5173",
            "http://localhost:5174",
            "http://127.0.0.1:5173",
            "http://127.0.0.1:5174",
            *([f"https://{os.getenv('VERCEL_URL')}"] if os.getenv("VERCEL_URL") else []),
        ]
    )
    allowed_hosts: list[str] = Field(
        default_factory=lambda: [
            "localhost",
            "127.0.0.1",
            "backend",
            "testserver",
            "*.vercel.app",
            "leak-sheild-pro-2-0.vercel.app",
            *([os.getenv("VERCEL_URL", "")] if os.getenv("VERCEL_URL") else []),
        ]
    )
    cache_ttl_seconds: int = 3600
    max_scan_bytes: int = 262_144

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

    @field_validator("cors_origins", mode="before")
    @classmethod
    def split_origins(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [origin.strip() for origin in value.split(",") if origin.strip()]
        return value

    @field_validator("allowed_hosts", mode="before")
    @classmethod
    def split_hosts(cls, value: str | list[str]) -> list[str]:
        if isinstance(value, str):
            return [host.strip() for host in value.split(",") if host.strip()]
        return value


@lru_cache
def get_settings() -> Settings:
    return Settings()

