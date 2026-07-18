from collections.abc import AsyncGenerator
from pathlib import Path

from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
database_url = settings.database_url
if database_url.startswith("postgresql+asyncpg://localhost") or database_url.startswith(
    "postgresql+asyncpg://127.0.0.1"
):
    fallback_path = Path("/tmp/leakshield.db")
    database_url = f"sqlite+aiosqlite:///{fallback_path}"

engine_kwargs = {"pool_pre_ping": True}
if database_url.startswith("sqlite+aiosqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs.update({"pool_size": 10, "max_overflow": 20})

engine = create_async_engine(database_url, **engine_kwargs)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def _fallback_sqlite_engine() -> tuple[object, async_sessionmaker[AsyncSession]]:
    fallback_url = "sqlite+aiosqlite:////tmp/leakshield.db"
    fallback_engine = create_async_engine(fallback_url, connect_args={"check_same_thread": False})
    fallback_session = async_sessionmaker(fallback_engine, expire_on_commit=False, class_=AsyncSession)
    return fallback_engine, fallback_session


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def init_db() -> None:
    global engine, AsyncSessionLocal

    from app import models  # noqa: F401

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
    except Exception:
        if not database_url.startswith("sqlite+aiosqlite"):
            engine, AsyncSessionLocal = _fallback_sqlite_engine()
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
        else:
            raise

