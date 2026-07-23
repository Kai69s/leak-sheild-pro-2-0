from collections.abc import AsyncGenerator
import logging
import os
from pathlib import Path
from tempfile import gettempdir

from sqlalchemy import inspect, text
from sqlalchemy.ext.asyncio import AsyncConnection, AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import DeclarativeBase

from app.config import get_settings


class Base(DeclarativeBase):
    pass


settings = get_settings()
database_url = settings.database_url
logger = logging.getLogger(__name__)
if "@localhost:" in database_url or "@127.0.0.1:" in database_url or (
    os.getenv("VERCEL") and database_url.startswith("sqlite+aiosqlite")
):
    fallback_path = Path(gettempdir()) / "leakshield.db"
    database_url = f"sqlite+aiosqlite:///{fallback_path}"

engine_kwargs = {"pool_pre_ping": True}
if database_url.startswith("sqlite+aiosqlite"):
    engine_kwargs["connect_args"] = {"check_same_thread": False}
else:
    engine_kwargs.update({"pool_size": 10, "max_overflow": 20})

engine = create_async_engine(database_url, **engine_kwargs)
AsyncSessionLocal = async_sessionmaker(engine, expire_on_commit=False, class_=AsyncSession)


def _fallback_sqlite_engine() -> tuple[object, async_sessionmaker[AsyncSession]]:
    fallback_path = Path(gettempdir()) / "leakshield.db"
    fallback_url = f"sqlite+aiosqlite:///{fallback_path.as_posix()}"
    fallback_engine = create_async_engine(fallback_url, connect_args={"check_same_thread": False})
    fallback_session = async_sessionmaker(fallback_engine, expire_on_commit=False, class_=AsyncSession)
    return fallback_engine, fallback_session


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        yield session


async def _ensure_owner_column(conn: AsyncConnection) -> None:
    columns = await conn.run_sync(lambda sync_conn: {column["name"] for column in inspect(sync_conn).get_columns("scans")})
    if "owner_id" not in columns:
        await conn.execute(text("ALTER TABLE scans ADD COLUMN owner_id VARCHAR(64)"))
        await conn.execute(text("CREATE INDEX IF NOT EXISTS ix_scans_owner_id ON scans (owner_id)"))


async def init_db() -> None:
    global engine, AsyncSessionLocal

    from app import models  # noqa: F401

    try:
        async with engine.begin() as conn:
            await conn.run_sync(Base.metadata.create_all)
            await _ensure_owner_column(conn)
    except Exception:
        if not database_url.startswith("sqlite+aiosqlite"):
            logger.warning("Primary database unavailable; using temporary SQLite fallback")
            engine, AsyncSessionLocal = _fallback_sqlite_engine()
            async with engine.begin() as conn:
                await conn.run_sync(Base.metadata.create_all)
                await _ensure_owner_column(conn)
        else:
            raise

