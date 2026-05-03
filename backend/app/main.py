from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router
from app.cache import cache_client
from app.config import get_settings
from app.database import init_db


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await cache_client.connect()
    yield
    await cache_client.close()


settings = get_settings()
app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


app.include_router(router, prefix="/api")

