from contextlib import asynccontextmanager
import logging

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app.api.routes import router
from app.cache import cache_client
from app.config import get_settings
from app.database import init_db
from app.security import RequestBodyLimitMiddleware


@asynccontextmanager
async def lifespan(app: FastAPI):
    await init_db()
    await cache_client.connect()
    yield
    await cache_client.close()


settings = get_settings()
app = FastAPI(title=settings.app_name, version="1.0.0", lifespan=lifespan)

logging.getLogger("httpx").setLevel(logging.WARNING)

app.add_middleware(RequestBodyLimitMiddleware)
app.add_middleware(TrustedHostMiddleware, allowed_hosts=settings.allowed_hosts)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origins,
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.middleware("http")
async def api_security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["Cache-Control"] = "no-store" if request.url.path.startswith("/api/") else response.headers.get("Cache-Control", "no-cache")
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), geolocation=(), microphone=()"
    return response


@app.get("/health")
@app.get("/api/health")
async def health() -> dict[str, str]:
    return {"status": "ok", "service": settings.app_name}


app.include_router(router, prefix="/api")

