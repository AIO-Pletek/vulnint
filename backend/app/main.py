"""FastAPI application entrypoint."""
from __future__ import annotations

from contextlib import asynccontextmanager

import structlog
from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from slowapi.middleware import SlowAPIMiddleware
from slowapi.util import get_remote_address
from starlette.middleware.base import BaseHTTPMiddleware

from app.api.router import api_router
from app.core.config import settings
from app.core.logging import configure_logging
from app.core.opensearch import ensure_indices

configure_logging()
log = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("vulnint.starting", env=settings.ENV)
    try:
        ensure_indices()
    except Exception as e:
        log.warning("opensearch.unreachable", err=str(e))
    yield
    log.info("vulnint.stopping")


limiter = Limiter(key_func=get_remote_address, default_limits=[f"{settings.RATE_LIMIT_PER_MINUTE}/minute"])

app = FastAPI(
    title=settings.PROJECT_NAME,
    version="1.0.0",
    description="Vulnerability Intelligence & Management Platform",
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)
app.add_middleware(SlowAPIMiddleware)


class SecureHeadersMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        resp.headers.setdefault("Permissions-Policy", "geolocation=(), microphone=()")
        if settings.ENV == "production":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
        return resp


app.add_middleware(SecureHeadersMiddleware)
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS or ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(RequestValidationError)
async def _validation_handler(request: Request, exc: RequestValidationError):
    return JSONResponse(
        status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
        content={"error": "validation_error", "detail": exc.errors()},
    )


@app.exception_handler(Exception)
async def _internal_handler(request: Request, exc: Exception):
    # CRITICAL: HTTPException and StarletteHTTPException must be re-raised
    # so FastAPI's built-in handler renders proper status codes (401, 403,
    # 404, 422, etc.). Without this guard, every "wrong password" returns
    # 500 "An internal error occurred", which is both wrong and confusing.
    from fastapi.exceptions import HTTPException as FastAPIHTTPException
    from starlette.exceptions import HTTPException as StarletteHTTPException
    if isinstance(exc, (FastAPIHTTPException, StarletteHTTPException)):
        raise exc
    log.exception("unhandled_exception", path=request.url.path, error=str(exc))
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"error": "internal_error", "detail": "An internal error occurred"},
    )


app.include_router(api_router, prefix="/api/v1")


# Root-level liveness/readiness for container orchestration probes.
# These deliberately bypass /api/v1 because Docker, Kubernetes, and most
# upstream load balancers expect /health at the root.
@app.get("/health", include_in_schema=False)
async def _root_health():
    return {"status": "ok"}


@app.get("/ready", include_in_schema=False)
async def _root_ready():
    """Readiness probe — verifies dependencies are reachable."""
    from sqlalchemy import text
    from app.core.database import AsyncSessionLocal
    from app.core.opensearch import get_opensearch

    out: dict = {"db": False, "opensearch": False}
    try:
        async with AsyncSessionLocal() as db:
            await db.execute(text("SELECT 1"))
            out["db"] = True
    except Exception as e:
        out["db_error"] = str(e)[:200]
    try:
        get_opensearch().info()
        out["opensearch"] = True
    except Exception as e:
        out["opensearch_error"] = str(e)[:200]
    out["status"] = "ok" if (out["db"] and out["opensearch"]) else "degraded"
    return out


@app.get("/", include_in_schema=False)
async def root():
    return {
        "name": settings.PROJECT_NAME,
        "version": "1.0.0",
        "docs": "/docs",
    }
