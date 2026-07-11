"""Liveness/readiness probes and Prometheus metrics."""
from __future__ import annotations

from fastapi import APIRouter, Response
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from fastapi import Depends

from app.core.database import get_db
from app.core.opensearch import get_opensearch

router = APIRouter(tags=["system"])


@router.get("/health")
async def health():
    return {"status": "ok"}


@router.get("/ready")
async def ready(db: AsyncSession = Depends(get_db)):
    out: dict = {"db": False, "opensearch": False}
    try:
        await db.execute(text("SELECT 1"))
        out["db"] = True
    except Exception as e:
        out["db_error"] = str(e)
    try:
        get_opensearch().info()
        out["opensearch"] = True
    except Exception as e:
        out["opensearch_error"] = str(e)
    out["status"] = "ok" if (out["db"] and out["opensearch"]) else "degraded"
    return out


@router.get("/metrics", include_in_schema=False)
async def metrics():
    try:
        from prometheus_client import CONTENT_TYPE_LATEST, generate_latest
        return Response(content=generate_latest(), media_type=CONTENT_TYPE_LATEST)
    except Exception:
        return Response(content="# prometheus_client not installed\n", media_type="text/plain")
