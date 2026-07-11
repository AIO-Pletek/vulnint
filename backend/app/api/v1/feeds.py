"""Feed manual trigger endpoints."""
from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status

from app.auth.deps import require_permissions
from app.auth.permissions import Perm
from app.schemas.auth import CurrentUser
from app.workers.celery_app import celery_app
from app.workers.tasks.feeds import FEED_REGISTRY

router = APIRouter(prefix="/feeds", tags=["feeds"])


@router.get("")
async def list_feeds(_: CurrentUser = Depends(require_permissions(Perm.FEEDS_TRIGGER))):
    return [{"name": k, "class": v.__name__} for k, v in FEED_REGISTRY.items()]


@router.post("/{name}/run", status_code=status.HTTP_202_ACCEPTED)
async def run_feed(
    name: str,
    _: CurrentUser = Depends(require_permissions(Perm.FEEDS_TRIGGER)),
):
    if name not in FEED_REGISTRY:
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Unknown feed")
    res = celery_app.send_task("feeds.run", args=[name])
    return {"queued": True, "task_id": res.id, "feed": name}


@router.post("/run-all", status_code=status.HTTP_202_ACCEPTED)
async def run_all(_: CurrentUser = Depends(require_permissions(Perm.FEEDS_TRIGGER))):
    res = celery_app.send_task("feeds.run_all")
    return {"queued": True, "task_id": res.id}


@router.post("/reindex", status_code=status.HTTP_202_ACCEPTED)
async def reindex(_: CurrentUser = Depends(require_permissions(Perm.FEEDS_TRIGGER))):
    res = celery_app.send_task("opensearch.reindex_all")
    return {"queued": True, "task_id": res.id}
