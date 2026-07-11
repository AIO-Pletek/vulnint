"""Aggregate API v1 routers."""
from fastapi import APIRouter

from app.api.v1 import (
    agents,
    alert_rules,
    alerts,
    audit,
    auth,
    correlations,
    cves,
    dashboard,
    feeds,
    health,
    inventory,
    roles,
    servers,
    users,
)

api_router = APIRouter()
api_router.include_router(agents.router)
api_router.include_router(auth.router)
api_router.include_router(users.router)
api_router.include_router(roles.router)
api_router.include_router(servers.router)
api_router.include_router(inventory.router)
api_router.include_router(cves.router)
api_router.include_router(correlations.router)
api_router.include_router(alerts.router)
api_router.include_router(alert_rules.router)
api_router.include_router(feeds.router)
api_router.include_router(audit.router)
api_router.include_router(dashboard.router)
api_router.include_router(health.router)
