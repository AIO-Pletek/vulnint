"""Regression test for the auth/HTTP exception handling.

Earlier the catch-all `@app.exception_handler(Exception)` was swallowing
HTTPException, turning every 401/403/404 into an opaque 500 with
"An internal error occurred". This test pins that behavior down.
"""
from __future__ import annotations

from fastapi import FastAPI, HTTPException, status
from fastapi.exceptions import RequestValidationError
from fastapi.testclient import TestClient
from fastapi.responses import JSONResponse


def _make_app_with_handlers() -> FastAPI:
    """Build a minimal app with the same exception-handler shape as main.py."""
    app = FastAPI()

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request, exc):
        return JSONResponse(status_code=422, content={"error": "validation_error"})

    @app.exception_handler(Exception)
    async def _internal_handler(request, exc):
        from fastapi.exceptions import HTTPException as FastAPIHTTPException
        from starlette.exceptions import HTTPException as StarletteHTTPException
        if isinstance(exc, (FastAPIHTTPException, StarletteHTTPException)):
            raise exc
        return JSONResponse(status_code=500, content={"error": "internal_error"})

    @app.get("/raises-401")
    async def raise_401():
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")

    @app.get("/raises-404")
    async def raise_404():
        raise HTTPException(status.HTTP_404_NOT_FOUND, detail="Not found")

    @app.get("/raises-zero-div")
    async def raise_zerodiv():
        return 1 / 0

    return app


def test_http_401_is_preserved():
    """Wrong-password 401 must NOT be swallowed by the catch-all."""
    client = TestClient(_make_app_with_handlers(), raise_server_exceptions=False)
    r = client.get("/raises-401")
    assert r.status_code == 401, f"Got {r.status_code}: {r.text}"
    assert r.json()["detail"] == "Invalid credentials"


def test_http_404_is_preserved():
    client = TestClient(_make_app_with_handlers(), raise_server_exceptions=False)
    r = client.get("/raises-404")
    assert r.status_code == 404
    assert r.json()["detail"] == "Not found"


def test_genuine_unhandled_exception_returns_500():
    """A real bug (ZeroDivisionError) should still surface as 500."""
    client = TestClient(_make_app_with_handlers(), raise_server_exceptions=False)
    r = client.get("/raises-zero-div")
    assert r.status_code == 500
    assert r.json()["error"] == "internal_error"
