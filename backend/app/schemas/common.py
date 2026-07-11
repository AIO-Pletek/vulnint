"""Common schemas: pagination, errors."""
from __future__ import annotations

from typing import Generic, List, Optional, TypeVar

from pydantic import BaseModel, Field

T = TypeVar("T")


class Page(BaseModel, Generic[T]):
    items: List[T]
    total: int
    page: int = 1
    page_size: int = 25
    pages: int = 1


class PageParams(BaseModel):
    page: int = Field(1, ge=1)
    page_size: int = Field(25, ge=1, le=200)
    sort: Optional[str] = None
    order: Optional[str] = Field(default="desc", pattern="^(asc|desc)$")


class ErrorDetail(BaseModel):
    code: str
    message: str
    field: Optional[str] = None


class ErrorResponse(BaseModel):
    error: ErrorDetail


class HealthCheck(BaseModel):
    status: str
    version: str = "1.0.0"
    components: dict = {}
