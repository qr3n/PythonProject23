import uuid
from datetime import datetime

from pydantic import BaseModel, HttpUrl, model_validator


class ProviderSubCreate(BaseModel):
    alias: str = ""
    url: str  # subscription URL from provider
    expires_at: datetime | None = None
    traffic_total_gb: float | None = None
    group_id: uuid.UUID | None = None
    auto_refresh: bool = True  # fetch outbounds immediately on creation


class ProviderSubCreateResponse(BaseModel):
    """Response for POST /provider-subs — includes the created sub + optional fetch warning."""
    id: uuid.UUID
    alias: str
    url: str
    expires_at: datetime | None
    traffic_total_gb: float | None
    traffic_used_gb: float | None
    last_fetched_at: datetime | None
    is_active: bool
    created_at: datetime
    outbound_count: int = 0
    warning: str | None = None  # set if auto_refresh failed or returned 0 outbounds

    model_config = {"from_attributes": True}


class ProviderSubUpdate(BaseModel):
    alias: str | None = None
    url: str | None = None
    expires_at: datetime | None = None
    traffic_total_gb: float | None = None
    traffic_used_gb: float | None = None
    group_id: uuid.UUID | None = None
    is_active: bool | None = None


class ProviderSubResponse(BaseModel):
    id: uuid.UUID
    alias: str
    url: str
    expires_at: datetime | None
    traffic_total_gb: float | None
    traffic_used_gb: float | None
    last_fetched_at: datetime | None
    group_id: uuid.UUID | None = None
    is_active: bool
    created_at: datetime
    outbound_count: int = 0

    model_config = {"from_attributes": True}


class RefreshResult(BaseModel):
    outbound_count: int
    traffic_used_gb: float | None
    traffic_total_gb: float | None
    expires_at: datetime | None
    message: str
