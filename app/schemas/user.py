import uuid
from datetime import datetime

from pydantic import BaseModel


class UserCreate(BaseModel):
    name: str = ""
    subscription_expires_at: datetime | None = None
    is_active: bool = True


class UserUpdate(BaseModel):
    name: str | None = None
    subscription_expires_at: datetime | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    id: uuid.UUID
    name: str
    token: str
    subscription_expires_at: datetime | None
    is_active: bool
    created_at: datetime

    # Convenience URLs
    sub_url: str = ""
    check_url: str = ""

    model_config = {"from_attributes": True}


class TokenResetResponse(BaseModel):
    token: str
    sub_url: str
    check_url: str
