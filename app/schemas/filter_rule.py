import uuid
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, field_validator


class FilterRuleCreate(BaseModel):
    description: str = ""
    pattern: str
    action: Literal["block", "allow"] = "block"
    is_active: bool = True

    @field_validator("pattern")
    @classmethod
    def pattern_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("pattern must not be empty")
        return v


class FilterRuleUpdate(BaseModel):
    description: str | None = None
    pattern: str | None = None
    action: Literal["block", "allow"] | None = None
    is_active: bool | None = None

    @field_validator("pattern")
    @classmethod
    def pattern_not_empty(cls, v: str | None) -> str | None:
        if v is not None:
            v = v.strip()
            if not v:
                raise ValueError("pattern must not be empty")
        return v


class FilterRuleResponse(BaseModel):
    id: uuid.UUID
    description: str
    pattern: str
    action: str
    is_active: bool
    created_at: datetime

    model_config = {"from_attributes": True}
