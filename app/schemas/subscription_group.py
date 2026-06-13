import uuid
from datetime import datetime

from pydantic import BaseModel


class SubscriptionGroupCreate(BaseModel):
    name: str


class SubscriptionGroupResponse(BaseModel):
    id: uuid.UUID
    name: str
    created_at: datetime

    model_config = {"from_attributes": True}
