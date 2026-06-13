import uuid
from datetime import datetime, timezone

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column
from sqlalchemy import Enum as SAEnum
import enum


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


class Base(DeclarativeBase):
    pass


class SubscriptionGroup(Base):
    """Named group that clusters provider subscriptions together."""

    __tablename__ = "subscription_groups"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(Text, nullable=False, unique=True)
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class ProviderSubscription(Base):
    __tablename__ = "provider_subscriptions"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    alias: Mapped[str] = mapped_column(Text, nullable=False, default="")
    url: Mapped[str] = mapped_column(Text, nullable=False)

    # Optional group membership; SET NULL on group deletion
    group_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("subscription_groups.id", ondelete="SET NULL"),
        nullable=True,
        index=True,
    )

    # Admin-supplied or parsed from Subscription-UserInfo header
    expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    traffic_total_gb: Mapped[float | None] = mapped_column(Float, nullable=True)
    traffic_used_gb: Mapped[float | None] = mapped_column(Float, nullable=True)

    # Cached parsed outbounds (list of raw xray outbound dicts)
    outbounds_json: Mapped[list | None] = mapped_column(JSONB, nullable=True)

    last_fetched_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class User(Base):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    name: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Single token used for both /sub/{token} and /check/{token}
    token: Mapped[str] = mapped_column(
        String(64), unique=True, nullable=False, index=True
    )

    subscription_expires_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )


class FilterAction(str, enum.Enum):
    block = "block"    # exclude outbounds matching the pattern
    allow = "allow"    # allow ONLY outbounds matching the pattern (whitelist mode)


class AddressFilterRule(Base):
    """
    Admin-managed address filter rules applied to the outbound pool.

    Each rule stores one pattern (glob / CIDR / /regex/) and an action.
    At pool-build time every outbound address is resolved (if it is a domain)
    and then checked against all active rules:
      - "block" rules discard matching outbounds.
      - If ANY "allow" rules exist, only outbounds that match at least one
        "allow" rule are kept (whitelist mode).

    Ordering: block rules are evaluated first, then allow rules.
    """
    __tablename__ = "address_filter_rules"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True), primary_key=True, default=uuid.uuid4
    )
    # Human-readable description, e.g. "Block China IPs"
    description: Mapped[str] = mapped_column(Text, nullable=False, default="")

    # Pattern: glob ("*.ru"), CIDR ("10.0.0.0/8"), or /regex/
    pattern: Mapped[str] = mapped_column(Text, nullable=False)

    # "block" or "allow"
    action: Mapped[str] = mapped_column(
        SAEnum(FilterAction, name="filter_action"), nullable=False, default=FilterAction.block
    )

    # Inactive rules are stored but not applied
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
