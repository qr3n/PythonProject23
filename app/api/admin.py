"""
api/admin.py
============
Protected admin endpoints. All routes require Authorization: Bearer {ADMIN_KEY}.
"""
from __future__ import annotations

import logging
import secrets
import uuid

from fastapi import APIRouter, HTTPException, status
from sqlalchemy import select

from app.config import settings
from app.db.models import AddressFilterRule, ProviderSubscription, SubscriptionGroup, User
from app.deps import AdminDep, DbDep, RedisDep
from app.schemas.filter_rule import FilterRuleCreate, FilterRuleResponse, FilterRuleUpdate
from app.schemas.provider import (
    ProviderSubCreate,
    ProviderSubCreateResponse,
    ProviderSubResponse,
    ProviderSubUpdate,
    RefreshResult,
)
from app.schemas.subscription_group import SubscriptionGroupCreate, SubscriptionGroupResponse
from app.schemas.user import TokenResetResponse, UserCreate, UserResponse, UserUpdate
from app.services.builder import (
    delete_user_active_key,
    invalidate_user_config,
    set_user_active_key,
)
from app.services.pool import increment_pool_version
from app.services.provider import refresh_provider_sub

router = APIRouter(prefix="/api/admin", tags=["admin"])
logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
#  Provider Subscriptions
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/provider-subs",
    response_model=ProviderSubCreateResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_provider_sub(
    body: ProviderSubCreate,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> ProviderSubCreateResponse:
    sub = ProviderSubscription(
        alias=body.alias,
        url=body.url,
        expires_at=body.expires_at,
        traffic_total_gb=body.traffic_total_gb,
        group_id=body.group_id,
    )
    db.add(sub)
    await db.flush()

    # Auto-fetch outbounds immediately so the pool is never empty after adding
    fetch_warning: str | None = None
    if body.auto_refresh:
        try:
            count, _meta = await refresh_provider_sub(db, sub)
            logger.info(
                "Auto-refreshed new provider sub %s (%s): %d outbounds",
                sub.id, sub.alias, count,
            )
            if count == 0:
                fetch_warning = (
                    "Subscription was fetched but returned 0 outbounds. "
                    "Check the URL and make sure it is a valid proxy subscription."
                )
        except ConnectionError as exc:
            fetch_warning = f"Could not fetch subscription: {exc}. Pool will be empty until you refresh manually."
            logger.warning(
                "Auto-refresh failed for new sub %s (%s): %s",
                sub.id, sub.alias, exc,
            )

    await increment_pool_version(redis)
    await db.refresh(sub)
    return ProviderSubCreateResponse(**_sub_response(sub).model_dump(), warning=fetch_warning)


@router.get("/provider-subs", response_model=list[ProviderSubResponse])
async def list_provider_subs(
    _: AdminDep,
    db: DbDep,
) -> list[ProviderSubResponse]:
    result = await db.execute(
        select(ProviderSubscription).order_by(ProviderSubscription.created_at.desc())
    )
    return [_sub_response(s) for s in result.scalars().all()]


@router.patch("/provider-subs/{sub_id}", response_model=ProviderSubResponse)
async def update_provider_sub(
    sub_id: uuid.UUID,
    body: ProviderSubUpdate,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> ProviderSubResponse:
    sub = await _get_sub_or_404(db, sub_id)
    changed = False
    for field, value in body.model_dump(exclude_none=True).items():
        if getattr(sub, field) != value:
            setattr(sub, field, value)
            changed = True
    if changed:
        await db.flush()
        await increment_pool_version(redis)
        await db.refresh(sub)
    return _sub_response(sub)


@router.delete("/provider-subs/{sub_id}")
async def delete_provider_sub(
    sub_id: uuid.UUID,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> dict:
    sub = await _get_sub_or_404(db, sub_id)
    await db.delete(sub)
    await db.flush()
    await increment_pool_version(redis)
    return {"deleted": True}


@router.post("/provider-subs/{sub_id}/refresh", response_model=RefreshResult)
async def refresh_provider_sub_endpoint(
    sub_id: uuid.UUID,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> RefreshResult:
    """Fetch fresh outbounds from provider, update DB, invalidate pool cache."""
    sub = await _get_sub_or_404(db, sub_id)
    try:
        count, meta = await refresh_provider_sub(db, sub)
    except ConnectionError as exc:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail=f"Failed to fetch provider subscription: {exc}",
        )
    await increment_pool_version(redis)
    return RefreshResult(
        outbound_count=count,
        traffic_used_gb=sub.traffic_used_gb,
        traffic_total_gb=sub.traffic_total_gb,
        expires_at=sub.expires_at,
        message=f"Refreshed {count} outbounds",
    )


# ══════════════════════════════════════════════════════════════════════════════
#  Subscription Groups
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/subscription-groups",
    response_model=SubscriptionGroupResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_subscription_group(
    body: SubscriptionGroupCreate,
    _: AdminDep,
    db: DbDep,
) -> SubscriptionGroupResponse:
    group = SubscriptionGroup(name=body.name)
    db.add(group)
    await db.flush()
    await db.refresh(group)
    return SubscriptionGroupResponse.model_validate(group)


@router.get("/subscription-groups", response_model=list[SubscriptionGroupResponse])
async def list_subscription_groups(
    _: AdminDep,
    db: DbDep,
) -> list[SubscriptionGroupResponse]:
    result = await db.execute(
        select(SubscriptionGroup).order_by(SubscriptionGroup.created_at.desc())
    )
    return [SubscriptionGroupResponse.model_validate(g) for g in result.scalars().all()]


@router.patch("/subscription-groups/{group_id}", response_model=SubscriptionGroupResponse)
async def update_subscription_group(
    group_id: uuid.UUID,
    body: SubscriptionGroupCreate,
    _: AdminDep,
    db: DbDep,
) -> SubscriptionGroupResponse:
    group = await _get_group_or_404(db, group_id)
    group.name = body.name
    await db.flush()
    await db.refresh(group)
    return SubscriptionGroupResponse.model_validate(group)


@router.delete("/subscription-groups/{group_id}")
async def delete_subscription_group(
    group_id: uuid.UUID,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> dict:
    group = await _get_group_or_404(db, group_id)
    await db.delete(group)
    await db.flush()
    await increment_pool_version(redis)
    return {"deleted": True}


# ══════════════════════════════════════════════════════════════════════════════
#  Users
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/users",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_user(
    body: UserCreate,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> UserResponse:
    token = secrets.token_hex(24)  # 48-char hex string
    user = User(
        name=body.name,
        token=token,
        subscription_expires_at=body.subscription_expires_at,
        is_active=body.is_active,
    )
    db.add(user)
    await db.flush()
    await set_user_active_key(redis, user)
    await db.refresh(user)
    return _user_response(user)


@router.get("/users", response_model=list[UserResponse])
async def list_users(
    _: AdminDep,
    db: DbDep,
) -> list[UserResponse]:
    result = await db.execute(
        select(User).order_by(User.created_at.desc())
    )
    return [_user_response(u) for u in result.scalars().all()]


@router.patch("/users/{user_id}", response_model=UserResponse)
async def update_user(
    user_id: uuid.UUID,
    body: UserUpdate,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> UserResponse:
    user = await _get_user_or_404(db, user_id)
    for field, value in body.model_dump(exclude_none=True).items():
        setattr(user, field, value)
    await db.flush()
    await set_user_active_key(redis, user)
    await invalidate_user_config(redis, user.id)
    await db.refresh(user)
    return _user_response(user)


@router.delete("/users/{user_id}")
async def delete_user(
    user_id: uuid.UUID,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> dict:
    user = await _get_user_or_404(db, user_id)
    await delete_user_active_key(redis, user.token)
    await invalidate_user_config(redis, user.id)
    await db.delete(user)
    await db.flush()
    return {"deleted": True}


@router.post("/users/{user_id}/reset-token", response_model=TokenResetResponse)
async def reset_user_token(
    user_id: uuid.UUID,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> TokenResetResponse:
    """Generate a new token. Old token's active key and cached config are deleted."""
    user = await _get_user_or_404(db, user_id)
    old_token = user.token

    await delete_user_active_key(redis, old_token)
    await invalidate_user_config(redis, user.id)

    user.token = secrets.token_hex(24)
    await db.flush()
    await set_user_active_key(redis, user)
    await db.refresh(user)

    return TokenResetResponse(
        token=user.token,
        sub_url=f"{settings.base_url}/sub/{user.token}",
        check_url=f"{settings.base_url}/check/{user.token}",
    )


# ══════════════════════════════════════════════════════════════════════════════
#  Address Filter Rules
# ══════════════════════════════════════════════════════════════════════════════

@router.post(
    "/filter-rules",
    response_model=FilterRuleResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create an address filter rule",
    description=(
        "Add a block or allow rule for outbound addresses.\n\n"
        "**Pattern syntax** (same as the parser's `match_address`):\n"
        "- Glob / exact: `*.ru`, `10.0.*`, `1.2.3.4`\n"
        "- CIDR: `10.0.0.0/8`, `2001:db8::/32`\n"
        "- Regex (wrap in `/`): `/^cdn\\d+\\.example\\.com$/`\n\n"
        "Patterns apply to both raw addresses **and** their resolved IPs "
        "(domains are resolved via DNS at pool-build time).\n\n"
        "**Actions:**\n"
        "- `block` – discard outbounds matching this pattern.\n"
        "- `allow` – if ANY allow rules exist, only matching outbounds survive "
        "(whitelist mode). Block rules are still evaluated first."
    ),
)
async def create_filter_rule(
    body: FilterRuleCreate,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> FilterRuleResponse:
    rule = AddressFilterRule(
        description=body.description,
        pattern=body.pattern,
        action=body.action,
        is_active=body.is_active,
    )
    db.add(rule)
    await db.flush()
    # Invalidate pool so new rule takes effect on next request
    await increment_pool_version(redis)
    await db.refresh(rule)
    return _rule_response(rule)


@router.get(
    "/filter-rules",
    response_model=list[FilterRuleResponse],
    summary="List all address filter rules",
)
async def list_filter_rules(
    _: AdminDep,
    db: DbDep,
) -> list[FilterRuleResponse]:
    result = await db.execute(
        select(AddressFilterRule).order_by(AddressFilterRule.created_at.desc())
    )
    return [_rule_response(r) for r in result.scalars().all()]


@router.patch(
    "/filter-rules/{rule_id}",
    response_model=FilterRuleResponse,
    summary="Update an address filter rule",
)
async def update_filter_rule(
    rule_id: uuid.UUID,
    body: FilterRuleUpdate,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> FilterRuleResponse:
    rule = await _get_rule_or_404(db, rule_id)
    changed = False
    for field_name, value in body.model_dump(exclude_none=True).items():
        if getattr(rule, field_name) != value:
            setattr(rule, field_name, value)
            changed = True
    if changed:
        await db.flush()
        await increment_pool_version(redis)
        await db.refresh(rule)
    return _rule_response(rule)


@router.delete(
    "/filter-rules/{rule_id}",
    summary="Delete an address filter rule",
)
async def delete_filter_rule(
    rule_id: uuid.UUID,
    _: AdminDep,
    db: DbDep,
    redis: RedisDep,
) -> dict:
    rule = await _get_rule_or_404(db, rule_id)
    await db.delete(rule)
    await db.flush()
    await increment_pool_version(redis)
    return {"deleted": True}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _sub_response(sub: ProviderSubscription) -> ProviderSubResponse:
    return ProviderSubResponse(
        id=sub.id,
        alias=sub.alias,
        url=sub.url,
        expires_at=sub.expires_at,
        traffic_total_gb=sub.traffic_total_gb,
        traffic_used_gb=sub.traffic_used_gb,
        last_fetched_at=sub.last_fetched_at,
        group_id=sub.group_id,
        is_active=sub.is_active,
        created_at=sub.created_at,
        outbound_count=len(sub.outbounds_json or []),
    )


def _user_response(user: User) -> UserResponse:
    return UserResponse(
        id=user.id,
        name=user.name,
        token=user.token,
        subscription_expires_at=user.subscription_expires_at,
        is_active=user.is_active,
        created_at=user.created_at,
        sub_url=f"{settings.base_url}/sub/{user.token}",
        check_url=f"{settings.base_url}/check/{user.token}",
    )


async def _get_sub_or_404(db: DbDep, sub_id: uuid.UUID) -> ProviderSubscription:
    result = await db.execute(
        select(ProviderSubscription).where(ProviderSubscription.id == sub_id)
    )
    sub = result.scalar_one_or_none()
    if sub is None:
        raise HTTPException(status_code=404, detail="Provider subscription not found")
    return sub


async def _get_user_or_404(db: DbDep, user_id: uuid.UUID) -> User:
    result = await db.execute(select(User).where(User.id == user_id))
    user = result.scalar_one_or_none()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    return user


def _rule_response(rule: AddressFilterRule) -> FilterRuleResponse:
    return FilterRuleResponse(
        id=rule.id,
        description=rule.description,
        pattern=rule.pattern,
        action=rule.action if isinstance(rule.action, str) else rule.action.value,
        is_active=rule.is_active,
        created_at=rule.created_at,
    )


async def _get_group_or_404(db: DbDep, group_id: uuid.UUID) -> SubscriptionGroup:
    result = await db.execute(
        select(SubscriptionGroup).where(SubscriptionGroup.id == group_id)
    )
    group = result.scalar_one_or_none()
    if group is None:
        raise HTTPException(status_code=404, detail="Subscription group not found")
    return group


async def _get_rule_or_404(db: DbDep, rule_id: uuid.UUID) -> AddressFilterRule:
    result = await db.execute(
        select(AddressFilterRule).where(AddressFilterRule.id == rule_id)
    )
    rule = result.scalar_one_or_none()
    if rule is None:
        raise HTTPException(status_code=404, detail="Filter rule not found")
    return rule
