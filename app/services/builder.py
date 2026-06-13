"""
services/builder.py
===================
Assembles a complete xray JSON config for a user.

The config contains:
- Selected proxy outbounds (p-X-Y tags)
- A blackhole outbound (fallback when all proxies are dead)
- burstObservatory pointed at /check/{token}
- A balancer with leastPing strategy and fallbackTag: "block"
- Minimal inbound (SOCKS+HTTP on localhost) + routing

The config is cached in Redis with a versioned key:
  config:{user_id}:{pool_version}

When pool version changes, old keys are naturally abandoned (expire in 24h).
"""
from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone

import redis.asyncio as aioredis
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.models import User
from app.services.pool import (
    get_or_build_pool,
    get_pool_version,
    select_user_outbounds,
)

logger = logging.getLogger(__name__)


def _build_xray_config(
    user: User,
    outbounds: list[dict],
    check_url: str,
) -> dict:
    """
    Build a complete xray JSON config dict.

    Parameters
    ----------
    user       The user record (for token / id)
    outbounds  Selected proxy outbound dicts (with p-X-Y tags)
    check_url  Full URL for burstObservatory probe
    """
    # Strip internal metadata keys before building the xray config
    _INTERNAL_KEYS = {"_sub_id", "_group_id"}
    clean_outbounds = [
        {k: v for k, v in ob.items() if k not in _INTERNAL_KEYS}
        for ob in outbounds
    ]

    proxy_tags = [ob.get("tag", f"p-{i}") for i, ob in enumerate(clean_outbounds)]

    # All outbounds: proxies + blackhole
    all_outbounds = list(clean_outbounds) + [
        {
            "tag": "block",
            "protocol": "blackhole",
            "settings": {},
        }
    ]

    config = {
        "log": {
            "loglevel": "warning",
        },
        "inbounds": [
            {
                "tag": "socks-in",
                "protocol": "socks",
                "listen": "127.0.0.1",
                "port": 10808,
                "settings": {
                    "auth": "noauth",
                    "udp": True,
                },
                "sniffing": {
                    "enabled": True,
                    "destOverride": ["http", "tls", "quic"],
                },
            },
            {
                "tag": "http-in",
                "protocol": "http",
                "listen": "127.0.0.1",
                "port": 10809,
                "settings": {},
            },
        ],
        "outbounds": all_outbounds,
        "burstObservatory": {
            "subjectSelector": ["p-"],
            "probeUrl": check_url,
            "probeInterval": f"{settings.probe_interval_seconds}s",
        },
        "routing": {
            "domainStrategy": "IPIfNonMatch",
            "balancers": [
                {
                    "tag": "proxy-balancer",
                    "selector": ["p-"],
                    "fallbackTag": "block",
                    "strategy": {
                        "type": "leastPing",
                    },
                }
            ],
            "rules": [
                {
                    "type": "field",
                    "network": "tcp,udp",
                    "balancerTag": "proxy-balancer",
                }
            ],
        },
    }

    return config


async def build_user_config(
    db: AsyncSession,
    redis: aioredis.Redis,
    user: User,
) -> dict | None:
    """
    Returns the xray JSON config for a user.
    Checks Redis cache first (versioned key). On miss, builds and caches.
    Returns None if pool is empty.
    """
    pool_version = await get_pool_version(redis)
    cache_key = f"config:{user.id}:{pool_version}"

    # Cache hit
    cached = await redis.get(cache_key)
    if cached:
        return json.loads(cached)

    # Build pool and select outbounds
    pool = await get_or_build_pool(db, redis)
    if not pool:
        logger.warning("Pool is empty, cannot build config for user %s", user.id)
        return None

    selected = select_user_outbounds(pool, user.token)
    check_url = f"{settings.base_url}/check/{user.token}"

    config = _build_xray_config(user, selected, check_url)

    # Cache with TTL
    await redis.setex(
        cache_key,
        settings.config_cache_ttl_seconds,
        json.dumps(config),
    )

    return config


async def invalidate_user_config(redis: aioredis.Redis, user_id: uuid.UUID) -> None:
    """
    Invalidate a specific user's config cache across all pool versions.
    We use a pattern scan here since this is a rare admin operation.
    """
    pattern = f"config:{user_id}:*"
    cursor = 0
    while True:
        cursor, keys = await redis.scan(cursor, match=pattern, count=100)
        if keys:
            await redis.delete(*keys)
        if cursor == 0:
            break


async def set_user_active_key(redis: aioredis.Redis, user: User) -> None:
    """
    Set or refresh the sub:active:{token} key in Redis.
    TTL = seconds until subscription expiry (or 24h if no expiry set).
    """
    key = f"sub:active:{user.token}"

    if not user.is_active:
        await redis.delete(key)
        return

    now = datetime.now(timezone.utc)
    if user.subscription_expires_at and user.subscription_expires_at > now:
        ttl = int((user.subscription_expires_at - now).total_seconds())
        await redis.setex(key, ttl, "1")
    elif user.subscription_expires_at is None:
        # No expiry configured → keep active with 24h rolling TTL
        await redis.setex(key, 86400, "1")
    else:
        # Already expired
        await redis.delete(key)


async def delete_user_active_key(redis: aioredis.Redis, token: str) -> None:
    await redis.delete(f"sub:active:{token}")
