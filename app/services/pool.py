"""
services/pool.py
================
Builds the outbound pool from all active provider subscriptions.

Algorithm:
1. Compute health score for each subscription (time + traffic)
2. Filter out near-dead subscriptions (health < MIN_HEALTH_SCORE)
3. Sort subscriptions by health descending
4. Round-robin merge (interleave) outbounds across subscriptions
5. For a user: deterministic slice of K outbounds via token-derived offset

Pool is versioned in Redis. Version increments on any pool-affecting change,
which invalidates all per-user config caches without a scan.
"""
from __future__ import annotations

import hashlib
import json
import logging
from datetime import datetime, timezone
from math import floor

import redis.asyncio as aioredis
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.models import ProviderSubscription
from app.services.provider import get_all_active_subs
from app.services.address_filter import apply_address_filters

logger = logging.getLogger(__name__)

POOL_VERSION_KEY = "pool:version"
POOL_DATA_KEY = "pool:data"
POOL_CACHE_TTL = 3600  # 1h, rebuilt on version bump anyway


def _health_score(sub: ProviderSubscription) -> float:
    """
    Returns a [0, 1] health score for a provider subscription.
    Uses the worse of time_health and traffic_health.
    """
    now = datetime.now(timezone.utc)

    # Time health: days_remaining / 30, clamped to [0, 1]
    if sub.expires_at:
        remaining_days = (sub.expires_at - now).total_seconds() / 86400
        time_health = max(0.0, min(1.0, remaining_days / 30.0))
    else:
        time_health = 1.0  # no expiry info → assume healthy

    # Traffic health: remaining / total, clamped to [0, 1]
    if sub.traffic_total_gb and sub.traffic_used_gb is not None:
        remaining_gb = sub.traffic_total_gb - sub.traffic_used_gb
        traffic_health = max(0.0, min(1.0, remaining_gb / sub.traffic_total_gb))
    else:
        traffic_health = 1.0  # no traffic info → assume healthy

    return min(time_health, traffic_health)


def _build_pool(subs: list[ProviderSubscription]) -> list[dict]:
    """
    Build the interleaved outbound pool from active subscriptions.

    Returns a flat list of raw xray outbound dicts, with tags prefixed as
    p-{sub_index}-{outbound_index} to guarantee uniqueness.
    """
    threshold = settings.min_health_score

    # Score and filter
    scored: list[tuple[float, ProviderSubscription]] = []
    for sub in subs:
        if not sub.outbounds_json:
            continue
        score = _health_score(sub)
        if score < threshold:
            logger.info(
                "Provider sub %s (%s) excluded from pool: health=%.3f < %.3f",
                sub.id, sub.alias, score, threshold,
            )
            continue
        scored.append((score, sub))

    if not scored:
        logger.warning("Outbound pool is empty! All provider subs are unhealthy.")
        return []

    # Sort by health descending so best subs appear more frequently in interleave
    scored.sort(key=lambda x: x[0], reverse=True)

    # Build per-subscription outbound lists with prefixed tags
    tagged_lists: list[list[dict]] = []
    for sub_idx, (score, sub) in enumerate(scored):
        outbounds = sub.outbounds_json or []
        sub_id = str(sub.id)
        group_id = str(sub.group_id) if getattr(sub, "group_id", None) else None
        tagged = []
        for ob_idx, ob in enumerate(outbounds):
            ob_copy = dict(ob)
            ob_copy["tag"] = f"p-{sub_idx}-{ob_idx}"
            ob_copy["_sub_id"] = sub_id
            ob_copy["_group_id"] = group_id
            tagged.append(ob_copy)
        tagged_lists.append(tagged)
        logger.debug(
            "Sub %s: %d outbounds, health=%.3f", sub.alias, len(tagged), score
        )

    # Round-robin interleave
    pool: list[dict] = []
    max_len = max(len(lst) for lst in tagged_lists)
    for i in range(max_len):
        for lst in tagged_lists:
            if i < len(lst):
                pool.append(lst[i])

    logger.info("Pool built: %d total outbounds from %d subscriptions", len(pool), len(scored))
    return pool


def _user_offset(token: str, pool_size: int) -> int:
    """Deterministic offset from user token hex prefix."""
    return int(token[:8], 16) % pool_size


def select_user_outbounds(pool: list[dict], token: str) -> list[dict]:
    """
    Pick K outbounds for a user using group-wise load-balancing.

    Groups outbounds by _group_id (or _sub_id when _group_id is None).
    For each group, selects exactly one _sub_id deterministically via
    MD5(token + group_key), then keeps only outbounds for that sub.
    Finally slices up to outbounds_per_user outbounds with a token-derived offset.
    """
    if not pool:
        return []

    # Group outbounds by group key
    groups: dict[str, list[dict]] = {}
    for ob in pool:
        group_key = ob.get("_group_id") or ob.get("_sub_id", "")
        groups.setdefault(group_key, []).append(ob)

    selected: list[dict] = []
    for group_key, outbounds in groups.items():
        # Collect unique sub_ids, sorted for determinism
        sub_ids = sorted({ob["_sub_id"] for ob in outbounds})

        # Pick one sub_id via MD5(token + group_key)
        digest = hashlib.md5((token + group_key).encode()).hexdigest()
        chosen_sub_id = sub_ids[int(digest, 16) % len(sub_ids)]

        # Keep only outbounds belonging to the chosen sub
        selected.extend(ob for ob in outbounds if ob["_sub_id"] == chosen_sub_id)

    n = len(selected)
    if n == 0:
        return []

    k = min(settings.outbounds_per_user, n)
    if k < settings.outbounds_per_user:
        logger.warning(
            "Filtered pool size %d < OUTBOUNDS_PER_USER %d, giving all outbounds to user",
            n, settings.outbounds_per_user,
        )

    offset = _user_offset(token, n)
    return [selected[(offset + i) % n] for i in range(k)]


# ── Redis pool cache ──────────────────────────────────────────────────────────

async def get_pool_version(redis: aioredis.Redis) -> int:
    v = await redis.get(POOL_VERSION_KEY)
    return int(v) if v else 0


async def increment_pool_version(redis: aioredis.Redis) -> int:
    v = await redis.incr(POOL_VERSION_KEY)
    # Delete old pool data too
    await redis.delete(POOL_DATA_KEY)
    return v


async def get_cached_pool(redis: aioredis.Redis) -> list[dict] | None:
    data = await redis.get(POOL_DATA_KEY)
    if data is None:
        return None
    return json.loads(data)


async def set_cached_pool(redis: aioredis.Redis, pool: list[dict]) -> None:
    await redis.setex(POOL_DATA_KEY, POOL_CACHE_TTL, json.dumps(pool))


async def get_or_build_pool(
    db: AsyncSession,
    redis: aioredis.Redis,
) -> list[dict]:
    """
    Returns the current outbound pool, building and caching it if needed.
    Address filter rules are applied before the pool is cached.
    """
    cached = await get_cached_pool(redis)
    if cached is not None:
        return cached

    subs = await get_all_active_subs(db)
    pool = _build_pool(subs)
    pool = await apply_address_filters(db, pool)
    await set_cached_pool(redis, pool)
    return pool
