import base64
import json
import logging
import time
from typing import Optional, AsyncIterator

import asyncpg
import httpx
from fastapi import HTTPException
from app.config import settings

logger = logging.getLogger(__name__)

# Cache for bot headers (same logic as in original middleware)
# token -> ((b64_title, b64_subtitle | None), expires_at)
_header_cache: dict[str, tuple[Optional[tuple[str, Optional[str]]], float]] = {}

def _cache_get(token: str) -> tuple[bool, Optional[tuple[str, Optional[str]]]]:
    entry = _header_cache.get(token)
    if entry is None:
        return False, None
    value, expires_at = entry
    if time.monotonic() > expires_at:
        _header_cache.pop(token, None)
        return False, None
    return True, value

def _cache_set(token: str, value: Optional[tuple[str, Optional[str]]], ttl: int) -> None:
    _header_cache[token] = (value, time.monotonic() + ttl)

async def resolve_bot_headers(
    rw_pool: asyncpg.Pool,
    bot_pool: asyncpg.Pool,
    token: str
) -> Optional[tuple[str, Optional[str]]]:
    """Resolves profile-title and announce from Remnawave/Bot DBs."""
    if not rw_pool or not bot_pool:
        return None

    hit, cached = _cache_get(token)
    if hit:
        return cached

    try:
        # Step 1: short_uuid -> remnawave uuid
        rw_sql = f'SELECT "uuid"::text FROM {settings.db_schema}.users WHERE short_uuid = $1 LIMIT 1'
        rw_row = await rw_pool.fetchrow(rw_sql, token)
        if rw_row is None:
            _cache_set(token, None, 30) # cache null
            return None

        rw_uuid = rw_row["uuid"]

        # Step 2: remnawave_uuid -> bot name + subtitle
        bot_sql = f"""
            SELECT bi.name, bi.subtitle
            FROM {settings.bot_db_schema}.users u
            JOIN {settings.bot_db_schema}.bot_instances bi ON bi.bot_id = u.bot_id AND bi.is_active = true
            WHERE u.remnawave_uuid = $1 LIMIT 1
        """
        bot_row = await bot_pool.fetchrow(bot_sql, rw_uuid)
        if bot_row is None:
            _cache_set(token, None, 30)
            return None

        bot_name = bot_row["name"]
        bot_subtitle = bot_row["subtitle"] or None

        b64_title = base64.b64encode(bot_name.encode()).decode()
        b64_subtitle = base64.b64encode(bot_subtitle.encode()).decode() if bot_subtitle else None

        result = (b64_title, b64_subtitle)
        _cache_set(token, result, 300) # cache 5m
        return result
    except Exception as exc:
        logger.error("Failed to resolve bot headers for %s: %s", token, exc)
        return None

async def fetch_upstream_config(
    path: str, 
    query: str = "", 
    method: str = "GET", 
    headers: dict = None
) -> tuple[int, dict, bytes]:
    """Fetches the original config from upstream subscription page."""
    url = f"{settings.subscription_page_url}/{path}"
    if query:
        url += f"?{query}"
    
    # Drop hop-by-hop headers before forwarding
    _drop = {"host", "content-length", "transfer-encoding", "connection"}
    fwd_headers = {k: v for k, v in (headers or {}).items() if k.lower() not in _drop}
    
    if settings.debug:
        logger.info("[DEBUG] Fetching upstream: %s %s", method, url)
        # logger.info("[DEBUG] Forwarding headers: %s", fwd_headers)

    async with httpx.AsyncClient(
        timeout=settings.api_timeout_seconds,
        follow_redirects=True,
        # Force HTTP/1.1 as some upstreams (like nodejs/subscription-page) might be picky
        limits=httpx.Limits(max_keepalive_connections=5, max_connections=10)
    ) as client:
        try:
            resp = await client.request(
                method=method,
                url=url,
                headers=fwd_headers,
            )
            if settings.debug:
                logger.info("[DEBUG] Upstream response: %d, Content-Type: %s", resp.status_code, resp.headers.get("content-type"))
            
            return resp.status_code, dict(resp.headers), resp.content
        except httpx.HTTPError as exc:
            logger.error("Failed to fetch upstream config from %s: %s", url, exc)
            if settings.debug:
                import traceback
                logger.error(traceback.format_exc())
            raise HTTPException(status_code=502, detail=f"Upstream error: {exc}")
        except Exception as exc:
            logger.error("Unexpected error fetching upstream %s: %s", url, exc)
            raise HTTPException(status_code=502, detail="Internal proxy error")

def inject_outbounds(upstream_json: list[dict], our_outbounds: list[dict]) -> list[dict]:
    """
    Merges our outbounds into the upstream config.
    Upstream usually returns a list with one or more config objects.
    """
    if not upstream_json or not isinstance(upstream_json, list):
        return upstream_json

    # We inject into the first config object found
    config = upstream_json[0]
    if "outbounds" not in config:
        config["outbounds"] = []
    
    # Prefix our tags to avoid collisions if not already prefixed
    for ob in our_outbounds:
        # Remove internal keys before injection
        clean_ob = {k: v for k, v in ob.items() if not k.startswith("_")}
        config["outbounds"].append(clean_ob)

    # Optional: If there is a balancer, we might want to add our proxies to it.
    # But usually, just adding them to outbounds makes them visible in the list.
    
    return upstream_json
