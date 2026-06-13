"""
api/client.py
=============
Public endpoints for the Middleware-proxy.

GET /sub/{token}
    Proxy to upstream Remnawave subscription with custom outbound injection.
"""
from __future__ import annotations

import json
import logging
from typing import Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.deps import DbDep, RedisDep, RwPoolDep, BotPoolDep
from app.services.pool import get_or_build_pool, select_user_outbounds
from app.services.middleware import (
    fetch_upstream_config,
    resolve_bot_headers,
    inject_outbounds
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["client"])


@router.get("/sub/{token}")
async def get_subscription(
    token: str,
    request: Request,
    db: DbDep,
    redis: RedisDep,
    rw_pool: RwPoolDep,
    bot_pool: BotPoolDep,
) -> Response:
    """
    Middleware-proxy endpoint.
    1. Fetches original config from Remnawave.
    2. Fetches our pool outbounds.
    3. Merges them.
    4. Adds profile-title and announce headers from external DBs.
    """
    # 1. Fetch upstream config
    status_code, headers, body = await fetch_upstream_config(token, str(request.url.query))
    
    try:
        upstream_json = json.loads(body)
    except Exception as exc:
        logger.error("Failed to parse upstream JSON for %s: %s", token, exc)
        return Response(content=body, status_code=status_code, headers=headers)

    # 2. Get our custom outbounds
    pool = await get_or_build_pool(db, redis)
    our_outbounds = []
    if pool:
        our_outbounds = select_user_outbounds(pool, token)

    # 3. Inject our outbounds into the upstream config
    modified_json = inject_outbounds(upstream_json, our_outbounds)
    modified_body = json.dumps(modified_json).encode("utf-8")

    # 4. Resolve bot headers (profile-title, announce)
    bot_hdrs = await resolve_bot_headers(rw_pool, bot_pool, token)
    
    # Prepare response headers
    # Remove hop-by-hop or conflicting headers
    fwd_headers = {
        k: v for k, v in headers.items() 
        if k.lower() not in {"content-length", "transfer-encoding", "connection", "content-encoding"}
    }
    
    if bot_hdrs:
        b64_title, b64_subtitle = bot_hdrs
        fwd_headers["profile-title"] = f"base64:{b64_title}"
        if b64_subtitle:
            fwd_headers["announce"] = f"base64:{b64_subtitle}"

    return Response(
        content=modified_body,
        status_code=status_code,
        headers=fwd_headers,
        media_type="application/json"
    )


@router.get("/check/{token}", status_code=200)
async def check_subscription(
    token: str,
    redis: RedisDep,
) -> dict:
    """
    Keep as is or implement custom logic later.
    Currently always returns OK for the proxy to function.
    """
    return {"status": "ok"}
