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
import re
from typing import Optional

from fastapi import APIRouter, Request, Response
from fastapi.responses import JSONResponse

from app.config import settings
from app.deps import DbDep, RedisDep, RwPoolDep, BotPoolDep
from app.services.pool import get_or_build_pool, select_user_outbounds
from app.services.middleware import (
    fetch_upstream_config,
    resolve_bot_headers,
    inject_outbounds
)

logger = logging.getLogger(__name__)

router = APIRouter(tags=["client"])

_TOKEN_RE = re.compile(r"^[a-zA-Z0-9_-]{4,64}$")

def extract_token(path: str) -> Optional[str]:
    # Extract the first segment of the path as the potential token
    # e.g., /abc12345/something -> abc12345
    # e.g., /abc12345?query -> abc12345
    segments = [s for s in path.split("/") if s]
    if not segments:
        return None
    
    segment = segments[0].split("?")[0]
    if _TOKEN_RE.match(segment):
        return segment
    return None


@router.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
)
async def proxy_all(
    path: str,
    request: Request,
    db: DbDep,
    redis: RedisDep,
    rw_pool: RwPoolDep,
    bot_pool: BotPoolDep,
) -> Response:
    """
    Catch-all proxy route that replicates original middleware behavior.
    """
    token = extract_token(path)
    if settings.debug:
        logger.info("[PROXY] Path: %s, Token: %s", path, token)
    
    # 1. Fetch upstream config (or any resource)
    status_code, headers, body = await fetch_upstream_config(path, str(request.url.query))
    
    modified_body = body
    
    # Only try to inject outbounds if we have a token and it looks like a subscription config
    if token and status_code == 200:
        try:
            # We check if it's a JSON array (standard Remnawave sub format)
            stripped_body = body.strip()
            if stripped_body.startswith(b"[") and stripped_body.endswith(b"]"):
                upstream_json = json.loads(body)
                
                # 2. Get our custom outbounds
                pool = await get_or_build_pool(db, redis)
                our_outbounds = []
                if pool:
                    our_outbounds = select_user_outbounds(pool, token)

                # 3. Inject our outbounds
                if our_outbounds:
                    modified_json = inject_outbounds(upstream_json, our_outbounds)
                    modified_body = json.dumps(modified_json).encode("utf-8")
                    if settings.debug:
                        logger.info("[PROXY] Injected %d outbounds for %s", len(our_outbounds), token)
        except Exception as exc:
            # If it's not JSON or injection fails, we just return the original body
            logger.debug("Skipping injection for %s: %s", path, exc)

    # 4. Resolve bot headers (profile-title, announce)
    fwd_headers = {
        k: v for k, v in headers.items() 
        if k.lower() not in {"content-length", "transfer-encoding", "connection", "content-encoding"}
    }
    
    if token:
        bot_hdrs = await resolve_bot_headers(rw_pool, bot_pool, token)
        if bot_hdrs:
            b64_title, b64_subtitle = bot_hdrs
            fwd_headers["profile-title"] = f"base64:{b64_title}"
            if b64_subtitle:
                fwd_headers["announce"] = f"base64:{b64_subtitle}"
            if settings.debug:
                logger.info("[PROXY] Added bot headers for %s", token)

    return Response(
        content=modified_body,
        status_code=status_code,
        headers=fwd_headers,
        media_type=headers.get("content-type")
    )
