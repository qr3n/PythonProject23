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
    status_code, headers, body = await fetch_upstream_config(
        path=path,
        query=str(request.url.query),
        method=request.method,
        headers=dict(request.headers)
    )

    modified_body = body

    # Only try to inject outbounds if we have a token and it looks like a subscription config
    if token and status_code == 200:
        try:
            stripped_body = body.strip()
            if stripped_body.startswith(b"[") or stripped_body.startswith(b"{"):
                upstream_json = json.loads(body)

                # 2. Get our custom outbounds
                pool = await get_or_build_pool(db, redis)
                our_outbounds = []
                if pool:
                    our_outbounds = select_user_outbounds(pool, token)

                # 3. Inject our outbounds (always call to allow mockup/logic)
                modified_json = inject_outbounds(upstream_json, our_outbounds)
                modified_body = json.dumps(modified_json).encode("utf-8")

                if settings.debug:
                    logger.info("[PROXY] Processed injection for %s (our_outbounds: %d)", token, len(our_outbounds))
        except Exception as exc:
            if settings.debug:
                logger.error("[PROXY] Injection error for %s: %s", path, exc)

    # 4. Drop hop-by-hop/unwanted transfer headers
    fwd_headers = {
        k: v for k, v in headers.items()
        if k.lower() not in {"content-length", "transfer-encoding", "connection", "content-encoding"}
    }

    # ======= НАЧАЛО ИНЪЕКЦИИ ЗАГОЛОВКОВ HAPP =======
    if token and status_code == 200:
        # Указываем стандартные ссылки управления
        fwd_headers["profile-web-page-url"] = "https://hazeevpn.com"
        fwd_headers["support-url"] = "https://t.me/hazevpn_support"

        # Если тестируешь расширенные фичи (serverDescription) на своей группе устройств:
        # fwd_headers["providerid"] = "G79bc1x5"

        # Подтягиваем динамические заголовки из БД бота (динамический title и announce)
        bot_hdrs = await resolve_bot_headers(rw_pool, bot_pool, token)
        if bot_hdrs:
            b64_title, b64_subtitle = bot_hdrs
            fwd_headers["profile-title"] = f"base64:{b64_title}"
            if b64_subtitle:
                fwd_headers["announce"] = f"base64:{b64_subtitle}"
            if settings.debug:
                logger.info("[PROXY] Added bot headers for %s: title=%s", token, b64_title[:10] + "...")
        elif settings.debug:
            logger.info("[PROXY] No bot headers found for %s", token)
    # ======= КОНЕЦ ИНЪЕКЦИИ ЗАГОЛОВКОВ HAPP =======

    if settings.debug:
        logger.info("[PROXY] Sending response with headers: %s", {k: v for k, v in fwd_headers.items() if k.lower() in ["profile-title", "announce", "content-type", "support-url", "profile-web-page-url"]})

    return Response(
        content=modified_body,
        status_code=status_code,
        headers=fwd_headers,
        media_type=headers.get("content-type")
    )