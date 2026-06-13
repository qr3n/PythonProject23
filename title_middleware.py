from __future__ import annotations

import asyncio
import base64
import os
import re
import time
from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

import asyncpg
import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse

# ─── Config ───────────────────────────────────────────────────────────────────

def _fix_url(url: str) -> str:
    return url.replace("postgres://", "postgresql://", 1) if url.startswith("postgres://") else url

cfg = {
    "port":            int(os.getenv("PORT", "3011")),
    "sub_page_url":    os.getenv("SUBSCRIPTION_PAGE_URL",
                                 "http://remnawave-subscription-page:3010").rstrip("/"),
    "cache_ttl":       int(os.getenv("CACHE_TTL_SECONDS", "300")),
    "cache_null_ttl":  int(os.getenv("CACHE_NULL_TTL_SECONDS", "30")),
    "api_timeout":     float(os.getenv("API_TIMEOUT_MS", "3000")) / 1000,
    "debug":           os.getenv("DEBUG", "false").lower() == "true",
    # Remnawave DB: short_uuid → uuid
    "rw_db_url":       _fix_url(os.getenv("DATABASE_URL", "")),
    "rw_db_schema":    os.getenv("DB_SCHEMA", "public"),
    # Bot DB: remnawave_uuid → bot_id → bot_instances.name / .subtitle
    "bot_db_url":      _fix_url(os.getenv("BOT_DATABASE_URL", "")),
    "bot_db_schema":   os.getenv("BOT_DB_SCHEMA", "public"),
}

if not cfg["rw_db_url"]:
    raise RuntimeError("[FATAL] DATABASE_URL is not set")
if not cfg["bot_db_url"]:
    raise RuntimeError("[FATAL] BOT_DATABASE_URL is not set")

# ─── Pools ────────────────────────────────────────────────────────────────────

_rw_pool:  asyncpg.Pool | None = None   # Remnawave DB
_bot_pool: asyncpg.Pool | None = None   # Bot DB

# ─── TTL-кеш ─────────────────────────────────────────────────────────────────

# token → ((b64_title, b64_subtitle | None), expires_at)
_cache: dict[str, tuple[Optional[tuple[str, Optional[str]]], float]] = {}

def _cache_get(token: str) -> tuple[bool, Optional[tuple[str, Optional[str]]]]:
    entry = _cache.get(token)
    if entry is None:
        return False, None
    value, expires_at = entry
    if time.monotonic() > expires_at:
        _cache.pop(token, None)
        return False, None
    return True, value

def _cache_set(token: str, value: Optional[tuple[str, Optional[str]]], ttl: int) -> None:
    _cache[token] = (value, time.monotonic() + ttl)

# ─── SQL ──────────────────────────────────────────────────────────────────────

_SQL_RW  = ""
_SQL_BOT = ""

def _build_sql(rw_schema: str, bot_schema: str) -> tuple[str, str]:
    rw = f"""
        SELECT "uuid"::text
        FROM   {rw_schema}.users
        WHERE  short_uuid = $1
        LIMIT  1
    """
    bot = f"""
        SELECT bi.name, bi.subtitle
        FROM   {bot_schema}.users u
        JOIN   {bot_schema}.bot_instances bi
               ON  bi.bot_id    = u.bot_id
               AND bi.is_active = true
        WHERE  u.remnawave_uuid = $1
        LIMIT  1
    """
    return rw, bot

# ─── Resolver ─────────────────────────────────────────────────────────────────

async def resolve_bot_headers(token: str) -> Optional[tuple[str, Optional[str]]]:
    """Возвращает (b64_title, b64_subtitle | None) или None."""
    hit, cached = _cache_get(token)
    if hit:
        return cached

    try:
        # Шаг 1: short_uuid → remnawave uuid
        rw_row = await _rw_pool.fetchrow(_SQL_RW, token)
        if rw_row is None:
            _cache_set(token, None, cfg["cache_null_ttl"])
            if cfg["debug"]:
                print(f"[TITLE] {token} → not found in remnawave DB")
            return None

        remnawave_uuid: str = rw_row["uuid"]
        if cfg["debug"]:
            print(f"[TITLE] {token} → remnawave_uuid={remnawave_uuid}")

        # Шаг 2: remnawave_uuid → bot name + subtitle
        bot_row = await _bot_pool.fetchrow(_SQL_BOT, remnawave_uuid)
        if bot_row is None:
            _cache_set(token, None, cfg["cache_null_ttl"])
            if cfg["debug"]:
                print(f"[TITLE] remnawave_uuid={remnawave_uuid} → no bot found")
            return None

        bot_name: str        = bot_row["name"]
        bot_subtitle: str | None = bot_row["subtitle"] or None

        b64_title    = base64.b64encode(bot_name.encode()).decode()
        b64_subtitle = base64.b64encode(bot_subtitle.encode()).decode() if bot_subtitle else None

        result = (b64_title, b64_subtitle)
        _cache_set(token, result, cfg["cache_ttl"])

        if cfg["debug"]:
            print(f"[TITLE] {token} → bot={bot_name!r}, subtitle={bot_subtitle!r}")
        return result

    except Exception as exc:
        if cfg["debug"]:
            print(f"[DB ERROR] token={token}: {exc}")
        return None

# ─── Token extractor ──────────────────────────────────────────────────────────

_TOKEN_RE = re.compile(r"^[a-zA-Z0-9_-]{4,64}$")

def extract_token(path: str) -> Optional[str]:
    segment = next((s for s in path.split("?")[0].split("/") if s), None)
    return segment if segment and _TOKEN_RE.match(segment) else None

# ─── Lifespan ─────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    global _rw_pool, _bot_pool, _SQL_RW, _SQL_BOT

    _SQL_RW, _SQL_BOT = _build_sql(cfg["rw_db_schema"], cfg["bot_db_schema"])

    _rw_pool = await asyncpg.create_pool(
        dsn=cfg["rw_db_url"], min_size=1, max_size=3,
        command_timeout=cfg["api_timeout"],
        server_settings={"search_path": cfg["rw_db_schema"]},
    )
    _bot_pool = await asyncpg.create_pool(
        dsn=cfg["bot_db_url"], min_size=1, max_size=3,
        command_timeout=cfg["api_timeout"],
        server_settings={"search_path": cfg["bot_db_schema"]},
    )

    try:
        await _rw_pool.fetchval(f"SELECT 1 FROM {cfg['rw_db_schema']}.users LIMIT 1")
        print(f"[OK] Remnawave DB connected (schema={cfg['rw_db_schema']!r})")
    except Exception as exc:
        print(f"[WARN] Remnawave DB check failed: {exc}")

    try:
        await _bot_pool.fetchval(f"SELECT 1 FROM {cfg['bot_db_schema']}.bot_instances LIMIT 1")
        print(f"[OK] Bot DB connected (schema={cfg['bot_db_schema']!r})")
    except Exception as exc:
        print(f"[WARN] Bot DB check failed: {exc}")

    print(f"[OK] Proxying to: {cfg['sub_page_url']}")
    print(f"[OK] Cache TTL: {cfg['cache_ttl']}s (null: {cfg['cache_null_ttl']}s)")

    try:
        yield
    finally:
        await _rw_pool.close()
        await _bot_pool.close()
        print("[OK] DB pools closed")

# ─── App ──────────────────────────────────────────────────────────────────────

app = FastAPI(lifespan=lifespan, docs_url=None, redoc_url=None)

@app.get("/_mw_health")
async def health() -> dict:
    return {"status": "ok", "cache_size": len(_cache)}

@app.api_route(
    "/{path:path}",
    methods=["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS", "PATCH"],
)
async def proxy(request: Request, path: str) -> StreamingResponse:
    token = extract_token(request.url.path)
    bot_hdrs: Optional[tuple[str, Optional[str]]] = None

    if token:
        try:
            bot_hdrs = await asyncio.wait_for(
                resolve_bot_headers(token),
                timeout=cfg["api_timeout"] + 0.5,
            )
        except asyncio.TimeoutError:
            bot_hdrs = None

    target_url = f"{cfg['sub_page_url']}/{path}"
    if request.url.query:
        target_url += f"?{request.url.query}"

    _drop = {"host", "content-length", "transfer-encoding", "connection"}
    fwd_headers = {k: v for k, v in request.headers.items() if k.lower() not in _drop}

    _ctx: dict = {}

    async def _stream_upstream() -> AsyncIterator[bytes]:
        async with httpx.AsyncClient(timeout=30.0) as client:
            async with client.stream(
                method=request.method,
                url=target_url,
                headers=fwd_headers,
                content=request.stream(),
                follow_redirects=False,
            ) as upstream:
                resp_headers = {
                    k: v
                    for k, v in upstream.headers.multi_items()
                    if k.lower() not in {"transfer-encoding", "connection"}
                }

                if bot_hdrs:
                    b64_title, b64_subtitle = bot_hdrs
                    resp_headers["profile-title"] = f"base64:{b64_title}"
                    if b64_subtitle:
                        resp_headers["announce"] = f"base64:{b64_subtitle}"

                _ctx["status"] = upstream.status_code
                _ctx["headers"] = resp_headers

                full_body = b""
                async for chunk in upstream.aiter_raw(chunk_size=64 * 1024):
                    full_body += chunk
                    yield chunk
                
                if cfg["debug"] or True: # Force debug for now as requested
                    print(f"\n[DEBUG] --- Proxy Interaction ---")
                    print(f"[DEBUG] Request: {request.method} {request.url}")
                    print(f"[DEBUG] Upstream URL: {target_url}")
                    print(f"[DEBUG] Response Status: {upstream.status_code}")
                    try:
                        # Attempt to parse and print JSON for debugging
                        body_to_decode = full_body
                        ce = upstream.headers.get("content-encoding", "").lower()
                        if "gzip" in ce:
                            try:
                                import gzip
                                body_to_decode = gzip.decompress(full_body)
                                print(f"[DEBUG] Decompressed GZIP body")
                            except Exception as ge:
                                print(f"[DEBUG] GZIP decompress failed: {ge}")

                        body_text = body_to_decode.decode("utf-8", errors="replace")
                        if body_text.strip().startswith("{") or body_text.strip().startswith("["):
                             print(f"[DEBUG] Response JSON: {body_text}")
                        else:
                             print(f"[DEBUG] Response Body (non-JSON or first 500 chars): {body_text[:500]}")
                    except Exception as e:
                        print(f"[DEBUG] Could not decode response body: {e}")
                    print(f"[DEBUG] --- End Interaction ---\n")

    gen = _stream_upstream()
    try:
        first_chunk = await gen.__anext__()
    except StopAsyncIteration:
        first_chunk = b""
    except httpx.RequestError as exc:
        print(f"[PROXY ERROR] {request.method} {request.url.path}: {exc}")
        return JSONResponse({"error": "Subscription page unavailable"}, status_code=502)

    async def _combined() -> AsyncIterator[bytes]:
        if first_chunk:
            yield first_chunk
        async for chunk in gen:
            yield chunk

    return StreamingResponse(
        content=_combined(),
        status_code=_ctx.get("status", 200),
        headers=_ctx.get("headers", {}),
    )
