from collections.abc import AsyncGenerator
from typing import Annotated

import redis.asyncio as aioredis
import asyncpg
from fastapi import Depends, HTTPException, Security, status
from fastapi.security import APIKeyHeader
from sqlalchemy.ext.asyncio import AsyncSession

from app.config import settings
from app.db.base import AsyncSessionLocal

# ── Database ──────────────────────────────────────────────────────────────────

async def get_db() -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        try:
            yield session
            await session.commit()
        except Exception:
            await session.rollback()
            raise


DbDep = Annotated[AsyncSession, Depends(get_db)]

# ── Redis ─────────────────────────────────────────────────────────────────────

# Module-level pool; created once during lifespan
_redis_pool: aioredis.Redis | None = None


def get_redis() -> aioredis.Redis:
    if _redis_pool is None:
        raise RuntimeError("Redis pool not initialised")
    return _redis_pool


RedisDep = Annotated[aioredis.Redis, Depends(get_redis)]


def set_redis_pool(pool: aioredis.Redis) -> None:
    global _redis_pool
    _redis_pool = pool


# ── External DBs (Middleware) ──────────────────────────────────────────────────

_rw_pool: asyncpg.Pool | None = None
_bot_pool: asyncpg.Pool | None = None


def get_rw_pool() -> asyncpg.Pool | None:
    return _rw_pool


def get_bot_pool() -> asyncpg.Pool | None:
    return _bot_pool


def set_external_pools(rw: asyncpg.Pool | None, bot: asyncpg.Pool | None) -> None:
    global _rw_pool, _bot_pool
    _rw_pool = rw
    _bot_pool = bot


RwPoolDep = Annotated[asyncpg.Pool | None, Depends(get_rw_pool)]
BotPoolDep = Annotated[asyncpg.Pool | None, Depends(get_bot_pool)]


# ── Admin auth ────────────────────────────────────────────────────────────────

_api_key_header = APIKeyHeader(name="Authorization", auto_error=False)


async def require_admin(
    raw: Annotated[str | None, Security(_api_key_header)],
) -> None:
    expected = f"Bearer {settings.admin_api_key}"
    if not raw or raw != expected:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing admin API key",
            headers={"WWW-Authenticate": "Bearer"},
        )


AdminDep = Annotated[None, Depends(require_admin)]
