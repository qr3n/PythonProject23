"""
app/main.py
===========
FastAPI application factory.
Handles Redis and external DB pools lifecycle via lifespan context manager.
"""
from __future__ import annotations

import logging
from contextlib import asynccontextmanager

import redis.asyncio as aioredis
import asyncpg
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.admin import router as admin_router
from app.api.client import router as client_router
from app.config import settings
from app.deps import set_redis_pool, set_external_pools

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s — %(message)s",
)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Starting up — connecting to Redis at %s", settings.redis_url)
    redis_pool = aioredis.from_url(
        settings.redis_url,
        encoding="utf-8",
        decode_responses=True,
        max_connections=20,
    )
    set_redis_pool(redis_pool)

    # External pools for Middleware
    rw_pool = None
    bot_pool = None
    if settings.remnawave_db_url:
        try:
            rw_pool = await asyncpg.create_pool(
                dsn=settings.remnawave_db_url, min_size=1, max_size=5,
                server_settings={"search_path": settings.db_schema},
            )
            logger.info("Remnawave DB pool connected")
        except Exception as e:
            logger.error("Failed to connect to Remnawave DB: %s", e)

    if settings.bot_db_url:
        try:
            bot_pool = await asyncpg.create_pool(
                dsn=settings.bot_db_url, min_size=1, max_size=5,
                server_settings={"search_path": settings.bot_db_schema},
            )
            logger.info("Bot DB pool connected")
        except Exception as e:
            logger.error("Failed to connect to Bot DB: %s", e)
    
    set_external_pools(rw_pool, bot_pool)

    # Warm-up ping
    try:
        await redis_pool.ping()
        logger.info("Redis connected OK")
    except Exception as exc:
        logger.error("Redis connection failed: %s", exc)

    yield

    logger.info("Shutting down — closing connections")
    await redis_pool.aclose()
    if rw_pool:
        await rw_pool.close()
    if bot_pool:
        await bot_pool.close()


def create_app() -> FastAPI:
    app = FastAPI(
        title="VPN Subscription Manager (Middleware)",
        version="2.0.0",
        description=(
            "Middleware for Remnawave subscriptions. Injects custom outbounds into upstream configs."
        ),
        lifespan=lifespan,
    )

    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_methods=["*"],
        allow_headers=["*"],
    )

    app.include_router(admin_router)
    app.include_router(client_router)

    @app.get("/health", tags=["system"])
    async def health() -> dict:
        return {"status": "ok"}

    return app


app = create_app()
