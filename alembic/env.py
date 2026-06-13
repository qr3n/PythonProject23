import asyncio
import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy.ext.asyncio import create_async_engine

from app.db.models import Base

# Alembic Config object
config = context.config

# Interpret the config file for Python logging
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

target_metadata = Base.metadata


def get_url() -> str:
    # Allow override via DATABASE_URL env var (used in Docker)
    url = os.getenv("DATABASE_URL", config.get_main_option("sqlalchemy.url"))
    print(f"[ALEMBIC] Connecting to: {url.split('@')[-1] if '@' in url else url}")
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql+asyncpg://", 1)
    return url


def run_migrations_offline() -> None:
    url = get_url()
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )
    with context.begin_transaction():
        context.run_migrations()


def do_run_migrations(connection):
    context.configure(connection=connection, target_metadata=target_metadata)
    with context.begin_transaction():
        context.run_migrations()


async def run_migrations_online() -> None:
    url = get_url()
    connectable = create_async_engine(url, future=True)
    
    # Retry connection for up to 30 seconds
    last_exc = None
    for i in range(10):
        try:
            async with connectable.connect() as connection:
                await connection.run_sync(do_run_migrations)
            await connectable.dispose()
            return
        except Exception as e:
            last_exc = e
            print(f"[ALEMBIC] Connection attempt {i+1} failed: {e}. Retrying in 3s...")
            await asyncio.sleep(3)
    
    if last_exc:
        raise last_exc


if context.is_offline_mode():
    run_migrations_offline()
else:
    asyncio.run(run_migrations_online())
