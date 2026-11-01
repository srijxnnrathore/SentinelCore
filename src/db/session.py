import asyncio
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from typing import Any, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from src.core.config import settings

# Production-grade bounded connection pool using asyncpg and AsyncAdaptedQueuePool
engine = create_async_engine(
    settings.DATABASE_URL,
    pool_size=10,
    max_overflow=5,
    pool_timeout=5.0,
    pool_recycle=1800,
    pool_pre_ping=True,
    pool_reset_on_return="rollback",
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

def _reset_connection_gucs(dbapi_conn: Any, connection_record: Any = None, reset_state: Any = None) -> None:
    """
    Retained for test suite compatibility.
    Under asyncpg, connection-level GUC and transaction reset is handled safely
    via pool_reset_on_return='rollback' without invoking unsupported DBAPI cursor methods.
    """
    pass

@asynccontextmanager
async def scoped_tenant_session(tenant_id: str) -> AsyncGenerator[AsyncSession, None]:
    """
    Provides a tenant-scoped transactional AsyncSession.
    Enforces transaction-local GUC setting (is_local=true) and cancellation-shielded cleanup
    to ensure asyncpg connections are never left in an unhandled protocol or contaminated state.
    """
    session = AsyncSessionLocal()
    try:
        async with session.begin():
            # Transaction-scoped GUC (is_local=true) automatically reverts upon transaction end
            await session.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_id)},
            )
            yield session
    except BaseException:
        # Task cancellation or error: cleanly rollback under shield to prevent wire corruption
        if session.is_active:
            try:
                await asyncio.shield(session.rollback())
            except Exception:
                pass
        raise
    finally:
        # Ensure connection is closed/returned to pool under shield even upon cancellation
        try:
            await asyncio.shield(session.close())
        except Exception:
            pass