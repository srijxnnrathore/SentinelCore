import asyncio
import logging
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
import secrets
from typing import Any, Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from src.core.config import settings

logger = logging.getLogger("sentinelcore.db")

COALESCED_CONTEXT_SQL = text("""
    SELECT
        pg_catalog.set_config('app.current_tenant_id', :tenant_id, true),
        pg_catalog.set_config('app.current_trace_id', :trace_id, true),
        pg_catalog.set_config('application_name', :app_name, true)
""")

def generate_w3c_traceparent() -> str:
    """
    Generates a valid W3C traceparent (format: 00-<32_hex_trace_id>-<16_hex_span_id>-01).
    """
    trace_id = secrets.token_hex(16)
    span_id = secrets.token_hex(8)
    return f"00-{trace_id}-{span_id}-01"

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
async def scoped_tenant_session(
    tenant_id: str,
    trace_id: Optional[str] = None,
) -> AsyncGenerator[AsyncSession, None]:
    """
    Provides a tenant-scoped transactional AsyncSession with Single-RTT coalesced
    trace context and W3C trace propagation.
    Enforces transaction-local GUC setting (is_local=true) and cancellation-shielded cleanup
    to ensure asyncpg connections are never left in an unhandled protocol or contaminated state.
    """
    if not trace_id:
        trace_id = generate_w3c_traceparent()

    app_name = f"sentinel:{trace_id[:32]}"[:63]

    session = AsyncSessionLocal()
    try:
        async with session.begin():
            # Coalesced Single-RTT context setup with prepared statement caching
            await session.execute(
                COALESCED_CONTEXT_SQL,
                {
                    "tenant_id": str(tenant_id),
                    "trace_id": str(trace_id),
                    "app_name": str(app_name),
                },
            )
            yield session
    except BaseException:
        # Task cancellation or error: cleanly rollback under shield to prevent wire corruption
        if session.is_active:
            try:
                await asyncio.shield(session.rollback())
            except Exception as exc:
                logger.debug("Suppressed error during session rollback: %s", exc)
        raise
    finally:
        # Ensure connection is closed/returned to pool under shield even upon cancellation
        try:
            await asyncio.shield(session.close())
        except Exception as exc:
            logger.debug("Suppressed error closing session: %s", exc)
