from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from sqlalchemy import text
from sqlalchemy.ext.asyncio import (
    AsyncSession,
    async_sessionmaker,
    create_async_engine,
)
from sqlalchemy.pool import NullPool
from src.core.config import settings

engine = create_async_engine(
    settings.DATABASE_URL,
    poolclass=NullPool,
)

AsyncSessionLocal = async_sessionmaker(
    bind=engine,
    class_=AsyncSession,
    expire_on_commit=False,
    autocommit=False,
    autoflush=False,
)

def _reset_connection_gucs(dbapi_conn, connection_record, reset_state) -> None:
    if not reset_state.terminate_only:
        dbapi_conn.rollback()

@asynccontextmanager
async def scoped_tenant_session(tenant_id: str) -> AsyncGenerator[AsyncSession, None]:
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
                {"tenant_id": str(tenant_id)},
            )
            yield session