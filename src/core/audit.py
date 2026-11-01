from typing import Optional
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession
from src.db.session import AsyncSessionLocal

async def log_security_event(
    actor_id: str,
    action: str,
    status: str,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
    tenant_id: Optional[str] = None,
    session: Optional[AsyncSession] = None,
) -> None:
    query = text("""
        INSERT INTO audit_logs (tenant_id, actor_id, action, resource_id, status, ip_address)
        VALUES (:tenant_id, :actor_id, :action, :resource_id, :status, :ip_address)
    """)
    params = {
        "tenant_id": tenant_id,
        "actor_id": actor_id,
        "action": action,
        "resource_id": resource_id,
        "status": status,
        "ip_address": ip_address,
    }

    if session is not None:
        await session.execute(query, params)
    else:
        async with AsyncSessionLocal() as local_session:
            await local_session.execute(query, params)
            await local_session.commit()