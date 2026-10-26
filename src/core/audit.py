from sqlalchemy import text
from src.db.session import AsyncSessionLocal
from typing import Optional
import uuid

async def log_security_event(
    actor_id: str,
    action: str,
    status: str,
    tenant_id: Optional[uuid.UUID] = None,
    resource_id: Optional[str] = None,
    ip_address: Optional[str] = None,
) -> None:
    """
    Writes an append-only security audit log event using a fresh transaction.
    """
    query = text("""
        INSERT INTO audit_logs (tenant_id, actor_id, action, resource_id, status, ip_address)
        VALUES (:tenant_id, :actor_id, :action, :resource_id, :status, :ip_address)
    """)
    async with AsyncSessionLocal() as session:
        async with session.begin():
            await session.execute(
                query,
                {
                    "tenant_id": str(tenant_id) if tenant_id else None,
                    "actor_id": actor_id,
                    "action": action,
                    "resource_id": resource_id,
                    "status": status,
                    "ip_address": ip_address,
                }
            )