import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from sqlalchemy.exc import ProgrammingError

from src.main import app
from src.db.session import engine, AsyncSessionLocal
from src.core.event_queue import security_event_queue
from tests.conftest import mint_test_token

@pytest.mark.anyio
async def test_audit_log_generation():
    tenant_id = str(uuid.uuid4())
    token = mint_test_token(tenant_id=tenant_id, subject="sec-auditor-1")

    # Seed tenant
    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t, 'Audit Org')"),
            {"t": tenant_id}
        )
        await conn.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Create a document
        res = await client.post(
            "/documents/",
            headers={"Authorization": f"Bearer {token}"},
            json={"title": "Audit Subject", "content": "Evidence data"}
        )
        assert res.status_code == 201
        doc_id = res.json()["id"]

    # Await background decoupled audit queue to drain
    await security_event_queue.queue.join()

    # Verify that an audit record exists in the database
    async with AsyncSessionLocal() as session:
        result = await session.execute(
            text("SELECT actor_id, action, status, resource_id FROM audit_logs WHERE tenant_id = :t"),
            {"t": tenant_id}
        )
        record = result.mappings().one()
        assert record["actor_id"] == "sec-auditor-1"
        assert record["action"] == "DOCUMENT_CREATE"
        assert record["status"] == "SUCCESS"
        assert record["resource_id"] == doc_id

@pytest.mark.anyio
async def test_audit_log_immutability():
    # Attempt to tamper with or delete audit logs as sentinel_app -> must fail
    async with AsyncSessionLocal() as session:
        async with session.begin():
            # Tampering attempt 1: UPDATE
            with pytest.raises(ProgrammingError) as exc_info:
                await session.execute(text("UPDATE audit_logs SET status = 'TAMPERED'"))
            assert "permission denied for table audit_logs" in str(exc_info.value).lower()

        async with session.begin():
            # Tampering attempt 2: DELETE
            with pytest.raises(ProgrammingError) as exc_info:
                await session.execute(text("DELETE FROM audit_logs"))
            assert "permission denied for table audit_logs" in str(exc_info.value).lower()
