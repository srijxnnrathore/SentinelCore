import pytest
import uuid
from sqlalchemy import text
from src.db.session import scoped_tenant_session, AsyncSessionLocal

@pytest.mark.anyio
async def test_tenant_isolation():
    tenant_a_id = str(uuid.uuid4())
    tenant_b_id = str(uuid.uuid4())

    # 1. Insert Tenant A's document inside Tenant A's scoped session
    async with scoped_tenant_session(tenant_a_id) as session:
        await session.execute(
            text("INSERT INTO tenants (id, name) VALUES (:id, 'Tenant A')"),
            {"id": tenant_a_id}
        )
        await session.execute(
            text("INSERT INTO documents (tenant_id, title, content) VALUES (:t_id, 'Doc A', 'Secret Content A')"),
            {"t_id": tenant_a_id}
        )

    # 2. Insert Tenant B's document inside Tenant B's scoped session
    async with scoped_tenant_session(tenant_b_id) as session:
        await session.execute(
            text("INSERT INTO tenants (id, name) VALUES (:id, 'Tenant B')"),
            {"id": tenant_b_id}
        )
        await session.execute(
            text("INSERT INTO documents (tenant_id, title, content) VALUES (:t_id, 'Doc B', 'Secret Content B')"),
            {"t_id": tenant_b_id}
        )

    # 3. Test: Tenant A queries the documents table WITHOUT any WHERE clause
    async with scoped_tenant_session(tenant_a_id) as session:
        result = await session.execute(text("SELECT title FROM documents"))
        titles = result.scalars().all()
        assert "Doc A" in titles
        assert "Doc B" not in titles

    # 4. Negative Test: Query without any tenant context set
    async with AsyncSessionLocal() as session:
        async with session.begin():
            result = await session.execute(text("SELECT title FROM documents"))
            titles = result.scalars().all()
            assert len(titles) == 0