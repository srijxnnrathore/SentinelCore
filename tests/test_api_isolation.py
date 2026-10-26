import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from src.main import app
from src.db.session import engine
from tests.conftest import mint_test_token
from sqlalchemy import text

@pytest.mark.anyio
async def test_jwt_cross_tenant_api_isolation():
    tenant_1 = str(uuid.uuid4())
    tenant_2 = str(uuid.uuid4())

    token_t1 = mint_test_token(tenant_id=tenant_1, subject="user-1")
    token_t2 = mint_test_token(tenant_id=tenant_2, subject="user-2")

    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t1, 'Org One'), (:t2, 'Org Two')"),
            {"t1": tenant_1, "t2": tenant_2}
        )
        await conn.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 1. Tenant 1 creates a document with valid Bearer token
        res1 = await client.post(
            "/documents/",
            headers={"Authorization": f"Bearer {token_t1}"},
            json={"title": "T1 Secret", "content": "Classified Info 1"}
        )
        assert res1.status_code == 201

        # 2. Tenant 2 creates a document with valid Bearer token
        res2 = await client.post(
            "/documents/",
            headers={"Authorization": f"Bearer {token_t2}"},
            json={"title": "T2 Secret", "content": "Classified Info 2"}
        )
        assert res2.status_code == 201

        # 3. Tenant 1 queries GET /documents/ -> only sees T1
        res_t1_list = await client.get(
            "/documents/",
            headers={"Authorization": f"Bearer {token_t1}"}
        )
        assert res_t1_list.status_code == 200
        titles_t1 = [d["title"] for d in res_t1_list.json()]
        assert "T1 Secret" in titles_t1
        assert "T2 Secret" not in titles_t1

        # 4. Tampered token attempt -> must fail with 401
        tampered_token = token_t1[:-5] + "aaaaa"
        res_tampered = await client.get(
            "/documents/",
            headers={"Authorization": f"Bearer {tampered_token}"}
        )
        assert res_tampered.status_code == 401

        # 5. Missing Authorization header -> must fail with 401/403
        res_missing = await client.get("/documents/")
        assert res_missing.status_code in (401, 403)