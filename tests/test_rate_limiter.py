import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text

from src.main import app
from src.db.session import engine
from src.core.redis import get_redis_client
from tests.conftest import mint_test_token

@pytest.mark.anyio
async def test_tenant_rate_limiting():
    tenant_id = str(uuid.uuid4())
    other_tenant = str(uuid.uuid4())

    token = mint_test_token(tenant_id=tenant_id, subject="rate-limit-test")
    other_token = mint_test_token(tenant_id=other_tenant, subject="other-tenant")

    # Seed tenants so audit_logs foreign key constraints pass
    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t1, 'RateLimit Tenant 1'), (:t2, 'RateLimit Tenant 2')"),
            {"t1": tenant_id, "t2": other_tenant}
        )
        await conn.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # First 5 requests should pass (limit is 5)
        for _ in range(5):
            res = await client.get("/documents/", headers={"Authorization": f"Bearer {token}"})
            assert res.status_code == 200

        # The 6th request must trigger HTTP 429 Too Many Requests
        res_blocked = await client.get("/documents/", headers={"Authorization": f"Bearer {token}"})
        assert res_blocked.status_code == 429
        assert "Retry-After" in res_blocked.headers
        assert res_blocked.json()["detail"] == "Rate limit exceeded. Too many requests."

        # Verify other tenant is isolated and unaffected
        res_other = await client.get("/documents/", headers={"Authorization": f"Bearer {other_token}"})
        assert res_other.status_code == 200

    # Cleanup Redis test keys
    redis_client = get_redis_client()
    keys = await redis_client.keys(f"rate:{tenant_id}:*")
    if keys:
        await redis_client.delete(*keys)