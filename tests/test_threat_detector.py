import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text

from src.main import app
from src.db.session import engine
from src.core.redis import get_redis_client
from tests.conftest import mint_test_token

@pytest.mark.anyio
async def test_threat_detector_quarantines_probing_tenant():
    """
    Validates automated circuit-breaking:
    Repeated IDOR/BOLA probes from an attacker trigger an automated Redis quarantine,
    transitioning the response from 404 Not Found to 403 Forbidden circuit break.
    """
    attacker_tenant = str(uuid.uuid4())
    attacker_token = mint_test_token(tenant_id=attacker_tenant, subject="adversary-1")

    # Seed attacker tenant so audit logging and rate limiter proceed
    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t, 'Probing Org')"),
            {"t": attacker_tenant}
        )
        await conn.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Probe 1: Returns 404 (Violation count: 1)
        res1 = await client.get(
            f"/documents/{uuid.uuid4()}",
            headers={"Authorization": f"Bearer {attacker_token}"}
        )
        assert res1.status_code == 404

        # Probe 2: Returns 404 (Violation count: 2)
        res2 = await client.get(
            f"/documents/{uuid.uuid4()}",
            headers={"Authorization": f"Bearer {attacker_token}"}
        )
        assert res2.status_code == 404

        # Probe 3: Returns 404, trips threshold of 3 violations -> triggers quarantine
        res3 = await client.get(
            f"/documents/{uuid.uuid4()}",
            headers={"Authorization": f"Bearer {attacker_token}"}
        )
        assert res3.status_code == 404

        # Probe 4: Immediate circuit break -> HTTP 403 Forbidden, database bypassed
        res_jailed = await client.get(
            "/documents/",
            headers={"Authorization": f"Bearer {attacker_token}"}
        )
        assert res_jailed.status_code == 403
        assert "quarantined due to suspicious probing" in res_jailed.json()["detail"]

    # Cleanup Redis state
    client_redis = get_redis_client()
    await client_redis.delete(f"jail:{attacker_tenant}")
    await client_redis.delete(f"violations:{attacker_tenant}")