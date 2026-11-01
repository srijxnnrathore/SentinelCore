import pytest
import uuid
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text

from src.main import app
from src.db.session import engine
from src.core.redis import get_redis_client
from src.core.event_queue import security_event_queue
from tests.conftest import mint_test_token

@pytest.mark.anyio
async def test_threat_detector_quarantines_probing_tenant():
    """
    Validates automated circuit-breaking:
    Repeated IDOR/BOLA cross-tenant probes from an attacker trigger an automated Redis quarantine,
    transitioning the response from 404 Not Found to 403 Forbidden circuit break.
    """
    victim_tenant = str(uuid.uuid4())
    attacker_tenant = str(uuid.uuid4())
    attacker_token = mint_test_token(tenant_id=attacker_tenant, subject="adversary-1")
    victim_doc_id = str(uuid.uuid4())

    # Seed victim tenant, attacker tenant, and victim document with RLS context
    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t1, 'Victim Org'), (:t2, 'Attacker Org')"),
            {"t1": victim_tenant, "t2": attacker_tenant}
        )
        await conn.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": victim_tenant},
        )
        await conn.execute(
            text("INSERT INTO documents (id, tenant_id, title, content) VALUES (:id, :t, 'Secret Doc', 'Secret Content')"),
            {"id": victim_doc_id, "t": victim_tenant}
        )
        await conn.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Probe 1: Returns 404 (Violation count: 1)
        res1 = await client.get(
            f"/documents/{victim_doc_id}",
            headers={"Authorization": f"Bearer {attacker_token}"}
        )
        assert res1.status_code == 404
        await security_event_queue.queue.join()

        # Probe 2: Returns 404 (Violation count: 2)
        res2 = await client.get(
            f"/documents/{victim_doc_id}",
            headers={"Authorization": f"Bearer {attacker_token}"}
        )
        assert res2.status_code == 404
        await security_event_queue.queue.join()

        # Probe 3: Returns 404, trips threshold of 3 violations -> triggers quarantine
        res3 = await client.get(
            f"/documents/{victim_doc_id}",
            headers={"Authorization": f"Bearer {attacker_token}"}
        )
        assert res3.status_code == 404
        await security_event_queue.queue.join()

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
