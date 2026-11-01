import asyncio
import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from src.core.redis import get_redis_client
from src.db.session import engine
from src.main import app
from tests.conftest import mint_test_token

@pytest.mark.anyio
async def test_decoupled_asynchronous_document_lifecycle_and_threat_events():
    tenant_owner = str(uuid.uuid4())
    tenant_attacker = str(uuid.uuid4())

    token_owner = mint_test_token(tenant_id=tenant_owner, subject="doc-owner")
    token_attacker = mint_test_token(tenant_id=tenant_attacker, subject="doc-attacker")

    # 1. Provision tenants
    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t1, 'Owner Org'), (:t2, 'Attacker Org')"),
            {"t1": tenant_owner, "t2": tenant_attacker},
        )
        await conn.commit()

    redis_client = get_redis_client()
    violations_key = f"violations:{tenant_attacker}"
    jail_key = f"jail:{tenant_attacker}"
    await redis_client.delete(violations_key, jail_key)

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # 2. Document Creation - Asynchronous decoupled logging
        create_res = await client.post(
            "/documents/",
            headers={"Authorization": f"Bearer {token_owner}"},
            json={"title": "Confidential Specs", "content": "Proprietary design"},
        )
        assert create_res.status_code == 201
        doc_data = create_res.json()
        doc_id = doc_data["id"]

        # 3. Document Read by Owner - Success
        read_res = await client.get(
            f"/documents/{doc_id}",
            headers={"Authorization": f"Bearer {token_owner}"},
        )
        assert read_res.status_code == 200
        assert read_res.json()["id"] == doc_id

        # 4. Non-existent probe by Attacker - Must be DOCUMENT_NOT_FOUND with record_threat=False
        fake_id = str(uuid.uuid4())
        not_found_res = await client.get(
            f"/documents/{fake_id}",
            headers={"Authorization": f"Bearer {token_attacker}"},
        )
        assert not_found_res.status_code == 404

        # Wait briefly for background event queue to process
        await asyncio.sleep(0.1)
        # Verify attacker violations count was NOT incremented for benign 404
        violation_count = await redis_client.get(violations_key)
        assert violation_count is None

        # 5. Cross-tenant probe by Attacker - Must return 404 and record threat event asynchronously
        cross_res = await client.get(
            f"/documents/{doc_id}",
            headers={"Authorization": f"Bearer {token_attacker}"},
        )
        assert cross_res.status_code == 404
        assert cross_res.json()["detail"] == "Document not found"

        # Poll for background threat event processing
        violation_count = None
        for _ in range(25):
            violation_count = await redis_client.get(violations_key)
            if violation_count is not None:
                break
            await asyncio.sleep(0.05)

        # Attacker's violation count MUST now be incremented via background threat detector
        assert violation_count is not None
        assert int(violation_count) == 1

    # Clean up Redis
    await redis_client.delete(violations_key, jail_key)
