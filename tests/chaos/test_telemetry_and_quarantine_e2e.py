import asyncio
from pathlib import Path
import statistics
import sys
import time
import uuid
import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent.parent))

from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from src.core.event_queue import security_event_queue
from src.core.redis import get_redis_client
from src.core.security import jwks_manager
from src.core.threat_detector import threat_detector
from src.db.session import engine
from src.main import app
from tests.conftest import mint_test_token, _pub_key, TEST_KID


@pytest.mark.anyio
async def test_telemetry_and_quarantine_e2e():
    """
    Simulates an active adversary executing consecutive cross-tenant read probes.
    Validates end-to-end:
    1. HTTP 404 responses maintain timing indistinguishability against non-existent IDs.
    2. Decoupled asynchronous event queue processes security events and persists
       DOCUMENT_READ_DENIED audit log records into PostgreSQL.
    3. Redis atomic Lua threat detector records violations, trips at the configured
       quarantine threshold, and stores the jail record.
    4. Fast-path edge check blocks subsequent attacker requests with HTTP 403 Forbidden
       and Retry-After, completely bypassing the PostgreSQL connection pool.
    """
    jwks_manager.set_keys_manually({TEST_KID: _pub_key})
    redis_client = get_redis_client()

    victim_tenant = str(uuid.uuid4())
    attacker_tenant = str(uuid.uuid4())
    baseline_tenant = str(uuid.uuid4())

    attacker_subject = f"adversary-actor-{attacker_tenant[:8]}"
    attacker_token = mint_test_token(tenant_id=attacker_tenant, subject=attacker_subject)
    baseline_token = mint_test_token(tenant_id=baseline_tenant, subject="baseline-actor")
    victim_doc_id = str(uuid.uuid4())

    # Configure quarantine threshold to exactly 5 violations for this test
    original_max_violations = threat_detector.max_violations
    threat_detector.max_violations = 5

    jail_key = f"jail:{attacker_tenant}"
    violations_key = f"violations:{attacker_tenant}"
    rate_key_attacker = f"rate:{{{attacker_tenant}}}"
    rate_key_baseline = f"rate:{{{baseline_tenant}}}"

    try:
        # 1. Seed victim, attacker, and baseline tenants, and victim document with strict RLS
        async with engine.connect() as conn:
            await conn.execute(
                text("INSERT INTO tenants (id, name) VALUES (:t1, 'Victim Corp'), (:t2, 'Attacker Org'), (:t3, 'Baseline Org')"),
                {"t1": victim_tenant, "t2": attacker_tenant, "t3": baseline_tenant},
            )
            await conn.execute(
                text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
                {"tenant_id": victim_tenant},
            )
            await conn.execute(
                text("INSERT INTO documents (id, tenant_id, title, content) VALUES (:id, :t, 'Classified Blueprint', 'Top Secret')"),
                {"id": victim_doc_id, "t": victim_tenant},
            )
            await conn.commit()

        # Clear Redis keys for fresh test state
        await redis_client.delete(jail_key, violations_key, rate_key_attacker, rate_key_baseline)

        headers_attacker = {"Authorization": f"Bearer {attacker_token}"}
        headers_baseline = {"Authorization": f"Bearer {baseline_token}"}

        cross_latencies = []
        fake_latencies = []

        async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
            # Warm up
            await client.get(f"/documents/{uuid.uuid4()}", headers=headers_baseline)
            await redis_client.delete(rate_key_baseline)

            # 2. Execute 5 consecutive cross-tenant read probes and measure latency
            for probe_idx in range(1, 6):
                # Measure cross-tenant probe latency
                t0 = time.perf_counter_ns()
                probe_res = await client.get(f"/documents/{victim_doc_id}", headers=headers_attacker)
                t1 = time.perf_counter_ns()

                assert probe_res.status_code == 404, (
                    f"Probe {probe_idx} expected 404, got {probe_res.status_code}: {probe_res.text}"
                )
                assert probe_res.json()["detail"] == "Document not found"
                cross_latencies.append((t1 - t0) / 1e6)

                # Measure baseline fake ID latency on separate quota for timing comparison
                fake_id = str(uuid.uuid4())
                t2 = time.perf_counter_ns()
                fake_res = await client.get(f"/documents/{fake_id}", headers=headers_baseline)
                t3 = time.perf_counter_ns()

                assert fake_res.status_code == 404
                fake_latencies.append((t3 - t2) / 1e6)

            # Timing invariance verification: BOLA timing oracle eliminated
            median_cross = statistics.median(cross_latencies)
            median_fake = statistics.median(fake_latencies)
            delta_ms = abs(median_cross - median_fake)
            assert delta_ms < 5.0, (
                f"Timing oracle detected: Cross-tenant median={median_cross:.2f}ms vs "
                f"Fake median={median_fake:.2f}ms (delta={delta_ms:.2f}ms)"
            )

            # 3. Await background event queue to process all asynchronous telemetry
            await security_event_queue.queue.join()

            # 4. Verify PostgreSQL audit_logs contains all 5 DOCUMENT_READ_DENIED security events
            async with engine.connect() as conn:
                audit_records = (await conn.execute(
                    text("""
                        SELECT tenant_id, actor_id, action, resource_id, status
                        FROM audit_logs
                        WHERE tenant_id = :t AND action = 'DOCUMENT_READ_DENIED'
                        ORDER BY created_at ASC
                    """),
                    {"t": attacker_tenant},
                )).mappings().all()

                assert len(audit_records) == 5, (
                    f"Expected exactly 5 DOCUMENT_READ_DENIED audit records, found {len(audit_records)}"
                )
                for rec in audit_records:
                    assert str(rec["tenant_id"]) == attacker_tenant
                    assert rec["actor_id"] == attacker_subject
                    assert rec["action"] == "DOCUMENT_READ_DENIED"
                    assert rec["resource_id"] == victim_doc_id
                    assert rec["status"] == "DENIED"

            # 5. Verify Redis quarantine threshold tripped and wrote jail key
            jail_status = await redis_client.get(jail_key)
            if isinstance(jail_status, bytes):
                jail_status = jail_status.decode("utf-8")
            assert jail_status == "QUARANTINED", f"Expected jail key to be 'QUARANTINED', got {jail_status}"

            jail_ttl = await redis_client.ttl(jail_key)
            assert jail_ttl > 0, f"Expected positive TTL on jail key, got {jail_ttl}"

            # Violations key should be deleted upon quarantine circuit break
            violations_val = await redis_client.get(violations_key)
            assert violations_val is None, f"Violations key should be cleaned up on quarantine, got {violations_val}"

            # 6. Verify subsequent attacker requests are immediately blocked with HTTP 403 Forbidden
            quarantined_res = await client.get("/documents/", headers=headers_attacker)
            assert quarantined_res.status_code == 403, (
                f"Expected 403 Forbidden for quarantined tenant, got {quarantined_res.status_code}"
            )
            assert "Retry-After" in quarantined_res.headers, "Quarantined response missing Retry-After header"
            retry_after = int(quarantined_res.headers["Retry-After"])
            assert retry_after > 0
            assert "quarantined due to suspicious probing" in quarantined_res.json()["detail"]

            # Also verify write attempt is blocked without touching database
            write_res = await client.post(
                "/documents/",
                headers=headers_attacker,
                json={"title": "Malicious Write", "content": "Payload"},
            )
            assert write_res.status_code == 403
            assert "quarantined due to suspicious probing" in write_res.json()["detail"]

    finally:
        threat_detector.max_violations = original_max_violations
        await redis_client.delete(jail_key, violations_key, rate_key_attacker, rate_key_baseline)


if __name__ == "__main__":
    asyncio.run(test_telemetry_and_quarantine_e2e())
    print("test_telemetry_and_quarantine_e2e.py passed standalone execution!")
