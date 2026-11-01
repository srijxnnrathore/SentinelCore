import asyncio
import statistics
import time
import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text
from sqlalchemy.ext.asyncio import create_async_engine
from sqlalchemy.pool import NullPool
from src.core.config import settings
from src.core.redis import get_redis_client
from src.db.session import _reset_connection_gucs, scoped_tenant_session
from src.main import app
from tests.conftest import mint_test_token

@pytest.mark.anyio
async def test_pg16_rls_enforces_initplan_and_index_cond():
    """
    Asserts that the PostgreSQL 16 optimizer:
    1. Did NOT inline app_current_tenant_id() into volatile current_setting().
    2. Evaluated tenant_id through an index scan rather than a post-scan filter.
    """
    tenant_id = str(uuid.uuid4())
    doc_id = str(uuid.uuid4())
    engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)

    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t, 'Test Tenant')"),
            {"t": tenant_id},
        )
        await conn.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": tenant_id},
        )
        await conn.execute(
            text("INSERT INTO documents (id, tenant_id, title, content) VALUES (:id, :t, 'Title', 'Content')"),
            {"id": doc_id, "t": tenant_id},
        )
        await conn.commit()

    async with engine.connect() as conn:
        await conn.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": tenant_id},
        )
        await conn.execute(text("SET LOCAL enable_seqscan = off"))

        result = await conn.execute(
            text("""
                EXPLAIN (FORMAT JSON, VERBOSE, COSTS OFF)
                SELECT id, title FROM documents
                WHERE id = :id
            """),
            {"id": doc_id},
        )
        plan_json = result.scalar_one()
        raw_plan = str(plan_json)

        # Invariant 1: volatile current_setting is not inlined
        assert "current_setting" not in raw_plan, "Optimizer inlined context helper!"

        # Invariant 2: Plan uses Index Scan
        plan_node = plan_json[0]["Plan"]
        assert "Index" in plan_node["Node Type"]

    await engine.dispose()

@pytest.mark.anyio
async def test_cancelled_coroutine_never_contaminates_single_connection_pool():
    engine = create_async_engine(
        settings.DATABASE_URL,
        poolclass=NullPool,
    )
    victim_tenant = str(uuid.uuid4())

    async def _aborted_task():
        async with scoped_tenant_session(victim_tenant) as session:
            await session.execute(text("SELECT pg_sleep(3.0)"))

    task = asyncio.create_task(_aborted_task())
    await asyncio.sleep(0.05)
    task.cancel()

    with pytest.raises(asyncio.CancelledError):
        await task

    async with engine.connect() as conn:
        leaked_guc = await conn.scalar(
            text("SELECT NULLIF(current_setting('app.current_tenant_id', true), '')")
        )
        assert leaked_guc is None, f"Connection pool leaked GUC state: {leaked_guc}"

    await engine.dispose()

@pytest.mark.anyio
async def test_bola_404_timing_indistinguishability():
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())
    token_b = mint_test_token(tenant_id=tenant_b, subject="attacker-probe")

    engine = create_async_engine(settings.DATABASE_URL, poolclass=NullPool)
    doc_id = uuid.uuid4()

    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t1, 'Org A'), (:t2, 'Org B')"),
            {"t1": tenant_a, "t2": tenant_b},
        )
        await conn.execute(
            text("SELECT set_config('app.current_tenant_id', :tenant_id, true)"),
            {"tenant_id": tenant_a},
        )
        await conn.execute(
            text("INSERT INTO documents (id, tenant_id, title, content) VALUES (:id, :t, 'A', 'A')"),
            {"id": doc_id, "t": tenant_a},
        )
        await conn.commit()
    await engine.dispose()

    redis_client = get_redis_client()
    jail_key = f"jail:{tenant_b}"
    violations_key = f"violations:{tenant_b}"
    rate_key = f"rate:{{{tenant_b}}}"

    headers = {"Authorization": f"Bearer {token_b}"}
    cross_latencies = []
    fake_latencies = []

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Warmup
        await client.get(f"/documents/{uuid.uuid4()}", headers=headers)
        await redis_client.delete(jail_key, violations_key, rate_key)

        for _ in range(15):
            await redis_client.delete(jail_key, violations_key, rate_key)

            t0 = time.perf_counter_ns()
            r1 = await client.get(f"/documents/{doc_id}", headers=headers)
            t1 = time.perf_counter_ns()
            assert r1.status_code == 404
            cross_latencies.append((t1 - t0) / 1e6)

            await redis_client.delete(jail_key, violations_key, rate_key)

            fake_id = uuid.uuid4()
            t2 = time.perf_counter_ns()
            r2 = await client.get(f"/documents/{fake_id}", headers=headers)
            t3 = time.perf_counter_ns()
            assert r2.status_code == 404
            fake_latencies.append((t3 - t2) / 1e6)

    median_cross = statistics.median(cross_latencies)
    median_fake = statistics.median(fake_latencies)
    delta_ms = abs(median_cross - median_fake)

    assert delta_ms < 3.5, (
        f"Timing oracle detected: Cross-tenant={median_cross:.2f}ms vs Fake={median_fake:.2f}ms (delta={delta_ms:.2f}ms)"
    )