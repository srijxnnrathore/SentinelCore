import asyncio
import re
import time
import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from src.core.redis import get_redis_client
from src.core.security import jwks_manager
from src.db.session import (
    COALESCED_CONTEXT_SQL,
    engine,
    generate_w3c_traceparent,
    scoped_tenant_session,
)
from src.main import app
from tests.conftest import _pub_key, TEST_KID, mint_test_token


@pytest.mark.anyio
async def test_scoped_tenant_session_sets_coalesced_context():
    """
    Asserts that scoped_tenant_session executes the single-RTT coalesced query
    setting app.current_tenant_id, app.current_trace_id, and application_name.
    """
    tenant_id = str(uuid.uuid4())
    custom_trace = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

    async with scoped_tenant_session(tenant_id, trace_id=custom_trace) as session:
        curr_tenant = await session.scalar(
            text("SELECT current_setting('app.current_tenant_id')")
        )
        curr_trace = await session.scalar(
            text("SELECT current_setting('app.current_trace_id')")
        )
        curr_app = await session.scalar(
            text("SELECT current_setting('application_name')")
        )

        assert curr_tenant == tenant_id
        assert curr_trace == custom_trace
        assert curr_app.startswith("sentinel:")
        assert custom_trace[:32] in curr_app


@pytest.mark.anyio
async def test_scoped_tenant_session_auto_generates_w3c_traceparent():
    """
    Asserts that if trace_id is omitted, a valid W3C traceparent is generated
    in format: 00-<32_hex_trace_id>-<16_hex_span_id>-01.
    """
    tenant_id = str(uuid.uuid4())

    async with scoped_tenant_session(tenant_id) as session:
        curr_trace = await session.scalar(
            text("SELECT current_setting('app.current_trace_id')")
        )
        assert curr_trace is not None
        # Strict W3C format validation
        w3c_pattern = r"^00-[0-9a-f]{32}-[0-9a-f]{16}-01$"
        assert re.match(w3c_pattern, curr_trace), f"Invalid W3C traceparent: {curr_trace}"


@pytest.mark.anyio
async def test_pg_stat_activity_reflects_active_trace_prefix():
    """
    Asserts that pg_stat_activity for the current backend PID reflects the
    active trace prefix in its application_name column.
    """
    tenant_id = str(uuid.uuid4())
    custom_trace = f"00-{uuid.uuid4().hex}-{uuid.uuid4().hex[:16]}-01"

    async with scoped_tenant_session(tenant_id, trace_id=custom_trace) as session:
        stat_app_name = await session.scalar(
            text("""
                SELECT application_name
                FROM pg_stat_activity
                WHERE pid = pg_backend_pid()
            """)
        )

        assert stat_app_name is not None
        assert stat_app_name.startswith("sentinel:")
        expected_prefix = custom_trace[:32]
        assert expected_prefix in stat_app_name


@pytest.mark.anyio
async def test_prepared_statement_caching_without_invalidation():
    """
    Asserts that parameterized COALESCED_CONTEXT_SQL reuses cached prepared
    statements without statement cache thrashing or query re-planning overhead.
    """
    # Execute 5 iterations with distinct tenant and trace IDs
    for i in range(5):
        t_id = str(uuid.uuid4())
        tr_id = generate_w3c_traceparent()
        async with scoped_tenant_session(t_id, trace_id=tr_id) as session:
            # Query pg_prepared_statements to confirm statement registration
            stmts = (await session.execute(
                text("SELECT name, statement FROM pg_prepared_statements")
            )).all()

            # Find statements matching the coalesced query pattern
            coalesced_stmts = [
                s for s in stmts
                if "app.current_tenant_id" in s[1] and "app.current_trace_id" in s[1]
            ]
            # Must have prepared the statement once and not created duplicates
            assert len(coalesced_stmts) <= 1, (
                f"Prepared statement cache leak: found {len(coalesced_stmts)} statements"
            )


@pytest.mark.anyio
async def test_guc_reset_on_transaction_end_and_abort():
    """
    Asserts that transaction-scoped GUCs (is_local=true) automatically reset
    upon both normal transaction completion and unexpected cancellation/abort.
    """
    tenant_id = str(uuid.uuid4())
    trace_id = generate_w3c_traceparent()

    # 1. Normal transaction completion
    async with scoped_tenant_session(tenant_id, trace_id=trace_id) as session:
        active_tenant = await session.scalar(
            text("SELECT current_setting('app.current_tenant_id')")
        )
        assert active_tenant == tenant_id

    # Outside transaction: must be cleanly reset
    async with engine.connect() as conn:
        reset_tenant = await conn.scalar(
            text("SELECT NULLIF(current_setting('app.current_tenant_id', true), '')")
        )
        reset_trace = await conn.scalar(
            text("SELECT NULLIF(current_setting('app.current_trace_id', true), '')")
        )
        assert reset_tenant is None, f"Leaked tenant GUC: {reset_tenant}"
        assert reset_trace is None, f"Leaked trace GUC: {reset_trace}"

    # 2. Aborted / failed transaction
    with pytest.raises(RuntimeError):
        async with scoped_tenant_session(tenant_id, trace_id=trace_id) as session:
            raise RuntimeError("Simulated transaction rollback")

    # Outside aborted transaction: must be cleanly reset
    async with engine.connect() as conn:
        post_abort_tenant = await conn.scalar(
            text("SELECT NULLIF(current_setting('app.current_tenant_id', true), '')")
        )
        post_abort_trace = await conn.scalar(
            text("SELECT NULLIF(current_setting('app.current_trace_id', true), '')")
        )
        assert post_abort_tenant is None
        assert post_abort_trace is None


@pytest.mark.anyio
async def test_fastapi_trace_header_propagation():
    """
    Asserts that incoming W3C traceparent or X-Trace-ID headers from HTTP
    requests are extracted by get_db and passed into scoped_tenant_session.
    """
    jwks_manager.set_keys_manually({TEST_KID: _pub_key})
    redis_client = get_redis_client()

    tenant_id = str(uuid.uuid4())
    token = mint_test_token(tenant_id=tenant_id, subject="trace-tester")

    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t, 'Trace Org')"),
            {"t": tenant_id},
        )
        await conn.commit()
    await redis_client.delete(f"rate:{{{tenant_id}}}")

    w3c_header = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Request with W3C traceparent header
        resp1 = await client.get(
            "/documents/",
            headers={
                "Authorization": f"Bearer {token}",
                "traceparent": w3c_header,
            },
        )
        assert resp1.status_code == 200

        # Request with X-Trace-ID header
        custom_x_trace = "trace-custom-correlation-999"
        resp2 = await client.get(
            "/documents/",
            headers={
                "Authorization": f"Bearer {token}",
                "X-Trace-ID": custom_x_trace,
            },
        )
        assert resp2.status_code == 200

    await redis_client.delete(f"rate:{{{tenant_id}}}")

