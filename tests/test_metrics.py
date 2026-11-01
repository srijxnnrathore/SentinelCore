import re
import uuid
import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy import text

from src.core.metrics import (
    HTTP_REQUESTS_TOTAL,
    RATE_LIMIT_DROPS_TOTAL,
    THREAT_CIRCUIT_TRIPS_TOTAL,
    normalize_endpoint,
)
from src.core.redis import get_redis_client
from src.core.security import jwks_manager
from src.core.threat_detector import threat_detector
from src.db.session import engine
from src.main import app
from tests.conftest import _pub_key, TEST_KID, mint_test_token


@pytest.mark.anyio
async def test_metrics_endpoint_returns_200_and_text_plain():
    """
    Verifies that GET /metrics responds with 200 OK and text/plain content type.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        resp = await client.get("/metrics")
        assert resp.status_code == 200
        assert "text/plain" in resp.headers["content-type"]
        assert "sentinel_http_requests_total" in resp.text


@pytest.mark.anyio
async def test_route_normalization_bounds_endpoint_cardinality():
    """
    Asserts that normalize_endpoint replaces arbitrary UUIDs with '{id}',
    and that requests to /documents/{random_uuid} register as /documents/{id} in Prometheus.
    """
    jwks_manager.set_keys_manually({TEST_KID: _pub_key})
    redis_client = get_redis_client()

    tenant_id = str(uuid.uuid4())
    token = mint_test_token(tenant_id=tenant_id, subject="metrics-tester")

    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t, 'Metrics Org')"),
            {"t": tenant_id},
        )
        await conn.commit()
    await redis_client.delete(f"rate:{{{tenant_id}}}")

    # Generate 3 distinct random UUIDs
    random_uuids = [str(uuid.uuid4()) for _ in range(3)]

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {token}"}
        for doc_id in random_uuids:
            res = await client.get(f"/documents/{doc_id}", headers=headers)
            assert res.status_code == 404

        metrics_resp = await client.get("/metrics")
        metrics_body = metrics_resp.text

        # 1. Parameterized template /documents/{id} must be registered
        assert 'endpoint="/documents/{id}"' in metrics_body

        # 2. None of the raw UUIDs must appear in Prometheus label values
        for doc_id in random_uuids:
            assert f'endpoint="/documents/{doc_id}"' not in metrics_body
            assert doc_id not in metrics_body

    await redis_client.delete(f"rate:{{{tenant_id}}}")


@pytest.mark.anyio
async def test_status_codes_categorized_by_class():
    """
    Asserts that status codes are categorized by class (2xx, 4xx, 5xx)
    rather than unbounded exact status code values.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Trigger a 200 response
        resp_200 = await client.get("/health/live")
        assert resp_200.status_code == 200

        # Trigger a 404 response
        resp_404 = await client.get("/nonexistent-endpoint")
        assert resp_404.status_code == 404

        metrics_resp = await client.get("/metrics")
        metrics_body = metrics_resp.text

        assert 'status_class="2xx"' in metrics_body
        assert 'status_class="4xx"' in metrics_body


@pytest.mark.anyio
async def test_rate_limit_and_threat_counters_increment():
    """
    Asserts that sentinel_rate_limit_drops_total and sentinel_threat_circuit_trips_total
    counters increment when rate limits are exceeded or threats trigger quarantine.
    """
    jwks_manager.set_keys_manually({TEST_KID: _pub_key})
    redis_client = get_redis_client()

    tenant_id = str(uuid.uuid4())
    token = mint_test_token(tenant_id=tenant_id, subject="burst-actor")

    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t, 'Rate Limit Metrics Org')"),
            {"t": tenant_id},
        )
        await conn.commit()
    await redis_client.delete(f"rate:{{{tenant_id}}}")

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        headers = {"Authorization": f"Bearer {token}"}
        # Exhaust rate limit quota (limit=5 per minute)
        for _ in range(5):
            await client.get("/documents/", headers=headers)

        # 6th request must trigger rate limiter drop
        drop_res = await client.get("/documents/", headers=headers)
        assert drop_res.status_code == 429

        # Trigger threat quarantine circuit trip directly
        adversary_tenant = str(uuid.uuid4())
        await redis_client.delete(f"jail:{adversary_tenant}", f"violations:{adversary_tenant}")

        for _ in range(threat_detector.max_violations):
            await threat_detector.record_violation(adversary_tenant, event_type="cross_tenant_probe")

        # Fetch metrics and verify counter increments
        metrics_resp = await client.get("/metrics")
        metrics_body = metrics_resp.text

        assert "sentinel_rate_limit_drops_total" in metrics_body
        assert 'sentinel_rate_limit_drops_total{endpoint="/documents/"}' in metrics_body
        assert 'sentinel_threat_circuit_trips_total{event_type="cross_tenant_probe"}' in metrics_body

    await redis_client.delete(f"rate:{{{tenant_id}}}")
    await redis_client.delete(f"jail:{adversary_tenant}", f"violations:{adversary_tenant}")


@pytest.mark.anyio
async def test_zero_high_cardinality_labels_in_metrics():
    """
    Asserts that sensitive and unbounded entity identifiers (tenant_id, user_id,
    document_id, actor_id) never appear as label keys in the Prometheus metrics output.
    """
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        # Generate some traffic
        await client.get("/health/live")
        await client.get("/metrics")

        metrics_resp = await client.get("/metrics")
        metrics_body = metrics_resp.text

        # Ensure high-cardinality label keys are absent
        forbidden_labels = [
            'tenant_id="',
            'user_id="',
            'document_id="',
            'actor_id="',
            'client_ip="',
            'ip_address="',
        ]
        for forbidden in forbidden_labels:
            assert forbidden not in metrics_body, (
                f"High-cardinality label leak detected in Prometheus metrics: {forbidden}"
            )

