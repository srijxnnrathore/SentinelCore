import pytest
import uuid
import json
import base64
import hmac
import hashlib
from httpx import AsyncClient, ASGITransport
from sqlalchemy import text
from cryptography.hazmat.primitives import serialization

from src.main import app
from src.db.session import engine, AsyncSessionLocal
from tests.conftest import mint_test_token, _pub_key

@pytest.mark.anyio
async def test_exploit_bola_cross_tenant_read_returns_404():
    tenant_a = str(uuid.uuid4())
    tenant_b = str(uuid.uuid4())

    token_a = mint_test_token(tenant_id=tenant_a, subject="attacker-tenant-a")
    token_b = mint_test_token(tenant_id=tenant_b, subject="victim-tenant-b")

    async with engine.connect() as conn:
        await conn.execute(
            text("INSERT INTO tenants (id, name) VALUES (:t1, 'Attacker Org'), (:t2, 'Victim Org')"),
            {"t1": tenant_a, "t2": tenant_b}
        )
        await conn.commit()

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res_victim = await client.post(
            "/documents/",
            headers={"Authorization": f"Bearer {token_b}"},
            json={"title": "M&A Target Strategy", "content": "Classified Acquisition Targets"}
        )
        assert res_victim.status_code == 201
        secret_doc_id = res_victim.json()["id"]

        res_attack = await client.get(
            f"/documents/{secret_doc_id}",
            headers={"Authorization": f"Bearer {token_a}"}
        )
        assert res_attack.status_code == 404
        assert res_attack.json()["detail"] == "Document not found"

    async with AsyncSessionLocal() as session:
        result = await session.execute(
            text("""
                SELECT action, status, resource_id 
                FROM audit_logs 
                WHERE tenant_id = :t AND action = 'DOCUMENT_READ_DENIED'
            """),
            {"t": tenant_a}
        )
        log_entry = result.mappings().one_or_none()
        assert log_entry is not None
        assert log_entry["status"] == "DENIED"
        assert log_entry["resource_id"] == secret_doc_id


@pytest.mark.anyio
async def test_exploit_algorithm_confusion_attack_blocked():
    """
    CRITICAL APPSEC REGRESSION:
    Attacker takes the server's public RSA key in PEM format, uses it as an HMAC
    symmetric secret to sign an HS256 token, claiming to be an administrator.
    The server MUST reject this algorithm mismatch immediately.
    """
    fake_tenant = str(uuid.uuid4())
    pem_public_key = _pub_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    header = {"alg": "HS256", "typ": "JWT", "kid": "sentinelcore-test-key-1"}
    payload = {"sub": "rogue-agent", "tenant_id": fake_tenant, "exp": 9999999999, "iat": 1000000000}

    header_b64 = base64.urlsafe_b64encode(json.dumps(header).encode()).decode().rstrip("=")
    payload_b64 = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signing_input = f"{header_b64}.{payload_b64}".encode()

    signature = hmac.new(pem_public_key, signing_input, hashlib.sha256).digest()
    sig_b64 = base64.urlsafe_b64encode(signature).decode().rstrip("=")

    forged_token = f"{signing_input.decode()}.{sig_b64}"

    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get(
            "/documents/",
            headers={"Authorization": f"Bearer {forged_token}"}
        )
        assert res.status_code == 401
        assert res.json()["detail"] == "Invalid authentication token"


@pytest.mark.anyio
async def test_exploit_session_context_leak_prevention():
    tenant_1 = str(uuid.uuid4())

    from src.db.session import scoped_tenant_session

    async with scoped_tenant_session(tenant_1) as session:
        val = await session.execute(text("SELECT current_setting('app.current_tenant_id', true)"))
        assert val.scalar() == tenant_1

    async with AsyncSessionLocal() as session:
        val_unscoped = await session.execute(text("SELECT current_setting('app.current_tenant_id', true)"))
        assert val_unscoped.scalar() in (None, "")