import asyncio
from unittest.mock import patch
import httpx
import pytest

from src.core.config import settings
from src.core.jwks import EnterpriseJWKSVerifier
from src.core.transport import SSRFProtectedTransport


@pytest.mark.anyio
async def test_ssrf_blocks_aws_metadata_endpoint():
    """
    Asserts that requests targeting the AWS EC2 instance metadata service (169.254.169.254)
    are immediately blocked by SSRFProtectedTransport and raise PermissionError.
    """
    transport = SSRFProtectedTransport()
    async with httpx.AsyncClient(transport=transport) as client:
        # HTTP scheme to AWS metadata
        with pytest.raises(PermissionError) as exc_info:
            await client.get("http://169.254.169.254/latest/meta-data/")
        assert "SSRF Protection" in str(exc_info.value)
        assert "169.254.169.254" in str(exc_info.value) or "Insecure scheme" in str(exc_info.value)

        # HTTPS scheme to AWS metadata must also be blocked by IP inspection
        with pytest.raises(PermissionError) as exc_info_https:
            await client.get("https://169.254.169.254/latest/meta-data/")
        assert "SSRF Protection" in str(exc_info_https.value)
        assert "169.254.169.254" in str(exc_info_https.value)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "private_ip",
    [
        "10.0.0.1",
        "192.168.1.1",
        "172.16.0.1",
        "172.31.255.254",
        "10.254.254.254",
    ],
)
async def test_ssrf_blocks_private_ip_ranges(private_ip: str):
    """
    Asserts that requests to private RFC 1918 IPv4 ranges are strictly blocked
    and raise PermissionError under both HTTP and HTTPS schemes.
    """
    transport = SSRFProtectedTransport()
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(PermissionError) as exc_http:
            await client.get(f"http://{private_ip}/")
        assert "SSRF Protection" in str(exc_http.value)

        with pytest.raises(PermissionError) as exc_https:
            await client.get(f"https://{private_ip}/")
        assert "SSRF Protection" in str(exc_https.value)
        assert private_ip in str(exc_https.value)


@pytest.mark.anyio
async def test_valid_https_endpoints_resolve_and_proceed():
    """
    Asserts that valid, publicly routable HTTPS endpoints pass the SSRF validation
    checks and proceed to super().handle_async_request() without error.
    """
    mock_response = httpx.Response(
        200,
        json={"keys": [{"kty": "RSA", "kid": "valid-public-key"}]},
    )

    with patch.object(httpx.AsyncHTTPTransport, "handle_async_request", return_value=mock_response):
        transport = SSRFProtectedTransport()
        async with httpx.AsyncClient(transport=transport) as client:
            # 1. Valid public domain name
            resp = await client.get("https://example.com/.well-known/jwks.json")
            assert resp.status_code == 200
            assert resp.json()["keys"][0]["kid"] == "valid-public-key"

            # 2. Valid public IP address (Cloudflare DNS: 1.1.1.1)
            resp_ip = await client.get("https://1.1.1.1/.well-known/jwks.json")
            assert resp_ip.status_code == 200
            assert resp_ip.json()["keys"][0]["kid"] == "valid-public-key"


@pytest.mark.anyio
async def test_insecure_scheme_blocked_in_production():
    """
    Asserts that HTTP requests to external domains are rejected when ENVIRONMENT != 'test'.
    """
    orig_env = settings.ENVIRONMENT
    try:
        settings.ENVIRONMENT = "production"
        transport = SSRFProtectedTransport()
        async with httpx.AsyncClient(transport=transport) as client:
            with pytest.raises(PermissionError) as exc_info:
                await client.get("http://example.com/jwks.json")
            assert "Only HTTPS is permitted" in str(exc_info.value)
    finally:
        settings.ENVIRONMENT = orig_env


@pytest.mark.anyio
async def test_enterprise_jwks_verifier_blocks_ssrf_requests():
    """
    Asserts that EnterpriseJWKSVerifier utilizes SSRFProtectedTransport by default
    and raises PermissionError when configured with malicious or internal JWKS URLs.
    """
    # 1. AWS EC2 Metadata SSRF attempt via EnterpriseJWKSVerifier
    verifier_aws = EnterpriseJWKSVerifier(
        jwks_url="http://169.254.169.254/latest/meta-data/",
        cooldown_seconds=1.0,
    )
    with pytest.raises(PermissionError) as exc_aws:
        await verifier_aws.get_public_key("malicious-kid-1")
    assert "SSRF Protection" in str(exc_aws.value)

    # 2. Internal private network probe attempt via EnterpriseJWKSVerifier
    verifier_internal = EnterpriseJWKSVerifier(
        jwks_url="https://10.0.0.1/.well-known/jwks.json",
        cooldown_seconds=1.0,
    )
    with pytest.raises(PermissionError) as exc_internal:
        await verifier_internal.get_public_key("malicious-kid-2")
    assert "SSRF Protection" in str(exc_internal.value)
    assert "10.0.0.1" in str(exc_internal.value)


@pytest.mark.anyio
@pytest.mark.parametrize(
    "restricted_ip",
    [
        "224.0.0.1",       # Multicast
        "0.0.0.0",         # Unspecified
        "240.0.0.1",       # Reserved
        "::ffff:10.0.0.1", # IPv4-mapped private
    ],
)
async def test_ssrf_blocks_multicast_reserved_and_mapped_ips(restricted_ip: str):
    """
    Asserts that multicast, unspecified, reserved, and IPv4-mapped IPv6 addresses
    are strictly rejected.
    """
    transport = SSRFProtectedTransport()
    formatted_target = f"[{restricted_ip}]" if ":" in restricted_ip else restricted_ip
    async with httpx.AsyncClient(transport=transport) as client:
        with pytest.raises(PermissionError):
            await client.get(f"https://{formatted_target}/")
