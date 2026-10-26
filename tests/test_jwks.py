
import pytest
import time
import json
import jwt
from httpx import AsyncClient, MockTransport, Response
from cryptography.hazmat.primitives.asymmetric import rsa
from jwt.algorithms import RSAAlgorithm

from src.core.jwks import JWKSManager

def generate_rsa_keypair(kid: str):
    """Generates an in-memory RSA keypair for testing."""
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Convert public key to RFC 7517 JWK dict
    jwk_dict = json.loads(RSAAlgorithm.to_jwk(public_key))
    jwk_dict["kid"] = kid
    jwk_dict["use"] = "sig"
    jwk_dict["alg"] = "RS256"
    
    return private_key, public_key, jwk_dict

@pytest.mark.anyio
async def test_jwks_fetch_and_verify_rsa_token():
    kid = "test-key-2026"
    priv_key, pub_key, jwk_dict = generate_rsa_keypair(kid)

    # Mock the IdP endpoint returning our JWKS
    jwks_payload = {"keys": [jwk_dict]}
    transport = MockTransport(lambda req: Response(200, json=jwks_payload))

    async with AsyncClient(transport=transport) as mock_client:
        manager = JWKSManager(jwks_url="https://mock-idp.local/jwks.json", cooldown_seconds=5)

        # 1. Fetch public key via manager
        resolved_key = await manager.get_public_key(kid=kid, client=mock_client)
        assert resolved_key is not None

        # 2. Mint a real RS256 token using the private key
        token = jwt.encode(
            {"sub": "user-123", "tenant_id": "tenant-abc"},
            priv_key,
            algorithm="RS256",
            headers={"kid": kid}
        )

        # 3. Verify signature using the public key from the manager
        decoded = jwt.decode(token, resolved_key, algorithms=["RS256"])
        assert decoded["sub"] == "user-123"
        assert decoded["tenant_id"] == "tenant-abc"

@pytest.mark.anyio
async def test_jwks_cooldown_prevents_outbound_flooding():
    """
    Verifies that querying multiple unknown kids does NOT trigger
    unbounded outbound HTTP calls during the cooldown window.
    """
    call_count = 0

    def handler(request):
        nonlocal call_count
        call_count += 1
        return Response(200, json={"keys": []})

    transport = MockTransport(handler)

    async with AsyncClient(transport=transport) as mock_client:
        # Set cooldown to 10 seconds
        manager = JWKSManager(jwks_url="https://mock-idp.local/jwks.json", cooldown_seconds=10)

        # 1. First unknown kid triggers outbound call
        with pytest.raises(jwt.PyJWTError) as exc_1:
            await manager.get_public_key("unknown-kid-1", client=mock_client)
        assert "not found in JWKS after refresh" in str(exc_1.value)
        assert call_count == 1

        # 2. Second unknown kid immediately after MUST be blocked by cooldown
        with pytest.raises(jwt.PyJWTError) as exc_2:
            await manager.get_public_key("unknown-kid-2", client=mock_client)
        assert "refresh on cooldown" in str(exc_2.value)
        # Crucial check: Network call count did NOT increase
        assert call_count == 1