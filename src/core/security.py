from datetime import datetime, timezone, timedelta
from typing import Any, Dict, Optional
import jwt
from src.core.config import settings
from src.core.jwks import JWKSManager

jwks_manager = JWKSManager()

def create_access_token_rs256(
    tenant_id: str,
    subject: str,
    private_key: Any,
    kid: str,
    expires_delta: timedelta = timedelta(minutes=30),
) -> str:
    """Helper to mint RS256 tokens for testing."""
    now = datetime.now(timezone.utc)
    payload: Dict[str, Any] = {
        "sub": subject,
        "tenant_id": str(tenant_id),
        "iat": now,
        "exp": now + expires_delta,
    }
    return jwt.encode(
        payload,
        private_key,
        algorithm="RS256",
        headers={"kid": kid, "typ": "JWT"},
    )

async def decode_access_token(token: str) -> Dict[str, Any]:
    """
    Decodes and verifies an RS256 JWT using public keys retrieved via JWKS.
    Enforces strict RFC 8725 validation rules:
      1. Algorithm must be explicitly RS256.
      2. Token header must supply a valid 'kid'.
      3. Public key signature must verify.
    """
    try:
        # Extract unverified headers to inspect algorithm and key ID
        unverified_headers = jwt.get_unverified_header(token)
    except jwt.PyJWTError:
        raise jwt.InvalidTokenError("Malformed token headers.")

    alg = unverified_headers.get("alg")
    kid = unverified_headers.get("kid")

    # Defense against Algorithm Confusion: Enforce RS256 exclusively
    if alg != "RS256":
        raise jwt.InvalidAlgorithmError(f"Unsupported algorithm '{alg}'. RS256 is strictly required.")

    if not kid:
        raise jwt.InvalidTokenError("Missing 'kid' in token header.")

    # Retrieve matching public key from the JWKS manager
    public_key = await jwks_manager.get_public_key(kid)

    # Cryptographic verification
    return jwt.decode(
        token,
        public_key,
        algorithms=["RS256"],
        options={"require": ["exp", "iat", "sub", "tenant_id"]},
    )