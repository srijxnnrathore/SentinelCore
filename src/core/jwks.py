import time
import asyncio
from typing import Dict, Any, Optional
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from src.core.config import settings

class JWKSManager:
    """
    Manages fetching, caching, and thread-safe rotation of RSA public keys
    from an Identity Provider's JWKS endpoint.
    """
    def __init__(self, jwks_url: str = settings.JWKS_URL, cooldown_seconds: int = settings.JWKS_COOLDOWN_SECONDS):
        self.jwks_url = jwks_url
        self.cooldown_seconds = cooldown_seconds
        self._keys: Dict[str, Any] = {}
        self._last_refresh: float = 0.0
        self._lock = asyncio.Lock()

    async def get_public_key(self, kid: str, client: Optional[httpx.AsyncClient] = None) -> Any:
        """
        Retrieves an RSA public key by kid.
        If missing, attempts a refresh subject to the cooldown lock.
        """
        # 1. Fast Path: In-memory cache hit
        if kid in self._keys:
            return self._keys[kid]

        # 2. Slow Path: Cache miss. Acquire lock to prevent cache stampede
        async with self._lock:
            # Double-check: another coroutine might have fetched it while waiting for the lock
            if kid in self._keys:
                return self._keys[kid]

            # Enforce cooldown: Protect IdP from outbound DoS
            now = time.time()
            if (now - self._last_refresh) < self.cooldown_seconds:
                raise jwt.PyJWTError(f"Key ID '{kid}' not found in cache (refresh on cooldown).")

            # Outbound fetch
            await self._refresh_keys(client=client)
            self._last_refresh = time.time()

            # Check again after fresh fetch
            if kid in self._keys:
                return self._keys[kid]

            raise jwt.PyJWTError(f"Key ID '{kid}' not found in JWKS after refresh.")

    async def _refresh_keys(self, client: Optional[httpx.AsyncClient] = None) -> None:
        """
        Performs the outbound HTTP GET to the JWKS endpoint and parses RSA public keys.
        """
        if client is not None:
            response = await client.get(self.jwks_url)
            data = response.json()
        else:
            async with httpx.AsyncClient(timeout=5.0) as default_client:
                response = await default_client.get(self.jwks_url)
                data = response.json()

        raw_keys = data.get("keys", [])
        new_keys: Dict[str, Any] = {}

        for key_data in raw_keys:
            kid = key_data.get("kid")
            if kid and key_data.get("kty") == "RSA":
                # Convert RFC 7517 JWK dict (n, e) into an RSA Public Key object
                public_key = RSAAlgorithm.from_jwk(key_data)
                new_keys[kid] = public_key

        self._keys = new_keys

    def set_keys_manually(self, keys_dict: Dict[str, Any]) -> None:
        """Helper used in testing to seed keys without network calls."""
        self._keys = keys_dict
        self._last_refresh = time.time()