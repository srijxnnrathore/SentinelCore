import asyncio
import re
import time
from typing import Any, Dict, Optional
import httpx
import jwt
from jwt.algorithms import RSAAlgorithm
from src.core.config import settings

KID_REGEX = re.compile(r"^[a-zA-Z0-9_\-\.]{1,64}$")

class JWKSManager:
    def __init__(
        self,
        jwks_url: str = settings.JWKS_URL,
        cooldown_seconds: Optional[float] = None,
        min_refresh_interval: Optional[float] = None,
        cache_ttl: float = 3600.0,
        max_stale_age: float = 86400.0,
    ):
        self.jwks_url = jwks_url
        self.cooldown_seconds = (
            cooldown_seconds
            if cooldown_seconds is not None
            else (min_refresh_interval if min_refresh_interval is not None else float(settings.JWKS_COOLDOWN_SECONDS))
        )
        self.cache_ttl = cache_ttl
        self.max_stale_age = max_stale_age

        self._keys: Dict[str, Any] = {}
        # Stores verified absent kids: kid -> expiry_ts
        self._verified_missing_kids: Dict[str, float] = {}
        self._last_success_ts: float = 0.0
        self._last_attempt_ts: float = 0.0
        self._lock = asyncio.Lock()

    async def get_public_key(
        self,
        token_or_kid: Optional[str] = None,
        kid: Optional[str] = None,
        client: Optional[httpx.AsyncClient] = None,
    ) -> Any:
        target_kid = kid or token_or_kid
        if not target_kid:
            raise jwt.PyJWTError("Missing Key ID (kid)")

        if "." in target_kid:
            try:
                unverified_header = jwt.get_unverified_header(target_kid)
            except jwt.PyJWTError as exc:
                raise jwt.InvalidTokenError("Malformed JWS header") from exc

            if unverified_header.get("alg") != "RS256":
                raise jwt.InvalidAlgorithmError("Unsupported algorithm: RS256 required")
            for forbidden in ("jku", "jwk", "x5u", "x5c", "crit"):
                if forbidden in unverified_header:
                    raise jwt.InvalidTokenError(f"Forbidden JWS header parameter: {forbidden}")

            target_kid = unverified_header.get("kid")
            if not target_kid:
                raise jwt.InvalidTokenError("Missing 'kid' in token header")

        if not isinstance(target_kid, str) or not KID_REGEX.match(target_kid):
            raise jwt.PyJWTError(f"Invalid 'kid' format: {target_kid}")

        now = time.monotonic()

        # 1. Positive cache hit
        if target_kid in self._keys and (now - self._last_success_ts) < self.cache_ttl:
            return self._keys[target_kid]

        # 2. Verified negative cache hit
        if now < self._verified_missing_kids.get(target_kid, 0.0):
            raise jwt.PyJWTError(f"Key ID '{target_kid}' not found and JWKS refresh on cooldown")

        async with self._lock:
            now = time.monotonic()
            if target_kid in self._keys and (now - self._last_success_ts) < self.cache_ttl:
                return self._keys[target_kid]

            if now < self._verified_missing_kids.get(target_kid, 0.0):
                raise jwt.PyJWTError(f"Key ID '{target_kid}' not found and JWKS refresh on cooldown")

            refreshed_upstream = False
            if (now - self._last_attempt_ts) >= self.cooldown_seconds:
                self._last_attempt_ts = now
                refreshed_upstream = await self._refresh_keys(now, client=client)

            if target_kid in self._keys:
                return self._keys[target_kid]

            # Invariant: Record in negative cache if upstream fetch confirmed key is missing
            if refreshed_upstream:
                if len(self._verified_missing_kids) >= 1024:
                    self._verified_missing_kids.clear()
                self._verified_missing_kids[target_kid] = now + self.cooldown_seconds
                raise jwt.PyJWTError(f"Key ID '{target_kid}' not found in JWKS after refresh")

            raise jwt.PyJWTError(f"Key ID '{target_kid}' not found and JWKS refresh on cooldown")

    async def get_key(self, kid: str, client: Optional[httpx.AsyncClient] = None) -> Any:
        return await self.get_public_key(kid=kid, client=client)

    async def _refresh_keys(self, now: float, client: Optional[httpx.AsyncClient] = None) -> bool:
        try:
            if client is not None:
                resp = await client.get(self.jwks_url)
                resp.raise_for_status()
                data = resp.json()
            else:
                async with httpx.AsyncClient(timeout=3.0, follow_redirects=False) as default_client:
                    resp = await default_client.get(self.jwks_url)
                    resp.raise_for_status()
                    data = resp.json()

            new_keys: Dict[str, Any] = {}
            for k in data.get("keys", []):
                if k.get("kty") == "RSA":
                    if k.get("use") and k.get("use") != "sig":
                        continue
                    if k.get("alg") and k.get("alg") != "RS256":
                        continue

                    k_id = k.get("kid")
                    if isinstance(k_id, str) and KID_REGEX.match(k_id):
                        pub = RSAAlgorithm.from_jwk(k)
                        if getattr(pub, "key_size", 2048) >= 2048:
                            new_keys[k_id] = pub

            # Successful response parsed: update state
            self._keys = new_keys
            self._last_success_ts = now
            self._verified_missing_kids.clear()
            return True
        except Exception:
            if (now - self._last_success_ts) > self.max_stale_age:
                self._keys.clear()
            return False

    def set_keys_manually(self, keys_dict: Dict[str, Any]) -> None:
        self._keys = keys_dict
        self._last_success_ts = time.monotonic()

jwks_manager = JWKSManager()