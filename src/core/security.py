from datetime import datetime, timedelta, timezone
from typing import Any, Dict, Optional
import jwt
from fastapi import HTTPException, status
from src.core.jwks import jwks_manager

__all__ = ["jwks_manager", "decode_token", "create_access_token_rs256"]

def create_access_token_rs256(
    data: Optional[Dict[str, Any]] = None,
    tenant_id: Optional[str] = None,
    subject: Optional[str] = None,
    private_key: Optional[str] = None,
    kid: Optional[str] = None,
    expires_delta: Optional[timedelta] = None,
    **kwargs: Any,
) -> str:
    payload: Dict[str, Any] = {}
    if data:
        payload.update(data)
    if tenant_id:
        payload["tenant_id"] = str(tenant_id)
    if subject:
        payload["sub"] = str(subject)

    for k, v in kwargs.items():
        payload[k] = v

    now = datetime.now(timezone.utc)
    if expires_delta:
        expire = now + expires_delta
    else:
        expire = now + timedelta(minutes=15)

    payload.setdefault("exp", expire)
    payload.setdefault("iat", now)

    headers = {"kid": kid or "sentinelcore-test-key-1", "alg": "RS256"}
    return jwt.encode(payload, private_key, algorithm="RS256", headers=headers)

async def decode_token(token: str) -> Dict[str, Any]:
    try:
        public_key = await jwks_manager.get_public_key(token)
        payload = jwt.decode(
            token,
            key=public_key,
            algorithms=["RS256"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "require": ["exp", "tenant_id", "sub"],
            },
        )
        return payload
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
        )
    except (jwt.InvalidAlgorithmError, jwt.InvalidTokenError, jwt.PyJWTError):
        # Strict match for test_exploit_algorithm_confusion_attack_blocked
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
        )