from fastapi import HTTPException, status, Depends
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from typing import AsyncGenerator
from dataclasses import dataclass
import uuid
import jwt
from sqlalchemy.ext.asyncio import AsyncSession
from src.db.session import scoped_tenant_session
from src.core.security import decode_access_token
from src.core.rate_limiter import RateLimiter
from src.core.threat_detector import threat_detector

security_scheme = HTTPBearer()
limiter = RateLimiter(requests_per_minute=5)

@dataclass
class AuthContext:
    tenant_id: uuid.UUID
    actor_id: str

async def get_auth_context(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme)
) -> AuthContext:
    token = credentials.credentials
    try:
        payload = await decode_access_token(token)
        raw_tenant_id = payload.get("tenant_id")
        actor_id = payload.get("sub", "anonymous")
        
        if not raw_tenant_id:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token missing tenant_id claim",
                headers={"WWW-Authenticate": "Bearer"},
            )
        tenant_uuid = uuid.UUID(raw_tenant_id)
        tenant_str = str(tenant_uuid)

        # 1. Threat Detector: Fast-path rejection for actively quarantined tenants
        await threat_detector.check_quarantine(tenant_str)

        # 2. Rate Limiting: Abuse and noisy-neighbor throttling
        await limiter.check(tenant_str)
        
        return AuthContext(tenant_id=tenant_uuid, actor_id=actor_id)
    except HTTPException:
        raise
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token has expired",
            headers={"WWW-Authenticate": "Bearer"},
        )
    except (jwt.PyJWTError, ValueError):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication token",
            headers={"WWW-Authenticate": "Bearer"},
        )

async def get_tenant_db(
    auth: AuthContext = Depends(get_auth_context)
) -> AsyncGenerator[AsyncSession, None]:
    async with scoped_tenant_session(str(auth.tenant_id)) as session:
        yield session