from collections.abc import AsyncGenerator
from dataclasses import dataclass
from typing import Optional
from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession
from src.core.rate_limiter import RateLimiter
from src.core.security import decode_token
from src.core.threat_detector import threat_detector
from src.db.session import scoped_tenant_session

limiter = RateLimiter(requests_per_minute=5)

@dataclass
class AuthContext:
    tenant_id: str
    actor_id: str

async def get_auth_context(
    authorization: Optional[str] = Header(None, description="Bearer JWT token")
) -> AuthContext:
    if not authorization:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing authorization header",
        )

    if not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authorization header scheme",
        )

    token = authorization.split(" ")[1]
    claims = await decode_token(token)

    tenant_id = claims.get("tenant_id")
    actor_id = claims.get("sub")

    if not tenant_id or not actor_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token missing required claims",
        )

    # 1. Edge-tier threat jail check (drops quarantined tenants immediately)
    await threat_detector.check_quarantine(tenant_id)

    # 2. Sliding-window rate limit check
    await limiter.check(tenant_id)

    return AuthContext(tenant_id=tenant_id, actor_id=actor_id)

async def get_db(
    request: Request,
    auth: AuthContext = Depends(get_auth_context),
) -> AsyncGenerator[AsyncSession, None]:
    trace_id = None
    if request:
        trace_id = request.headers.get("traceparent") or request.headers.get("x-trace-id")
    async with scoped_tenant_session(auth.tenant_id, trace_id=trace_id) as session:
        yield session
