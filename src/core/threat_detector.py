import time
from fastapi import HTTPException, status
from src.core.redis import get_redis_client

# Atomic Lua: increment violation count, apply sliding window, and conditionally jail
LUA_RECORD_VIOLATION = """
local violation_key = KEYS[1]
local jail_key = KEYS[2]
local window = tonumber(ARGV[1])
local max_violations = tonumber(ARGV[2])
local jail_duration = tonumber(ARGV[3])

local count = redis.call('INCR', violation_key)
if count == 1 then
    redis.call('EXPIRE', violation_key, window)
end

if count >= max_violations then
    redis.call('SET', jail_key, 'QUARANTINED', 'EX', jail_duration)
    redis.call('DEL', violation_key)
    return 1
end

return 0
"""

class ThreatDetector:
    def __init__(
        self,
        max_violations: int = 3,
        window_seconds: int = 30,
        jail_duration_seconds: int = 300
    ):
        self.max_violations = max_violations
        self.window_seconds = window_seconds
        self.jail_duration_seconds = jail_duration_seconds

    async def check_quarantine(self, tenant_id: str) -> None:
        """
        Fast-path check: returns 403 immediately if the tenant is quarantined.
        """
        client = get_redis_client()
        jail_key = f"jail:{tenant_id}"
        is_jailed = await client.get(jail_key)
        if is_jailed:
            ttl = await client.ttl(jail_key)
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security violation: Account temporarily quarantined due to suspicious probing activity.",
                headers={"Retry-After": str(ttl if ttl > 0 else 60)}
            )

    async def record_violation(self, tenant_id: str) -> None:
        """
        Records an authorization violation. Automatically trips the circuit breaker
        if violations exceed the threshold within the sliding window.
        """
        client = get_redis_client()
        violation_key = f"violations:{tenant_id}"
        jail_key = f"jail:{tenant_id}"

        script = client.register_script(LUA_RECORD_VIOLATION)
        await script(
            keys=[violation_key, jail_key],
            args=[self.window_seconds, self.max_violations, self.jail_duration_seconds]
        )

threat_detector = ThreatDetector()