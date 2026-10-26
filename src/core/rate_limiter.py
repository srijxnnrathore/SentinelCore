import time
from fastapi import HTTPException, status
from src.core.redis import get_redis_client

LUA_RATE_LIMIT = """
local current = redis.call('INCR', KEYS[1])
if current == 1 then
    redis.call('EXPIRE', KEYS[1], ARGV[1])
end
return current
"""

class RateLimiter:
    def __init__(self, requests_per_minute: int = 5):
        self.limit = requests_per_minute
        self.window_seconds = 60

    async def check(self, tenant_id: str) -> None:
        client = get_redis_client()
        current_minute = int(time.time() // self.window_seconds)
        key = f"rate:{tenant_id}:{current_minute}"

        # Register and execute the script against the current event loop's client
        script = client.register_script(LUA_RATE_LIMIT)
        count = await script(keys=[key], args=[self.window_seconds])

        if count > self.limit:
            ttl = await client.ttl(key)
            retry_after = ttl if ttl > 0 else 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Too many requests.",
                headers={"Retry-After": str(retry_after)}
            )