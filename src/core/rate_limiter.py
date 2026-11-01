import time
from fastapi import HTTPException, status
from src.core.redis import get_redis_client

# Sliding Window Counter with Self-Healing TTL
# KEYS[1]: rate:{tenant_id}:{curr_bucket}
# KEYS[2]: rate:{tenant_id}:{prev_bucket}
# ARGV[1]: limit (int)
# ARGV[2]: window_seconds (int)
# ARGV[3]: elapsed_in_window (int)
LUA_SLIDING_WINDOW_RATE_LIMIT = """
local curr_key = KEYS[1]
local prev_key = KEYS[2]
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])
local elapsed = tonumber(ARGV[3])

local curr_count = tonumber(redis.call('GET', curr_key) or '0')
local prev_count = tonumber(redis.call('GET', prev_key) or '0')

-- Weighted sliding window approximation:
local weight = (window - elapsed) / window
local estimated_count = math.floor(prev_count * weight + curr_count)

if estimated_count >= limit then
    local ttl = redis.call('TTL', curr_key)
    if ttl <= 0 then
        ttl = window - elapsed
        if ttl <= 0 then ttl = 1 end
        redis.call('EXPIRE', curr_key, window * 2)
    end
    return {0, estimated_count, ttl}
end

local new_curr = redis.call('INCR', curr_key)
local ttl = redis.call('TTL', curr_key)
if new_curr == 1 or ttl == -1 then
    redis.call('EXPIRE', curr_key, window * 2)
    ttl = window * 2
end

return {1, estimated_count + 1, window - elapsed}
"""

class RateLimiter:
    def __init__(self, requests_per_minute: int = 5):
        self.limit = requests_per_minute
        self.window_seconds = 60

    async def check(self, tenant_id: str) -> None:
        client = get_redis_client()
        now = time.time()
        curr_bucket = int(now // self.window_seconds)
        prev_bucket = curr_bucket - 1
        elapsed = int(now % self.window_seconds)

        curr_key = f"rate:{tenant_id}:{curr_bucket}"
        prev_key = f"rate:{tenant_id}:{prev_bucket}"

        # Register script against current event loop's active client
        script = client.register_script(LUA_SLIDING_WINDOW_RATE_LIMIT)
        result = await script(
            keys=[curr_key, prev_key],
            args=[self.limit, self.window_seconds, elapsed]
        )

        allowed, count, ttl = result[0], result[1], result[2]

        if allowed == 0:
            retry_after = ttl if ttl > 0 else 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Too many requests.",
                headers={"Retry-After": str(retry_after)}
            )