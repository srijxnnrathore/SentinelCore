from fastapi import HTTPException, status
from src.core.redis import get_redis_client

# Single-Key Atomic Sliding Window with Redis Engine Clock Authority
# KEYS[1]: rate:{tenant_id}  (Hash-tagged to single slot)
# ARGV[1]: limit (int)
# ARGV[2]: window_seconds (int)
LUA_SLIDING_WINDOW_RATE_LIMIT = """
local limit = tonumber(ARGV[1])
local window = tonumber(ARGV[2])

-- Authoritative time from Redis server clock
local rtime = redis.call('TIME')
local now_sec = tonumber(rtime[1])
local curr_window = math.floor(now_sec / window)
local elapsed = now_sec % window

local weight = (window - elapsed) / window
local data = redis.call('HMGET', KEYS[1], 'w_curr', 'c_curr', 'c_prev')

local stored_w = tonumber(data[1])
local c_curr = tonumber(data[2]) or 0
local c_prev = tonumber(data[3]) or 0

if stored_w == nil then
    c_curr = 0
    c_prev = 0
elseif stored_w == curr_window - 1 then
    c_prev = c_curr
    c_curr = 0
elseif stored_w < curr_window - 1 then
    c_prev = 0
    c_curr = 0
end

local estimated = math.floor(c_prev * weight + c_curr)

if estimated >= limit then
    local pttl = redis.call('PTTL', KEYS[1])
    if pttl < 0 then
        redis.call('EXPIRE', KEYS[1], window * 2)
    end
    return {0, estimated, window - elapsed}
end

c_curr = c_curr + 1
redis.call('HSET', KEYS[1], 'w_curr', curr_window, 'c_curr', c_curr, 'c_prev', c_prev)
redis.call('EXPIRE', KEYS[1], window * 2)
return {1, estimated + 1, 0}
"""

class RateLimiter:
    def __init__(self, requests_per_minute: int = 5):
        self.limit = requests_per_minute
        self.window_seconds = 60

    async def check(self, tenant_id: str) -> None:
        client = get_redis_client()
        # Hash-tag key format ensures compatibility with single-node and cluster topologies
        key = f"rate:{{{tenant_id}}}"

        script = client.register_script(LUA_SLIDING_WINDOW_RATE_LIMIT)
        result = await script(
            keys=[key],
            args=[self.limit, self.window_seconds]
        )

        allowed, count, ttl = result[0], result[1], result[2]

        if allowed == 0:
            retry_after = ttl if ttl > 0 else 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="Rate limit exceeded. Too many requests.",
                headers={"Retry-After": str(retry_after)}
            )