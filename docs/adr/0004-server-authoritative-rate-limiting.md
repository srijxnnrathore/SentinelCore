# ADR 0004: Server-Authoritative Sliding-Window Rate Limiting

## Status
Accepted

## Context
Multi-tenant architectures require strict rate limiting to prevent noisy-neighbor capacity starvation and denial-of-service attacks. Naive rate limiting implementations present three severe production vulnerabilities:
1. **$2N$ Boundary-Burst Attacks:** Fixed-window counters (e.g. `INCR key` with fixed TTL) allow clients to fire $N$ requests at the tail of window $T_1$ and another $N$ requests at the head of window $T_2$, permitting $2N$ requests within a sub-second interval.
2. **NTP Clock Drift Across Containers:** In distributed container clusters, application nodes experience clock skew relative to one another. Using client-side timestamps (`time.time()`) allows attackers to manipulate timestamps or bypass limits due to server time divergence.
3. **Cluster Incompatibility & Memory Leaks:** Multi-key operations without hash tags cause Redis Cluster `CROSSSLOT` errors when keys hash to different shards. Incomplete key expiration logic creates orphan Redis memory leaks.

## Decision
We implement a single-key atomic sliding-window rate limiter powered by Redis 7 Lua scripting in [`src/core/rate_limiter.py`](../../src/core/rate_limiter.py):

1. **Redis Server Clock Authority:**
   The Lua script uses `redis.call('TIME')` rather than client-provided timestamps. The Redis cluster master clock is the single authoritative source of time across all application containers.

2. **Hash-Tagged Keys:**
   Rate limit keys use Redis hash-tag notation: `rate:{{{tenant_id}}}`. This guarantees that all hash fields for a tenant map to a single Redis hash slot, preventing `CROSSSLOT Keys in request don't hash to the same slot` exceptions.

3. **Atomic Lua Sliding-Window Estimation:**
   The algorithm stores window counters in a Redis Hash (`w_curr`, `c_curr`, `c_prev`) and calculates the weighted request rate using integer math:
   ```lua
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
   ```

4. **Self-Healing TTL & Cached Lua Scripts:**
   The script calculates a rolling `EXPIRE` of $2 \times \text{window}$ on every update, guaranteeing orphan keys are pruned. In Python, `client.register_script()` caches the script SHA1 digest so invocations execute as fast `EVALSHA` commands.

## Rationale & Consequences
- **Smooth Backpressure:** Eliminates $2N$ boundary-burst spikes by continuously weighting requests across the boundary of the previous and current window.
- **Clock Drift Immunity:** All container nodes synchronize against the authoritative Redis master clock.
- **Cluster & Bounded Memory Safety:** Hash-tag slot pinning ensures 100% compatibility with Redis Cluster, while atomic TTL refresh prevents memory leaks.

