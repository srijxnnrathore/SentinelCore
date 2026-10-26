import asyncio
from typing import Optional
from redis.asyncio import Redis
from src.core.config import settings

REDIS_URL = settings.REDIS_URL

_redis_client: Optional[Redis] = None
_client_loop: Optional[asyncio.AbstractEventLoop] = None

def get_redis_client() -> Redis:
    global _redis_client, _client_loop
    current_loop = asyncio.get_running_loop()
    if _redis_client is None or _client_loop != current_loop:
        _redis_client = Redis.from_url(REDIS_URL, encoding="utf-8", decode_responses=True)
        _client_loop = current_loop
    return _redis_client