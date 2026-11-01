import asyncio
import logging
from typing import Optional
from redis.asyncio import Redis
from redis.asyncio.connection import BlockingConnectionPool
from redis.asyncio.retry import Retry
from redis.backoff import ExponentialBackoff
from redis.exceptions import BusyLoadingError, ConnectionError, TimeoutError
from src.core.config import settings

logger = logging.getLogger("sentinelcore.redis")

REDIS_URL = settings.REDIS_URL

_redis_pool: Optional[BlockingConnectionPool] = None
_redis_client: Optional[Redis] = None
_client_loop: Optional[asyncio.AbstractEventLoop] = None

def get_redis_client() -> Redis:
    global _redis_client, _redis_pool, _client_loop
    current_loop = asyncio.get_running_loop()
    if _redis_client is None or _client_loop != current_loop:
        _redis_pool = BlockingConnectionPool.from_url(
            REDIS_URL,
            max_connections=20,
            timeout=5.0,
            health_check_interval=30,
            socket_timeout=3.0,
            socket_connect_timeout=3.0,
            retry=Retry(ExponentialBackoff(cap=2, base=0.1), retries=3),
            retry_on_error=[ConnectionError, TimeoutError, BusyLoadingError],
            encoding="utf-8",
            decode_responses=True,
        )
        _redis_client = Redis(connection_pool=_redis_pool)
        _client_loop = current_loop
    return _redis_client

async def close_redis_client() -> None:
    global _redis_client, _redis_pool, _client_loop
    if _redis_client is not None:
        try:
            await _redis_client.aclose()
        except Exception as exc:
            logger.debug("Suppressed error closing Redis client during teardown: %s", exc)
        _redis_client = None

    if _redis_pool is not None:
        try:
            await _redis_pool.aclose()
        except Exception as exc:
            logger.debug("Suppressed error closing Redis pool during teardown: %s", exc)
        _redis_pool = None

    _client_loop = None

def reset_redis_client() -> None:
    global _redis_client, _redis_pool, _client_loop
    _redis_client = None
    _redis_pool = None
    _client_loop = None
