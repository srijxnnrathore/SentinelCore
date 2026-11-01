import re
import time
from typing import Optional
from fastapi import APIRouter, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response as StarletteResponse

# 1. Prometheus Metrics Primitives
HTTP_REQUESTS_TOTAL = Counter(
    "sentinel_http_requests_total",
    "Total HTTP requests",
    ["method", "endpoint", "status_class"],
)

RATE_LIMIT_DROPS_TOTAL = Counter(
    "sentinel_rate_limit_drops_total",
    "Total rate limit drops",
    ["endpoint"],
)

THREAT_CIRCUIT_TRIPS_TOTAL = Counter(
    "sentinel_threat_circuit_trips_total",
    "Total quarantine trips",
    ["event_type"],
)

REQUEST_DURATION_SECONDS = Histogram(
    "sentinel_request_duration_seconds",
    "HTTP request latency in seconds",
    ["method", "endpoint", "status_class"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5],
)

# 2. Path parameter normalization
UUID_REGEX = re.compile(
    r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
)

def normalize_endpoint(path: str) -> str:
    """
    Replaces dynamic UUID path parameters with '{id}' to protect Prometheus
    TSDB against cardinality explosions.
    """
    if not path:
        return "/"
    # Replace UUID segments with {id}
    normalized = UUID_REGEX.sub("{id}", path)
    # Also normalize parameterized placeholders like {document_id} to {id}
    normalized = re.sub(r"\{[a-zA-Z0-9_]+_id\}", "{id}", normalized)
    return normalized

def get_status_class(status_code: int) -> str:
    """Categorizes HTTP status codes by class (2xx, 3xx, 4xx, 5xx)."""
    if 200 <= status_code < 300:
        return "2xx"
    elif 300 <= status_code < 400:
        return "3xx"
    elif 400 <= status_code < 500:
        return "4xx"
    elif 500 <= status_code < 600:
        return "5xx"
    return "unknown"

# 3. ASGI/FastAPI Metrics Middleware
class PrometheusMetricsMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next) -> StarletteResponse:
        method = request.method
        start_time = time.perf_counter()
        status_code = 500

        try:
            response = await call_next(request)
            status_code = response.status_code
            return response
        except Exception:
            status_code = 500
            raise
        finally:
            duration = time.perf_counter() - start_time
            endpoint = normalize_endpoint(request.url.path)
            status_class = get_status_class(status_code)

            HTTP_REQUESTS_TOTAL.labels(
                method=method,
                endpoint=endpoint,
                status_class=status_class,
            ).inc()

            REQUEST_DURATION_SECONDS.labels(
                method=method,
                endpoint=endpoint,
                status_class=status_class,
            ).observe(duration)

# 4. Metrics Router
metrics_router = APIRouter(tags=["Metrics"])

@metrics_router.get("/metrics")
async def get_metrics():
    return Response(
        content=generate_latest(),
        media_type=CONTENT_TYPE_LATEST,
    )
