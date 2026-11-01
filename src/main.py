from contextlib import asynccontextmanager
from fastapi import FastAPI, status
from fastapi.responses import JSONResponse
from sqlalchemy import text
from src.api.documents import router as documents_router
from src.core.event_queue import security_event_queue
from src.core.metrics import PrometheusMetricsMiddleware, metrics_router
from src.core.redis import close_redis_client, get_redis_client
from src.db.session import engine

@asynccontextmanager
async def lifespan(app: FastAPI):
    await security_event_queue.start()
    yield
    await security_event_queue.stop(drain_timeout=5.0)
    await close_redis_client()

app = FastAPI(
    title="SentinelCore",
    version="1.0.0",
    lifespan=lifespan,
)

# 1. Register Prometheus Metrics Middleware
app.add_middleware(PrometheusMetricsMiddleware)

# 2. Mount Prometheus Metrics Router
app.include_router(metrics_router)

# 3. Mount Application Routers
app.include_router(documents_router, prefix="/documents", tags=["Documents"])

@app.get("/health")
@app.get("/health/live")
async def health_live():
    return {"status": "alive"}

@app.get("/health/ready")
async def health_ready():
    subsystems = {}
    is_ready = True

    # 1. PostgreSQL Probe
    try:
        async with engine.connect() as conn:
            await conn.execute(text("SELECT 1"))
        subsystems["database"] = "ok"
    except Exception as exc:
        is_ready = False
        subsystems["database"] = f"failed: {exc}"

    # 2. Redis Probe
    try:
        client = get_redis_client()
        await client.ping()
        subsystems["redis"] = "ok"
    except Exception as exc:
        is_ready = False
        subsystems["redis"] = f"failed: {exc}"

    if is_ready:
        return {"status": "ready", "subsystems": subsystems}
    else:
        return JSONResponse(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            content={"status": "degraded", "subsystems": subsystems},
        )
