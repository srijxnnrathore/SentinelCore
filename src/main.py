from contextlib import asynccontextmanager
from fastapi import FastAPI
from src.api.documents import router as documents_router
from src.core.event_queue import security_event_queue

@asynccontextmanager
async def lifespan(app: FastAPI):
    await security_event_queue.start()
    yield
    await security_event_queue.stop()

app = FastAPI(
    title="SentinelCore",
    version="1.0.0",
    lifespan=lifespan,
)

app.include_router(documents_router, prefix="/documents", tags=["Documents"])

@app.get("/health")
@app.get("/health/live")
async def health():
    return {"status": "alive"}