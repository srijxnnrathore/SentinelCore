import pytest
from httpx import ASGITransport, AsyncClient
from src.main import app

@pytest.mark.anyio
async def test_health_live():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/health/live")
        assert res.status_code == 200
        assert res.json() == {"status": "alive"}

@pytest.mark.anyio
async def test_health_ready_live_dependencies():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        res = await client.get("/health/ready")
        assert res.status_code == 200
        data = res.json()
        assert data["status"] == "ready"
        assert data["subsystems"]["database"] == "ok"
        assert data["subsystems"]["redis"] == "ok"

