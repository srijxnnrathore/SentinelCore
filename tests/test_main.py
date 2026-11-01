import pytest
from httpx import ASGITransport, AsyncClient
from src.main import app

@pytest.mark.anyio
async def test_health_check_is_alive():
    async with AsyncClient(transport=ASGITransport(app=app), base_url="http://test") as client:
        response = await client.get("/health/live")
        assert response.status_code == 200
        assert response.json() == {"status": "alive"}
