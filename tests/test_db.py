import pytest
from sqlalchemy import text
from src.db.session import engine

@pytest.mark.anyio
async def test_database_connection():
    async with engine.connect() as connection:
        result = await connection.execute(text("SELECT 1;"))
        assert result.scalar() == 1