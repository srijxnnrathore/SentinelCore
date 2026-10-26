from fastapi.testclient import TestClient
from src.main import app

# Create a test client that can talk to our FastAPI app without running a real server
client = TestClient(app)

def test_health_check_is_alive():
    # 1. Send a GET request to our endpoint
    response = client.get("/health/live")
    
    # 2. Assert (verify) the HTTP status code is 200 (Success)
    assert response.status_code == 200
    
    # 3. Assert the JSON response matches exactly what we expect
    assert response.json() == {"status": "alive"}