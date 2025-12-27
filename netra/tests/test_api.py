
from fastapi.testclient import TestClient
from netra.api.main import app
import pytest

client = TestClient(app)

# We need to mock the DB dependency or use a test DB. 
# For this MVP test, we'll assume the client can hit the running app or mock the session.
# Since we are using an async DB, TestClient usage with async endpoints requires 'async_asgi_testclient' or similar, 
# or we use the standard client which works for sync, but for async def it might need the event loop.
# Standard TestClient actually handles async def via Starlette's implementation.

def test_root():
    response = client.get("/")
    # Should catch-all to index.html or 404 depending on static mount
    # Our app has a catch-all route mostly
    assert response.status_code in [200, 404]

def test_ml_status():
    response = client.get("/debug/ml-status")
    assert response.status_code == 200
    data = response.json()
    assert "heuristic_mode" in data

# Note: Integration tests requiring Auth/DB are skipped in this unit suite 
# to avoid complex mocking in this step. Use 'pytest-asyncio' for full integration.
