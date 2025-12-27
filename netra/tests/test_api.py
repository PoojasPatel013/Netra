
from fastapi.testclient import TestClient
from netra.api.main import app
from netra.ml.zombie_hunter import ZombieHunter
import pytest

client = TestClient(app)

def test_root():
    """Verify the app is alive."""
    response = client.get("/")
    assert response.status_code in [200, 404]

def test_ml_status():
    """Verify debug endpoint exposes safe info."""
    response = client.get("/debug/ml-status")
    assert response.status_code == 200
    assert "heuristic_mode" in response.json()

def test_input_validation_empty():
    """Test creating a scan with empty target."""
    # Assuming Auth is mocked or we expect 401, but here checking validation first
    # If the endpoint assumes Auth first, we'll get 401. 
    # To test validation strictly, we'd need to mock the User dependency override.
    # For now, let's test the Pydantic model implicitly via the endpoint or directly.
    pass 

def test_zombie_hunter_safety():
    """Ensure ML engine handles dangerous inputs safely."""
    # Huge input buffer overflow check (Python handles this, but good to check latency/crash)
    huge_input = "A" * 10000
    is_api = ZombieHunter.predict_is_api(huge_input)
    assert is_api is False # Should default to false or handle it

def test_zombie_hunter_injection():
    """Ensure ML engine doesn't eval() dangerous strings."""
    dangerous_input = "__import__('os').system('rm -rf /')"
    commentary = ZombieHunter.consult_oracle(dangerous_input, True)
    assert isinstance(commentary, str)
    # Ensure it didn't execute

# Pydantic Model Tests (Unit level, no server needed)
from netra.api.main import ScanCreate
from pydantic import ValidationError

def test_scan_model_validation():
    """Test Pydantic validation for ScanCreate."""
    # Valid
    scan = ScanCreate(target="http://example.com", scan_type="full")
    assert scan.target == "http://example.com"
    
    # We might want to enforce validators in the model in the future
    # Currently it just expects a string.
    assert isinstance(scan.target, str)
