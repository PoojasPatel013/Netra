import pytest
from unittest.mock import MagicMock, patch
from netra.ml.zombie_hunter import ZombieHunter


def test_heuristic_basic():
    # Test obvious API patterns
    assert ZombieHunter.predict_is_api("/api/v1/user") == True
    assert ZombieHunter.predict_is_api("/graphql") == True
    assert ZombieHunter.predict_is_api("/internal/admin") == True


def test_heuristic_negative():
    # Test non-API paths
    assert ZombieHunter.predict_is_api("/index.html") == False
    assert ZombieHunter.predict_is_api("/css/style.css") == False
    assert ZombieHunter.predict_is_api("not_a_path") == False


def test_oracle_safe():
    # Test AI commentary for safe items
    comment = ZombieHunter.consult_oracle("/image.png", False)
    assert "0%" in comment or "Clean" in comment or "Boring" in comment


def test_oracle_shadow():
    # Test AI commentary for shadow hits
    comment = ZombieHunter.consult_oracle("/secret/admin", True)
    assert len(comment) > 10
    # Should be sarcastic
