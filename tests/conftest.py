"""Test configuration and shared fixtures."""

import pytest
import tempfile
from pathlib import Path


@pytest.fixture
def tmp_scenario_dir():
    """Create a temporary directory for test scenarios."""
    with tempfile.TemporaryDirectory() as tmpdir:
        yield Path(tmpdir)


@pytest.fixture
def sample_scenario_content():
    """Sample scenario file content with magical comments."""
    return """
(* Simple test scenario *)
new key: bitstring.

(*** Rainbow table attack [100 time]
attacker(key).
***)

(*** Intruder at database [10 hack]
attacker(database_access).
***)

query attacker(key).
"""


@pytest.fixture
def sample_scenario_file(tmp_scenario_dir, sample_scenario_content):
    """Create a sample scenario file."""
    scenario_path = tmp_scenario_dir / "test_scenario.pv"
    scenario_path.write_text(sample_scenario_content)
    return scenario_path
