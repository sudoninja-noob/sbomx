import sys
from pathlib import Path

import pytest

# Ensure the package is importable when running from the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixtures_dir():
    return FIXTURES
