import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "services" / "api-gateway"))

from faro_api.main import create_app  # noqa: E402


@pytest.fixture
def client(tmp_path):
    with TestClient(create_app(db_path=str(tmp_path / "test.sqlite3"), api_key="test-secret")) as c:
        yield c


@pytest.fixture
def auth():
    return {"X-Faro-Api-Key": "test-secret"}
