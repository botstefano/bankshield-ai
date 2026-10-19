import os
import tempfile

_tmp = tempfile.mkdtemp()
os.environ["DATABASE_URL"] = f"sqlite:///{_tmp}/test.db"
os.environ["MODEL_DIR"] = os.path.join(_tmp, "model")
os.environ["ADMIN_EMAIL"] = "admin@test.local"
os.environ["ADMIN_PASSWORD"] = "Admin#Test-2026"
os.environ["SEED_DEMO"] = "true"
os.environ["STATIC_DIR"] = os.path.join(_tmp, "nostatic")

import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.fixture(scope="session")
def client():
    with TestClient(app) as c:
        yield c


def _login(client, email, pw):
    r = client.post("/api/v1/auth/login", json={"email": email, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


@pytest.fixture(scope="session")
def admin(client):
    return _login(client, "admin@test.local", "Admin#Test-2026")


@pytest.fixture(scope="session")
def operator(client):
    return _login(client, "operator@bankshield.local", "Demo#2026-Cambiar")


@pytest.fixture(scope="session")
def analyst(client):
    return _login(client, "analyst@bankshield.local", "Demo#2026-Cambiar")
