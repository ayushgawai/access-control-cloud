import os
import tempfile

# Must be set before app modules import (engine and detector read env at import time).
os.environ.setdefault("DATABASE_URL", f"sqlite:///{tempfile.mkdtemp()}/test.db")
os.environ["TAILGATE_MODEL"] = "stub"
os.environ["SEED_DEMO"] = "1"

import pytest  # noqa: E402

# Seeded ids: org 1 "Demo Org", org 2 "Second Org"; users 1 Alice (admin), 2 Bob (operator),
# 3 Carol (viewer) in org 1, 4 Dave (admin) in org 2; doors 1 Lobby, 2 Server Room, 3 Loading Dock, 4 Roof Hatch.


def bearer(sub: str, org_id: int, role: str) -> dict:
    from app.auth import mint_access_token

    return {"Authorization": f"Bearer {mint_access_token(sub, org_id, role)}"}


@pytest.fixture(scope="session")
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c


@pytest.fixture
def alice():
    return bearer("user:1", 1, "admin")


@pytest.fixture
def bob():
    return bearer("user:2", 1, "operator")


@pytest.fixture
def carol():
    return bearer("user:3", 1, "viewer")


@pytest.fixture
def dave():
    return bearer("user:4", 2, "admin")
