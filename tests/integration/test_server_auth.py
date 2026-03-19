from __future__ import annotations

import pytest
from fastapi.testclient import TestClient


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("OPENSCRIPT_API_KEY", "test-api-key")
    monkeypatch.setenv(
        "DATABASE_URL", "postgresql+asyncpg://openscript:openscript@localhost:5432/openscript"
    )
    from server.app import app

    return TestClient(app, raise_server_exceptions=False)


def test_health_no_auth_required(client):
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_events_401_without_key(client):
    resp = client.get("/events/any-session")
    assert resp.status_code == 401


def test_events_401_with_wrong_key(client):
    resp = client.get("/events/any-session", headers={"X-API-KEY": "wrong-key"})
    assert resp.status_code == 401


def test_session_graph_401_without_key(client):
    resp = client.get("/sessions/any-session/graph")
    assert resp.status_code == 401
