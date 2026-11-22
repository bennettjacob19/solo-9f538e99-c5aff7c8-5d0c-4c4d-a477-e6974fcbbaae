"""API-level tests using FastAPI's TestClient."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def sample_payload():
    rules = [
        {"priority": 0, "src": "all", "table": "local"},
        {"priority": 100, "src": "10.0.0.0/8", "table": "100"},
        {"priority": 32766, "src": "all", "table": "main"},
    ]
    before_routes = [
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
    ]
    after_routes = [
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
        {"dst": "default", "gateway": "203.0.113.1", "dev": "eth2", "table": "100"},
        {"dst": "198.51.100.128/25", "type": "blackhole", "table": "100"},
    ]
    return {
        "source_cidr": "10.0.0.0/8",
        "destination_cidr": "198.51.100.0/24",
        "before": {"rules": rules, "routes": before_routes},
        "after": {"rules": rules, "routes": after_routes},
    }


def test_healthz():
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.json() == {"status": "ok"}


def test_root_redirects_to_docs():
    resp = client.get("/", follow_redirects=False)
    assert resp.status_code in (302, 307)
    assert resp.headers["location"] == "/docs"


def test_docs_served():
    assert client.get("/docs").status_code == 200
    assert client.get("/openapi.json").status_code == 200


def test_precheck_happy_path():
    resp = client.post("/precheck", json=sample_payload())
    assert resp.status_code == 200, resp.text
    body = resp.json()
    assert body["summary"]["total_pairs"] == str(2**24 * 2**8)
    assert body["summary"]["changed_pairs"] == str(2 * 2**24 * 2**7)
    assert body["summary"]["group_count"] == 2

    by_after = {g["after"]["type"]: g for g in body["groups"]}
    moved = by_after["unicast"]
    assert moved["before"] == {"type": "unicast", "dev": "eth1", "gateway": "198.51.100.1"}
    assert moved["after"] == {"type": "unicast", "dev": "eth2", "gateway": "203.0.113.1"}
    assert moved["count"] == str(2**24 * 128)
    assert moved["basis_before"]["table"] == "100"
    assert moved["basis_after"]["table"] == "100"

    dropped = by_after["blackhole"]
    assert dropped["count"] == str(2**24 * 128)
    assert dropped["example"]["destination"] == "198.51.100.128"
    assert dropped["basis_after"]["route_prefix"] == "198.51.100.128/25"


def test_precheck_unsupported_input_returns_400():
    payload = sample_payload()
    payload["after"]["routes"].append(
        {"dst": "203.0.113.0/24", "type": "prohibit", "table": "main"}
    )
    resp = client.post("/precheck", json=payload)
    assert resp.status_code == 400
    assert "prohibit" in resp.json()["detail"]


def test_precheck_invalid_cidr_returns_400():
    payload = sample_payload()
    payload["source_cidr"] = "10.0.0.0/33"
    resp = client.post("/precheck", json=payload)
    assert resp.status_code == 400
    assert "source_cidr" in resp.json()["detail"]


def test_precheck_schema_violation_returns_422():
    resp = client.post("/precheck", json={"source_cidr": "10.0.0.0/8"})
    assert resp.status_code == 422
