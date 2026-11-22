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


# ---------------------------------------------------------------------------
# POST /audit-unused
# ---------------------------------------------------------------------------

def audit_payload():
    rules = [
        {"priority": 0, "src": "all", "table": "local"},
        {"priority": 100, "src": "10.0.0.0/8", "table": "100"},
        {"priority": 200, "src": "10.0.0.0/8", "table": "100"},
        {"priority": 32766, "src": "all", "table": "main"},
    ]
    routes = [
        {"dst": "10.0.0.0/8", "dev": "lo", "table": "local"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
    ]
    return {
        "source_cidr": "10.0.0.0/8",
        "destination_cidr": "192.0.2.0/24",
        "rules": rules,
        "routes": routes,
    }


def test_audit_unused_happy_path():
    resp = client.post("/audit-unused", json=audit_payload())
    assert resp.status_code == 200, resp.text
    body = resp.json()

    assert [x["index"] for x in body["rules"]] == [0, 1, 2, 3]
    assert [x["index"] for x in body["routes"]] == [0, 1, 2]
    assert body["summary"]["rules_total"] == 4
    assert body["summary"]["routes_total"] == 3

    by_rule = {x["index"]: x for x in body["rules"]}
    by_route = {x["index"]: x for x in body["routes"]}

    # local rule/route stay in the response but are never called safe
    assert by_rule[0]["cleanable"] is False
    assert by_rule[0]["reason"] == "local_table_excluded"
    assert by_route[0]["reason"] == "local_table_excluded"

    # rule 1 is duplicated by rule 2 behind it -> cleanable; rule 2 shadowed
    assert by_rule[1]["cleanable"] is True
    assert by_rule[1]["reason"] == "cleanable"
    assert by_rule[1]["evidence"]["changed_pairs_after_removal"] == "0"
    assert by_rule[2]["cleanable"] is False
    assert by_rule[2]["reason"] == "not_referenced_in_scope"

    # main rule is shadowed by table 100 for the whole queried range
    assert by_rule[3]["reason"] == "not_referenced_in_scope"

    # table 100 default carries all traffic; main default is shadowed
    assert by_route[1]["reason"] == "forwarding_changes"
    assert by_route[1]["evidence"]["first_change"]["after_removal"]["dev"] == "eth0"
    assert by_route[2]["reason"] == "not_referenced_in_scope"

    assert body["summary"]["rules_cleanable"] == 1
    assert body["summary"]["routes_cleanable"] == 0


def test_audit_unused_throw_blackhole_and_nested_prefixes():
    payload = {
        "source_cidr": "10.0.0.1/32",
        "destination_cidr": "192.0.2.0/24",
        "rules": [
            {"priority": 100, "src": "all", "table": "100"},
            {"priority": 200, "src": "all", "table": "main"},
        ],
        "routes": [
            {"dst": "192.0.2.128/25", "type": "blackhole", "table": "100"},
            {"dst": "192.0.2.0/24", "type": "throw", "table": "100"},
            {"dst": "192.0.2.0/25", "gateway": "203.0.113.1", "dev": "eth2",
             "table": "main"},
            {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
        ],
    }
    resp = client.post("/audit-unused", json=payload)
    assert resp.status_code == 200, resp.text
    body = resp.json()
    by_route = {x["index"]: x for x in body["routes"]}

    # blackhole actually drops the upper half: load-bearing
    assert by_route[0]["reason"] == "forwarding_changes"
    assert by_route[0]["evidence"]["first_change"]["before_removal"]["type"] == "blackhole"

    # the throw IS consulted (LPM of table 100 for the lower half); with or
    # without it the lower half lands on main's eth2 /25 -> cleanable
    throw = by_route[1]
    assert throw["cleanable"] is True and throw["reason"] == "cleanable"
    assert throw["evidence"]["changed_pairs_after_removal"] == "0"
    assert int(throw["evidence"]["matched_pairs"]) == 128

    # main's /25 carries the lower half after the throw falls through:
    # load-bearing; only main's default stays fully shadowed
    assert by_route[2]["reason"] == "forwarding_changes"
    assert int(by_route[2]["evidence"]["matched_pairs"]) == 128
    assert by_route[3]["reason"] == "not_referenced_in_scope"


def test_audit_unused_throw_masking_a_route_is_load_bearing():
    payload = {
        "source_cidr": "10.0.0.1/32",
        "destination_cidr": "192.0.2.0/24",
        "rules": [
            {"priority": 100, "src": "all", "table": "100"},
            {"priority": 200, "src": "all", "table": "main"},
        ],
        "routes": [
            {"dst": "192.0.2.0/24", "type": "throw", "table": "100"},
            {"dst": "default", "gateway": "198.51.100.9", "dev": "eth9", "table": "100"},
            {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
        ],
    }
    resp = client.post("/audit-unused", json=payload)
    body = resp.json()
    by_route = {x["index"]: x for x in body["routes"]}
    # removing the throw exposes table 100's own default (eth9): not cleanable
    throw = by_route[0]
    assert throw["reason"] == "forwarding_changes" and throw["cleanable"] is False
    change = throw["evidence"]["first_change"]
    assert change["before_removal"]["dev"] == "eth0"
    assert change["after_removal"]["dev"] == "eth9"
    # table 100's default is shadowed by the throw inside the queried range
    assert by_route[1]["reason"] == "not_referenced_in_scope"


def test_audit_unused_unsupported_input_returns_400():
    payload = audit_payload()
    payload["routes"].append(
        {"dst": "203.0.113.0/24", "type": "prohibit", "table": "main"}
    )
    resp = client.post("/audit-unused", json=payload)
    assert resp.status_code == 400
    assert "prohibit" in resp.json()["detail"]


def test_audit_unused_invalid_cidr_returns_400():
    payload = audit_payload()
    payload["destination_cidr"] = "192.0.2.0/33"
    resp = client.post("/audit-unused", json=payload)
    assert resp.status_code == 400
    assert "destination_cidr" in resp.json()["detail"]


def test_audit_unused_schema_violation_returns_422():
    resp = client.post("/audit-unused", json={"source_cidr": "10.0.0.0/8"})
    assert resp.status_code == 422


def test_audit_unused_documented_in_openapi():
    spec = client.get("/openapi.json").json()
    assert "/audit-unused" in spec["paths"]
    assert "AuditResponse" in spec["components"]["schemas"]
