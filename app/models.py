"""Request/response schemas for the precheck API (documented in /docs)."""
from __future__ import annotations

from typing import Any, Optional

from pydantic import BaseModel, Field


class PolicySnapshot(BaseModel):
    """One routing snapshot: the parsed JSON output of the two `ip` commands."""

    rules: list[dict[str, Any]] = Field(
        ..., description="Parsed JSON array from `ip -j -4 rule show`"
    )
    routes: list[dict[str, Any]] = Field(
        ..., description="Parsed JSON array from `ip -j -4 route show table all`"
    )


_EXAMPLE_RULES = [
    {"priority": 0, "src": "all", "table": "local"},
    {"priority": 100, "src": "10.0.0.0/8", "table": "100"},
    {"priority": 32766, "src": "all", "table": "main"},
    {"priority": 32767, "src": "all", "table": "default"},
]

_EXAMPLE_ROUTES_BEFORE = [
    {"dst": "10.0.0.0/8", "dev": "eth0", "protocol": "kernel", "scope": "link",
     "src": "10.0.0.2", "table": "local"},
    {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0",
     "protocol": "static", "table": "main"},
    {"dst": "10.0.0.0/8", "dev": "eth0", "protocol": "kernel", "scope": "link",
     "src": "10.0.0.2", "table": "main"},
    {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1",
     "protocol": "static", "table": "100"},
]

_EXAMPLE_ROUTES_AFTER = [
    {"dst": "10.0.0.0/8", "dev": "eth0", "protocol": "kernel", "scope": "link",
     "src": "10.0.0.2", "table": "local"},
    {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0",
     "protocol": "static", "table": "main"},
    {"dst": "10.0.0.0/8", "dev": "eth0", "protocol": "kernel", "scope": "link",
     "src": "10.0.0.2", "table": "main"},
    {"dst": "default", "gateway": "203.0.113.1", "dev": "eth2",
     "protocol": "static", "table": "100"},
    {"dst": "198.51.100.128/25", "type": "blackhole", "table": "100"},
]


class PrecheckRequest(BaseModel):
    source_cidr: str = Field(
        ..., description="Source IPv4 CIDR, e.g. `10.0.0.0/8`; `0.0.0.0/0` is allowed"
    )
    destination_cidr: str = Field(
        ..., description="Destination IPv4 CIDR; `0.0.0.0/0` is allowed"
    )
    before: PolicySnapshot
    after: PolicySnapshot

    model_config = {
        "json_schema_extra": {
            "examples": [
                {
                    "source_cidr": "10.0.0.0/8",
                    "destination_cidr": "198.51.100.0/24",
                    "before": {
                        "rules": _EXAMPLE_RULES,
                        "routes": _EXAMPLE_ROUTES_BEFORE,
                    },
                    "after": {
                        "rules": _EXAMPLE_RULES,
                        "routes": _EXAMPLE_ROUTES_AFTER,
                    },
                }
            ]
        }
    }


class RouteResult(BaseModel):
    """One forwarding result: unicast (dev+nexthop), blackhole, or no_route."""

    type: str = Field(..., description="'unicast', 'blackhole' or 'no_route'")
    dev: Optional[str] = Field(None, description="Egress interface (unicast only)")
    gateway: Optional[str] = Field(None, description="Next hop, null for on-link (unicast only)")


class ExamplePair(BaseModel):
    source: str
    destination: str


class ChangeGroup(BaseModel):
    before: RouteResult
    after: RouteResult
    count: str = Field(..., description="Number of address pairs, decimal string")
    example: ExamplePair = Field(..., description="One address pair from this group")
    basis_before: dict[str, Any] = Field(
        ..., description="Rule/table/prefix that produced the 'before' result"
    )
    basis_after: dict[str, Any] = Field(
        ..., description="Rule/table/prefix that produced the 'after' result"
    )


class Summary(BaseModel):
    source_cidr: str
    destination_cidr: str
    total_pairs: str
    changed_pairs: str
    unchanged_pairs: str
    group_count: int


class PrecheckResponse(BaseModel):
    summary: Summary
    groups: list[ChangeGroup] = Field(
        ..., description="Only address pairs whose forwarding result changes"
    )
