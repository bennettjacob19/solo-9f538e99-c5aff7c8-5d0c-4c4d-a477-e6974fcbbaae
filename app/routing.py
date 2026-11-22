"""Symbolic Linux IPv4 policy-routing engine for the dual-egress precheck API.

The module is pure stdlib so it can be unit-tested without FastAPI.

Model (everything outside this model is rejected with :class:`UnsupportedInput`):

* rules: lookup rules only, matched on ``src`` / ``dst`` selectors, consulted
  by ascending *distinct* priority.  The ``local`` table and rules pointing to
  it are skipped.
* routes: per table the prefixes are unique; longest-prefix match on the
  destination; supported types are single-path ``unicast`` (``dev`` plus
  optional ``gateway``), ``throw`` and ``blackhole``.
* lookup semantics: no matching route or a ``throw`` continues with the next
  rule; ``blackhole`` drops immediately; exhausting all rules yields
  ``no_route``.

The address space is never enumerated: source/destination CIDRs are split
symbolically into rectangles on which both snapshots have a constant result,
so the cost depends on the policy size, not on the number of addresses.
"""
from __future__ import annotations

import ipaddress
import json
from dataclasses import dataclass
from typing import Any, Optional, Union


class UnsupportedInput(ValueError):
    """The supplied snapshot or CIDR uses features outside the supported model."""


# ---------------------------------------------------------------------------
# prefixes and tables
# ---------------------------------------------------------------------------

def parse_prefix(value: Any, what: str) -> ipaddress.IPv4Network:
    """Parse an IPv4 CIDR ('all'/'default' mean 0.0.0.0/0, bare IPs mean /32)."""
    if not isinstance(value, str):
        raise UnsupportedInput(f"{what}: prefix must be a string, got {value!r}")
    text = value.strip()
    if text.lower() in ("all", "default"):
        return ipaddress.IPv4Network("0.0.0.0/0")
    if "/" not in text:
        text += "/32"
    try:
        return ipaddress.IPv4Network(text, strict=False)
    except ValueError as exc:
        raise UnsupportedInput(f"{what}: invalid IPv4 prefix {value!r} ({exc})") from exc


TABLE_NAME_TO_ID = {"unspec": 0, "local": 255, "main": 253, "default": 254}
LOCAL_TABLE_ID = 255
TableKey = Union[int, str]


def normalize_table(value: Any, what: str) -> TableKey:
    """Normalize a table reference so rules and routes compare consistently.

    Well-known names map to their ids; numeric strings map to ints; unknown
    (custom rt_tables) names are kept as strings and matched by name.
    """
    if isinstance(value, bool):
        raise UnsupportedInput(f"{what}: invalid table {value!r}")
    if isinstance(value, int):
        if 0 <= value <= 0xFFFFFFFF:
            return value
        raise UnsupportedInput(f"{what}: table id out of range: {value!r}")
    if isinstance(value, str):
        text = value.strip()
        if text in TABLE_NAME_TO_ID:
            return TABLE_NAME_TO_ID[text]
        if text.isdigit():
            num = int(text)
            if 0 <= num <= 0xFFFFFFFF:
                return num
            raise UnsupportedInput(f"{what}: table id out of range: {value!r}")
        if not text:
            raise UnsupportedInput(f"{what}: empty table name")
        return text
    raise UnsupportedInput(f"{what}: invalid table {value!r}")


# ---------------------------------------------------------------------------
# rules
# ---------------------------------------------------------------------------

RULE_ALLOWED_KEYS = {"priority", "src", "dst", "table", "action"}


@dataclass(frozen=True)
class Rule:
    priority: int
    src: ipaddress.IPv4Network
    dst: ipaddress.IPv4Network
    table: TableKey
    table_display: str


def parse_rules(raw: Any, label: str) -> list[Rule]:
    """Validate and normalize the JSON array from ``ip -j -4 rule show``."""
    if not isinstance(raw, list):
        raise UnsupportedInput(
            f"{label}: 'rules' must be the JSON array from `ip -j -4 rule show`"
        )
    rules: list[Rule] = []
    for idx, entry in enumerate(raw):
        what = f"{label} rule #{idx}"
        if not isinstance(entry, dict):
            raise UnsupportedInput(f"{what}: each rule must be a JSON object")
        extra = sorted(k for k in entry if k not in RULE_ALLOWED_KEYS)
        if extra:
            raise UnsupportedInput(
                f"{what}: unsupported attribute(s) {', '.join(extra)}; only "
                "'priority', 'src'/'dst' selectors and 'table' lookups are supported"
            )
        action = entry.get("action", "lookup")
        if action != "lookup":
            raise UnsupportedInput(
                f"{what}: unsupported rule action {action!r} "
                "(only table-lookup rules are supported)"
            )
        if "priority" not in entry:
            raise UnsupportedInput(f"{what}: missing 'priority'")
        priority = entry["priority"]
        if isinstance(priority, bool) or not isinstance(priority, int):
            if isinstance(priority, str) and priority.isdigit():
                priority = int(priority)
            else:
                raise UnsupportedInput(f"{what}: invalid priority {priority!r}")
        if "table" not in entry:
            raise UnsupportedInput(
                f"{what}: missing 'table' (only table-lookup rules are supported)"
            )
        table = normalize_table(entry["table"], what)
        if table == LOCAL_TABLE_ID:
            continue  # rules pointing to the local table are skipped
        src = parse_prefix(entry.get("src", "all"), f"{what} 'src'")
        dst = parse_prefix(entry.get("dst", "all"), f"{what} 'dst'")
        rules.append(Rule(priority, src, dst, table, str(entry["table"])))
    seen: set[int] = set()
    for rule in rules:
        if rule.priority in seen:
            raise UnsupportedInput(
                f"{label}: duplicate rule priority {rule.priority} "
                "(priorities must be distinct)"
            )
        seen.add(rule.priority)
    rules.sort(key=lambda r: r.priority)
    return rules


# ---------------------------------------------------------------------------
# routes
# ---------------------------------------------------------------------------

ROUTE_UNSUPPORTED_KEYS = {
    "nexthops",            # multipath routes
    "nhid",                # nexthop objects
    "via",                 # unexpected gateway encoding
    "encap", "encaptype", "mpls", "lwtstate",  # encapsulations
    "tos", "realms",       # extra selectors
}
ROUTE_SUPPORTED_TYPES = {"unicast", "throw", "blackhole"}


@dataclass(frozen=True)
class Route:
    prefix: ipaddress.IPv4Network
    rtype: str  # "unicast" | "throw" | "blackhole"
    dev: Optional[str]
    gateway: Optional[str]


def parse_routes(raw: Any, label: str) -> dict[TableKey, list[Route]]:
    """Validate and normalize the JSON array from ``ip -j -4 route show table all``."""
    if not isinstance(raw, list):
        raise UnsupportedInput(
            f"{label}: 'routes' must be the JSON array from "
            "`ip -j -4 route show table all`"
        )
    tables: dict[TableKey, list[Route]] = {}
    seen: set[tuple[TableKey, ipaddress.IPv4Network]] = set()
    for idx, entry in enumerate(raw):
        what = f"{label} route #{idx}"
        if not isinstance(entry, dict):
            raise UnsupportedInput(f"{what}: each route must be a JSON object")
        table = normalize_table(entry.get("table", "main"), what)
        if table == LOCAL_TABLE_ID:
            continue  # the local table is skipped entirely
        bad = sorted(k for k in entry if k in ROUTE_UNSUPPORTED_KEYS)
        if bad:
            raise UnsupportedInput(
                f"{what}: unsupported attribute(s) {', '.join(bad)}; multipath, "
                "nexthop objects, encapsulations and extra selectors are not supported"
            )
        rtype = entry.get("type", "unicast")
        if rtype not in ROUTE_SUPPORTED_TYPES:
            raise UnsupportedInput(
                f"{what}: unsupported route type {rtype!r} "
                "(only unicast, throw and blackhole are supported)"
            )
        if "dst" not in entry:
            raise UnsupportedInput(f"{what}: missing 'dst'")
        prefix = parse_prefix(entry["dst"], what)
        key = (table, prefix)
        if key in seen:
            raise UnsupportedInput(
                f"{label}: duplicate prefix {prefix} in table "
                f"{entry.get('table', 'main')!r} (prefixes must be unique per table)"
            )
        seen.add(key)
        dev = entry.get("dev")
        gateway = entry.get("gateway")
        if rtype == "unicast":
            if not isinstance(dev, str) or not dev.strip():
                raise UnsupportedInput(f"{what}: unicast route requires a non-empty 'dev'")
            if gateway is not None:
                if not isinstance(gateway, str):
                    raise UnsupportedInput(f"{what}: 'gateway' must be a string")
                try:
                    ipaddress.IPv4Address(gateway)
                except ValueError:
                    raise UnsupportedInput(f"{what}: invalid IPv4 gateway {gateway!r}")
        else:
            dev = None
            gateway = None
        tables.setdefault(table, []).append(Route(prefix, rtype, dev, gateway))
    return tables


# ---------------------------------------------------------------------------
# forwarding results
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Unicast:
    dev: str
    gateway: Optional[str]


@dataclass(frozen=True)
class Blackhole:
    pass


@dataclass(frozen=True)
class NoRoute:
    pass


BLACKHOLE = Blackhole()
NO_ROUTE = NoRoute()

Result = Union[Unicast, Blackhole, NoRoute]


def result_json(result: Result) -> dict:
    if isinstance(result, Unicast):
        return {"type": "unicast", "dev": result.dev, "gateway": result.gateway}
    if isinstance(result, Blackhole):
        return {"type": "blackhole"}
    return {"type": "no_route"}


# ---------------------------------------------------------------------------
# symbolic decision over address rectangles
# ---------------------------------------------------------------------------

@dataclass
class _Const:
    result: Result
    basis: dict


@dataclass
class _Split:
    dim: str  # "src" | "dst"


def _basis(rule: Rule, route: Route) -> dict:
    basis: dict[str, Any] = {
        "rule_priority": rule.priority,
        "table": rule.table_display,
        "route_prefix": str(route.prefix),
        "route_type": route.rtype,
    }
    if route.rtype == "unicast":
        basis["dev"] = route.dev
        basis["gateway"] = route.gateway
    return basis


def _no_route_basis() -> dict:
    return {
        "route_type": "no_route",
        "detail": "no usable route in any table selected by the rules",
    }


def _decide_rect(
    src: ipaddress.IPv4Network,
    dst: ipaddress.IPv4Network,
    rules: list[Rule],
    tables: dict[TableKey, list[Route]],
) -> Union[_Const, _Split]:
    """Decide the fate of the whole rectangle ``src`` x ``dst``.

    Returns ``_Const`` when every (source, destination) pair in the rectangle
    shares one forwarding result, or ``_Split`` when the rectangle must be
    subdivided along one dimension first.  Prefixes only ever relate as
    disjoint / superset / subset, so a rule or route either covers the whole
    rectangle, misses it, or lies strictly inside it (which forces a split).
    """
    for idx, rule in enumerate(rules):
        if not src.overlaps(rule.src) or not dst.overlaps(rule.dst):
            continue
        if not src.subnet_of(rule.src):
            return _Split("src")  # rule.src lies strictly inside src
        if not dst.subnet_of(rule.dst):
            return _Split("dst")  # rule.dst lies strictly inside dst
        # The rule covers the whole rectangle: consult its table.
        best: Optional[Route] = None
        has_inner = False
        for route in tables.get(rule.table, ()):
            if dst.subnet_of(route.prefix):
                # route.prefix covers the whole rectangle: longest prefix wins
                if best is None or route.prefix.prefixlen > best.prefix.prefixlen:
                    best = route
            elif route.prefix.subnet_of(dst):
                has_inner = True  # more-specific route strictly inside dst
        if has_inner:
            return _Split("dst")
        if best is None or best.rtype == "throw":
            continue  # no route or throw: keep consulting the next rules
        if best.rtype == "blackhole":
            return _Const(BLACKHOLE, _basis(rule, best))
        return _Const(Unicast(best.dev, best.gateway), _basis(rule, best))
    return _Const(NO_ROUTE, _no_route_basis())


MAX_CELLS = 100_000  # safety bound against pathologically fragmented inputs


def _enumerate_cells(
    src_net: ipaddress.IPv4Network,
    dst_net: ipaddress.IPv4Network,
    before: tuple[list[Rule], dict[TableKey, list[Route]]],
    after: tuple[list[Rule], dict[TableKey, list[Route]]],
) -> list[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network, _Const, _Const]]:
    """Partition src_net x dst_net into rectangles where both snapshots are constant."""
    rules_b, tables_b = before
    rules_a, tables_a = after
    cells: list[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network, _Const, _Const]] = []

    def rec(s: ipaddress.IPv4Network, d: ipaddress.IPv4Network) -> None:
        if len(cells) >= MAX_CELLS:
            raise UnsupportedInput(
                f"address space is fragmented into more than {MAX_CELLS} decision "
                "cells; narrow the CIDRs or simplify the policy"
            )
        db = _decide_rect(s, d, rules_b, tables_b)
        da = _decide_rect(s, d, rules_a, tables_a)
        if isinstance(db, _Const) and isinstance(da, _Const):
            cells.append((s, d, db, da))
            return
        if any(isinstance(x, _Split) and x.dim == "src" for x in (db, da)):
            if s.prefixlen == 32:  # pragma: no cover - unreachable by construction
                raise AssertionError("cannot split a /32 source prefix")
            left, right = s.subnets()
            rec(left, d)
            rec(right, d)
        else:
            if d.prefixlen == 32:  # pragma: no cover - unreachable by construction
                raise AssertionError("cannot split a /32 destination prefix")
            left, right = d.subnets()
            rec(s, left)
            rec(s, right)

    rec(src_net, dst_net)
    return cells


def _addr_count(net: ipaddress.IPv4Network) -> int:
    return 1 << (32 - net.prefixlen)


# ---------------------------------------------------------------------------
# public entry point
# ---------------------------------------------------------------------------

def run_precheck(
    source_cidr: Any,
    destination_cidr: Any,
    before_rules: Any,
    before_routes: Any,
    after_rules: Any,
    after_routes: Any,
) -> dict:
    """Compare two routing snapshots over source_cidr x destination_cidr.

    Returns a dict with a summary and one group per (before, after) result
    combination that actually occurs; only address pairs whose forwarding
    result changes are reported.
    """
    src_net = parse_prefix(source_cidr, "source_cidr")
    dst_net = parse_prefix(destination_cidr, "destination_cidr")
    before = (parse_rules(before_rules, "before"), parse_routes(before_routes, "before"))
    after = (parse_rules(after_rules, "after"), parse_routes(after_routes, "after"))

    cells = _enumerate_cells(src_net, dst_net, before, after)

    total = _addr_count(src_net) * _addr_count(dst_net)
    changed = 0
    groups: dict[tuple[Result, Result], dict] = {}
    for s, d, db, da in cells:
        if db.result == da.result:
            continue
        count = _addr_count(s) * _addr_count(d)
        key = (db.result, da.result)
        group = groups.get(key)
        if group is None:
            group = groups[key] = {
                "count": 0,
                "example": {
                    "source": str(s.network_address),
                    "destination": str(d.network_address),
                },
                "basis_before": db.basis,
                "basis_after": da.basis,
            }
        group["count"] += count
        changed += count

    ordered = sorted(
        groups.items(),
        key=lambda kv: json.dumps(
            [result_json(kv[0][0]), result_json(kv[0][1])], sort_keys=True
        ),
    )
    return {
        "summary": {
            "source_cidr": str(src_net),
            "destination_cidr": str(dst_net),
            "total_pairs": str(total),
            "changed_pairs": str(changed),
            "unchanged_pairs": str(total - changed),
            "group_count": len(ordered),
        },
        "groups": [
            {
                "before": result_json(key[0]),
                "after": result_json(key[1]),
                "count": str(group["count"]),
                "example": group["example"],
                "basis_before": group["basis_before"],
                "basis_after": group["basis_after"],
            }
            for key, group in ordered
        ],
    }
