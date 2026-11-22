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
    orig_index: int  # position in the raw `ip -j -4 rule show` array


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
        rules.append(Rule(priority, src, dst, table, str(entry["table"]), idx))
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
    orig_index: int  # position in the raw `ip -j -4 route show table all` array
    table_display: str


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
        tables.setdefault(table, []).append(
            Route(prefix, rtype, dev, gateway, idx, str(entry.get("table", "main")))
        )
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


# ---------------------------------------------------------------------------
# dead-config audit: which single rule / route can be removed safely
# ---------------------------------------------------------------------------

# audit verdict reason codes
REASON_CLEANABLE = "cleanable"
REASON_NOT_REFERENCED = "not_referenced_in_scope"
REASON_FORWARDING_CHANGES = "forwarding_changes"
REASON_LOCAL_EXCLUDED = "local_table_excluded"


def _partition_cells(
    src_net: ipaddress.IPv4Network,
    dst_net: ipaddress.IPv4Network,
    rules: list[Rule],
    tables: dict[TableKey, list[Route]],
) -> list[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network, _Const]]:
    """Partition src_net x dst_net into rectangles with one constant decision.

    Every decision boundary (rule selectors, route prefixes) is aligned on CIDR
    boundaries, so the rectangles tile the whole queried address space without
    overlaps.  Re-running the lookup with one rule/route removed keeps each
    rectangle constant too: removal only deletes boundaries, it never adds one.
    """
    cells: list[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network, _Const]] = []

    def rec(s: ipaddress.IPv4Network, d: ipaddress.IPv4Network) -> None:
        if len(cells) >= MAX_CELLS:
            raise UnsupportedInput(
                f"address space is fragmented into more than {MAX_CELLS} decision "
                "cells; narrow the CIDRs or simplify the policy"
            )
        decision = _decide_rect(s, d, rules, tables)
        if isinstance(decision, _Const):
            cells.append((s, d, decision))
            return
        if decision.dim == "src":
            left, right = s.subnets()
            rec(left, d)
            rec(right, d)
        else:
            left, right = d.subnets()
            rec(s, left)
            rec(s, right)

    rec(src_net, dst_net)
    return cells


@dataclass
class _Usage:
    """Which rules/routes actually decide traffic, and on how many pairs."""

    rule_pairs: dict[int, int]
    route_pairs: dict[int, int]
    rule_sample: dict[int, tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]]
    route_sample: dict[int, tuple[ipaddress.IPv4Network, ipaddress.IPv4Network]]


def _trace_usage(
    cells: list[tuple[ipaddress.IPv4Network, ipaddress.IPv4Network, _Const]],
    rules: list[Rule],
    tables: dict[TableKey, list[Route]],
) -> _Usage:
    """Walk every decision cell with the real rule order and record usage.

    A rule is "used" when its selectors match at least one queried pair;
    a route is "used" when it is consulted as the longest-prefix route of a
    matched rule's table (including a longest-prefix ``throw`` that makes the
    lookup fall through).  Items never hit inside the queried range stay
    unrecorded and cannot be declared safe later.
    """
    rule_pairs: dict[int, int] = {}
    route_pairs: dict[int, int] = {}
    rule_sample: dict[int, tuple] = {}
    route_sample: dict[int, tuple] = {}

    for s, d, _const in cells:
        area = _addr_count(s) * _addr_count(d)
        routes_hit_in_cell: set[int] = set()
        for rule in rules:
            if not s.subnet_of(rule.src) or not d.subnet_of(rule.dst):
                continue
            rule_pairs[rule.orig_index] = rule_pairs.get(rule.orig_index, 0) + area
            rule_sample.setdefault(rule.orig_index, (s, d))
            best: Optional[Route] = None
            for route in tables.get(rule.table, ()):
                if d.subnet_of(route.prefix) and (
                    best is None or route.prefix.prefixlen > best.prefix.prefixlen
                ):
                    best = route
            if best is not None:
                # several rules may point at the same table; count each route
                # only once per address pair
                if best.orig_index not in routes_hit_in_cell:
                    routes_hit_in_cell.add(best.orig_index)
                    route_pairs[best.orig_index] = (
                        route_pairs.get(best.orig_index, 0) + area
                    )
                    route_sample.setdefault(best.orig_index, (s, d))
                if best.rtype in ("unicast", "blackhole"):
                    break  # terminal decision; later rules are not consulted here
            # no route or a throw: fall through to the next rule
    return _Usage(rule_pairs, route_pairs, rule_sample, route_sample)


def _points_to_local(entry: dict) -> bool:
    try:
        return normalize_table(entry.get("table"), "audit") == LOCAL_TABLE_ID
    except UnsupportedInput:
        return False


def _rule_identity(entry: dict) -> dict:
    identity: dict[str, Any] = {"priority": entry.get("priority")}
    if "src" in entry:
        identity["src"] = entry["src"]
    if "dst" in entry:
        identity["dst"] = entry["dst"]
    identity["table"] = entry.get("table")
    if "action" in entry:
        identity["action"] = entry["action"]
    return identity


def _route_identity(entry: dict) -> dict:
    identity: dict[str, Any] = {"dst": entry.get("dst"), "table": entry.get("table", "main")}
    if "type" in entry:
        identity["type"] = entry["type"]
    if "dev" in entry:
        identity["dev"] = entry["dev"]
    if "gateway" in entry:
        identity["gateway"] = entry["gateway"]
    return identity


def _evaluate_removal(
    cells: list[
        tuple[ipaddress.IPv4Network, ipaddress.IPv4Network, _Const]
    ],
    rules: list[Rule],
    tables: dict[TableKey, list[Route]],
) -> tuple[int, Optional[dict]]:
    """Re-run the lookup over every baseline cell for one modified snapshot.

    Returns (number of pairs whose result changed, evidence for the first
    changed cell).  Baseline cells hold no internal decision boundary, so the
    modified lookup is constant on each of them.
    """
    changed = 0
    first: Optional[dict] = None
    for s, d, const in cells:
        decision = _decide_rect(s, d, rules, tables)
        if not isinstance(decision, _Const):  # pragma: no cover - removal adds no boundary
            raise AssertionError("removing an item must not split a baseline decision cell")
        if decision.result != const.result:
            area = _addr_count(s) * _addr_count(d)
            changed += area
            if first is None:
                first = {
                    "sample": {"source": str(s.network_address),
                               "destination": str(d.network_address)},
                    "before_removal": result_json(const.result),
                    "after_removal": result_json(decision.result),
                    "basis_before_removal": const.basis,
                    "basis_after_removal": decision.basis,
                    "changed_pairs_in_sample_cell": str(area),
                }
    return changed, first


def run_audit(
    source_cidr: Any,
    destination_cidr: Any,
    raw_rules: Any,
    raw_routes: Any,
) -> dict:
    """Audit every rule/route of one snapshot for safe removal.

    An item is reported cleanable only when (1) it is actually consulted for
    at least one queried address pair and (2) deleting it leaves the whole
    source x destination range with identical results -- identical
    (dev, gateway) unicast combinations, blackholes and no-route outcomes.
    Items that simply never match inside the range are kept distinct so a
    narrower query can never turn shadowed config into a "safe" verdict.
    """
    src_net = parse_prefix(source_cidr, "source_cidr")
    dst_net = parse_prefix(destination_cidr, "destination_cidr")
    if not isinstance(raw_rules, list):
        raise UnsupportedInput(
            "rules: must be the JSON array from `ip -j -4 rule show`"
        )
    if not isinstance(raw_routes, list):
        raise UnsupportedInput(
            "routes: must be the JSON array from `ip -j -4 route show table all`"
        )

    rules = parse_rules(raw_rules, "snapshot")
    tables = parse_routes(raw_routes, "snapshot")

    cells = _partition_cells(src_net, dst_net, rules, tables)
    total_pairs = _addr_count(src_net) * _addr_count(dst_net)
    usage = _trace_usage(cells, rules, tables)

    parsed_rules_by_index = {rule.orig_index: rule for rule in rules}
    parsed_routes_by_index = {
        route.orig_index: table_routes
        for table_routes in tables.values()
        for route in table_routes
    }

    audited_rules: list[dict] = []
    cleanable_rules = 0
    for idx, entry in enumerate(raw_rules):
        identity = _rule_identity(entry)
        if _points_to_local(entry):
            audited_rules.append({
                "index": idx,
                "kind": "rule",
                "identity": identity,
                "cleanable": False,
                "reason": REASON_LOCAL_EXCLUDED,
                "evidence": {
                    "detail": "rules pointing to the local table are not modeled; "
                              "their effect is outside this audit's scope"
                },
            })
            continue
        rule = parsed_rules_by_index.get(idx)
        if rule is None or idx not in usage.rule_pairs:
            audited_rules.append({
                "index": idx,
                "kind": "rule",
                "identity": identity,
                "cleanable": False,
                "reason": REASON_NOT_REFERENCED,
                "evidence": {
                    "detail": "no (source, destination) pair in the queried CIDR range "
                              "matches this rule's selectors; it cannot be proven safe "
                              "from this query alone"
                },
            })
            continue
        modified_rules = [r for r in rules if r.orig_index != idx]
        changed, first_change = _evaluate_removal(cells, modified_rules, tables)
        sample_s, sample_d = usage.rule_sample[idx]
        evidence: dict[str, Any] = {
            "matched_pairs": str(usage.rule_pairs[idx]),
            "sample": {"source": str(sample_s.network_address),
                       "destination": str(sample_d.network_address)},
        }
        if changed == 0:
            cleanable_rules += 1
            sample_cell = next(
                c for c in cells if c[0] == sample_s and c[1] == sample_d
            )[2]
            evidence["changed_pairs_after_removal"] = "0"
            evidence["sample_result_before_removal"] = result_json(sample_cell.result)
            evidence["sample_basis_before_removal"] = sample_cell.basis
            audited_rules.append({
                "index": idx,
                "kind": "rule",
                "identity": identity,
                "cleanable": True,
                "reason": REASON_CLEANABLE,
                "evidence": evidence,
            })
        else:
            evidence["changed_pairs_after_removal"] = str(changed)
            evidence["first_change"] = first_change
            audited_rules.append({
                "index": idx,
                "kind": "rule",
                "identity": identity,
                "cleanable": False,
                "reason": REASON_FORWARDING_CHANGES,
                "evidence": evidence,
            })

    audited_routes: list[dict] = []
    cleanable_routes = 0
    for idx, entry in enumerate(raw_routes):
        identity = _route_identity(entry)
        if normalize_table(entry.get("table", "main"), "audit") == LOCAL_TABLE_ID:
            audited_routes.append({
                "index": idx,
                "kind": "route",
                "identity": identity,
                "cleanable": False,
                "reason": REASON_LOCAL_EXCLUDED,
                "evidence": {
                    "detail": "routes in the local table are not modeled; their "
                              "effect is outside this audit's scope"
                },
            })
            continue
        if idx not in parsed_routes_by_index or idx not in usage.route_pairs:
            audited_routes.append({
                "index": idx,
                "kind": "route",
                "identity": identity,
                "cleanable": False,
                "reason": REASON_NOT_REFERENCED,
                "evidence": {
                    "detail": "no (source, destination) pair in the queried CIDR range "
                              "consults this route as a table's longest-prefix match; "
                              "it cannot be proven safe from this query alone"
                },
            })
            continue
        modified_tables = {
            table: [r for r in table_routes if r.orig_index != idx]
            for table, table_routes in tables.items()
        }
        changed, first_change = _evaluate_removal(cells, rules, modified_tables)
        sample_s, sample_d = usage.route_sample[idx]
        evidence = {
            "matched_pairs": str(usage.route_pairs[idx]),
            "sample": {"source": str(sample_s.network_address),
                       "destination": str(sample_d.network_address)},
        }
        if changed == 0:
            cleanable_routes += 1
            sample_cell = next(
                c for c in cells if c[0] == sample_s and c[1] == sample_d
            )[2]
            evidence["changed_pairs_after_removal"] = "0"
            evidence["sample_result_before_removal"] = result_json(sample_cell.result)
            evidence["sample_basis_before_removal"] = sample_cell.basis
            audited_routes.append({
                "index": idx,
                "kind": "route",
                "identity": identity,
                "cleanable": True,
                "reason": REASON_CLEANABLE,
                "evidence": evidence,
            })
        else:
            evidence["changed_pairs_after_removal"] = str(changed)
            evidence["first_change"] = first_change
            audited_routes.append({
                "index": idx,
                "kind": "route",
                "identity": identity,
                "cleanable": False,
                "reason": REASON_FORWARDING_CHANGES,
                "evidence": evidence,
            })

    return {
        "summary": {
            "source_cidr": str(src_net),
            "destination_cidr": str(dst_net),
            "total_pairs": str(total_pairs),
            "rules_total": len(raw_rules),
            "rules_cleanable": cleanable_rules,
            "routes_total": len(raw_routes),
            "routes_cleanable": cleanable_routes,
        },
        "rules": audited_rules,
        "routes": audited_routes,
    }
