"""Unit tests for the dead-config audit engine (app/routing.run_audit)."""
import ipaddress
import random

import pytest

from app.routing import UnsupportedInput, parse_routes, parse_rules, run_audit

LOCAL_RULE = {"priority": 0, "src": "all", "table": "local"}
MAIN_RULE = {"priority": 32766, "src": "all", "table": "main"}


def verdict(res, kind, index):
    (item,) = [x for x in res[kind + "s"] if x["index"] == index]
    return item


# ---------------------------------------------------------------------------
# interleaved rules: shadowing, duplication and a load-bearing middle rule
# ---------------------------------------------------------------------------

def test_interleaved_rules_audit():
    rules = [
        LOCAL_RULE,                                                       # 0
        {"priority": 100, "src": "10.0.0.0/8", "table": "100"},           # 1
        {"priority": 150, "dst": "203.0.113.0/24", "table": "200"},       # 2
        {"priority": 200, "src": "10.0.0.0/8", "table": "100"},           # 3 duplicate
        MAIN_RULE,                                                        # 4
    ]
    routes = [
        {"dst": "10.0.0.0/8", "dev": "lo", "table": "local"},             # 0
        {"dst": "203.0.113.0/24", "type": "throw", "table": "100"},       # 1
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1",
         "table": "100"},                                                 # 2
        {"dst": "203.0.113.0/24", "dev": "eth2", "table": "200"},         # 3
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0",
         "table": "main"},                                                # 4
    ]
    res = run_audit("10.0.0.0/8", "0.0.0.0/0", rules, routes)

    assert [x["index"] for x in res["rules"]] == [0, 1, 2, 3, 4]
    assert [x["index"] for x in res["routes"]] == [0, 1, 2, 3, 4]

    # local table / rule pointing to it: excluded, never called safe
    assert verdict(res, "rule", 0)["reason"] == "local_table_excluded"
    assert verdict(res, "route", 0)["reason"] == "local_table_excluded"
    assert not verdict(res, "rule", 0)["cleanable"]

    # rule 1 is duplicated by rule 3 behind it and rule 2 covers the throw case
    r1 = verdict(res, "rule", 1)
    assert r1["cleanable"] is True and r1["reason"] == "cleanable"
    assert r1["evidence"]["changed_pairs_after_removal"] == "0"
    assert int(r1["evidence"]["matched_pairs"]) == int(res["summary"]["total_pairs"])

    # rule 2 genuinely keeps 203.0.113.0/24 on eth2: removing it falls through to main
    r2 = verdict(res, "rule", 2)
    assert r2["cleanable"] is False and r2["reason"] == "forwarding_changes"
    change = r2["evidence"]["first_change"]
    assert change["before_removal"] == {"type": "unicast", "dev": "eth2", "gateway": None}
    assert change["after_removal"] == {"type": "unicast", "dev": "eth0",
                                       "gateway": "192.0.2.1"}
    assert change["sample"]["destination"] == "203.0.113.0"
    assert int(r2["evidence"]["changed_pairs_after_removal"]) == 2**24 * 256

    # rules 3 and 4 are shadowed inside this range: NOT misreported as safe
    for idx in (3, 4):
        item = verdict(res, "rule", idx)
        assert item["cleanable"] is False
        assert item["reason"] == "not_referenced_in_scope"

    # the throw is the longest-prefix route for 203.0.113.0/24: it is load-bearing
    throw = verdict(res, "route", 1)
    assert throw["reason"] == "forwarding_changes" and throw["cleanable"] is False
    assert throw["evidence"]["first_change"]["after_removal"]["dev"] == "eth1"

    # every remaining unicast route is load-bearing here; the main default is shadowed
    for idx in (2, 3):
        assert verdict(res, "route", idx)["reason"] == "forwarding_changes"
    assert verdict(res, "route", 4)["reason"] == "not_referenced_in_scope"

    assert res["summary"]["rules_cleanable"] == 1
    assert res["summary"]["routes_cleanable"] == 0
    assert res["summary"]["rules_total"] == 5 and res["summary"]["routes_total"] == 5


# ---------------------------------------------------------------------------
# throw semantics
# ---------------------------------------------------------------------------

def test_throw_that_masks_a_less_specific_route_is_not_cleanable():
    rules = [
        {"priority": 100, "src": "all", "table": "100"},
        MAIN_RULE,
    ]
    routes = [
        {"dst": "192.0.2.0/24", "type": "throw", "table": "100"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
    ]
    res = run_audit("10.0.0.1/32", "192.0.2.0/24", rules, routes)
    throw = verdict(res, "route", 0)
    # removing the throw exposes table 100's default -> eth1 instead of main -> eth0
    assert throw["cleanable"] is False
    assert throw["reason"] == "forwarding_changes"
    assert throw["evidence"]["first_change"]["before_removal"]["dev"] == "eth0"
    assert throw["evidence"]["first_change"]["after_removal"]["dev"] == "eth1"
    # table 100's default is never the LPM inside this range: not proven safe
    assert verdict(res, "route", 1)["reason"] == "not_referenced_in_scope"


def test_redundant_throw_is_cleanable_when_fallthrough_lands_the_same_way():
    rules = [
        {"priority": 100, "src": "all", "table": "100"},
        MAIN_RULE,
    ]
    routes = [
        {"dst": "192.0.2.0/24", "type": "throw", "table": "100"},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
    ]
    res = run_audit("10.0.0.1/32", "192.0.2.0/24", rules, routes)
    throw = verdict(res, "route", 0)
    # the throw IS consulted (LPM of table 100); with or without it main gives eth0
    assert throw["cleanable"] is True and throw["reason"] == "cleanable"
    assert int(throw["evidence"]["matched_pairs"]) == 256
    assert throw["evidence"]["changed_pairs_after_removal"] == "0"
    assert throw["evidence"]["sample_result_before_removal"] == {
        "type": "unicast", "dev": "eth0", "gateway": "192.0.2.1"
    }
    assert res["summary"]["routes_cleanable"] == 1


def test_throw_in_otherwise_empty_table_makes_its_rule_cleanable():
    rules = [
        {"priority": 100, "src": "all", "table": "100"},  # table 100 only has a throw
        MAIN_RULE,
    ]
    routes = [
        {"dst": "192.0.2.0/24", "type": "throw", "table": "100"},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
    ]
    res = run_audit("10.0.0.1/32", "192.0.2.0/24", rules, routes)
    # rule 100 always falls through to main with identical outcome -> safe to delete
    rule100 = verdict(res, "rule", 0)
    assert rule100["cleanable"] is True and rule100["reason"] == "cleanable"
    main_rule = verdict(res, "rule", 1)
    assert main_rule["cleanable"] is False  # main actually carries the traffic
    assert main_rule["reason"] == "forwarding_changes"


# ---------------------------------------------------------------------------
# blackhole semantics
# ---------------------------------------------------------------------------

def test_load_bearing_blackhole_is_not_cleanable():
    rules = [MAIN_RULE]
    routes = [
        {"dst": "198.51.100.128/25", "type": "blackhole", "table": "main"},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
    ]
    res = run_audit("10.0.0.1/32", "198.51.100.0/24", rules, routes)
    bh = verdict(res, "route", 0)
    assert bh["cleanable"] is False and bh["reason"] == "forwarding_changes"
    change = bh["evidence"]["first_change"]
    assert change["before_removal"] == {"type": "blackhole"}
    assert change["after_removal"] == {"type": "unicast", "dev": "eth0",
                                       "gateway": "192.0.2.1"}
    assert int(bh["evidence"]["matched_pairs"]) == 128


def test_unreachable_blackhole_is_not_referenced_not_cleanable():
    # the first rule always terminates, so table 200's blackhole is never consulted
    rules = [
        {"priority": 100, "src": "all", "table": "100"},
        {"priority": 200, "src": "all", "table": "200"},
    ]
    routes = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "192.0.2.0/24", "type": "blackhole", "table": "200"},
    ]
    res = run_audit("10.0.0.1/32", "192.0.2.0/24", rules, routes)
    assert verdict(res, "route", 1)["reason"] == "not_referenced_in_scope"
    assert verdict(res, "rule", 1)["reason"] == "not_referenced_in_scope"


def test_blackhole_cleanable_when_a_later_table_blackholes_identically():
    rules = [
        {"priority": 100, "src": "all", "table": "100"},
        {"priority": 200, "src": "all", "table": "200"},
    ]
    routes = [
        {"dst": "192.0.2.0/24", "type": "blackhole", "table": "100"},
        {"dst": "192.0.2.0/24", "type": "blackhole", "table": "200"},
        {"dst": "default", "gateway": "203.0.113.1", "dev": "eth2", "table": "200"},
    ]
    res = run_audit("10.0.0.1/32", "192.0.2.0/24", rules, routes)
    first_bh = verdict(res, "route", 0)
    assert first_bh["cleanable"] is True and first_bh["reason"] == "cleanable"
    # the second blackhole is shadowed: not proven safe from this query
    assert verdict(res, "route", 1)["reason"] == "not_referenced_in_scope"
    assert verdict(res, "route", 2)["reason"] == "not_referenced_in_scope"
    # the second rule is only reached after the first blackhole: shadowed as well
    assert verdict(res, "rule", 1)["reason"] == "not_referenced_in_scope"


# ---------------------------------------------------------------------------
# nested prefixes
# ---------------------------------------------------------------------------

def test_nested_route_prefixes_shadowed_default_not_misreported():
    rules = [MAIN_RULE]
    routes = [
        {"dst": "10.1.0.0/16", "gateway": "192.0.2.2", "dev": "eth1", "table": "main"},
        {"dst": "10.1.2.0/24", "gateway": "192.0.2.3", "dev": "eth2", "table": "main"},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
    ]
    res = run_audit("172.16.0.1/32", "10.1.0.0/16", rules, routes)
    # both more-specifics carry traffic and are load-bearing
    for idx, pairs in ((0, 2**16 - 256), (1, 256)):
        item = verdict(res, "route", idx)
        assert item["reason"] == "forwarding_changes"
        assert int(item["evidence"]["matched_pairs"]) == pairs
    # the default never becomes LPM inside 10.1.0.0/16: shadowed, not "safe"
    shadowed = verdict(res, "route", 2)
    assert shadowed["reason"] == "not_referenced_in_scope"
    assert shadowed["cleanable"] is False


def test_nested_src_selectors_both_used_and_distinguished():
    rules = [
        {"priority": 100, "src": "10.0.1.0/24", "table": "200"},
        {"priority": 200, "src": "10.0.0.0/8", "table": "100"},
        MAIN_RULE,
    ]
    routes = [
        {"dst": "default", "gateway": "203.0.113.1", "dev": "eth2", "table": "200"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
    ]
    res = run_audit("10.0.0.0/8", "192.0.2.1/32", rules, routes)
    narrow, broad = verdict(res, "rule", 0), verdict(res, "rule", 1)
    assert int(narrow["evidence"]["matched_pairs"]) == 256
    assert int(broad["evidence"]["matched_pairs"]) == 2**24 - 256
    assert narrow["reason"] == "forwarding_changes"
    assert broad["reason"] == "forwarding_changes"
    assert verdict(res, "rule", 2)["reason"] == "not_referenced_in_scope"
    # table 200's route only serves the narrow slice
    assert int(verdict(res, "route", 0)["evidence"]["matched_pairs"]) == 256
    assert int(verdict(res, "route", 1)["evidence"]["matched_pairs"]) == 2**24 - 256


def test_duplicate_route_behind_identical_rules_makes_first_cleanable():
    rules = [
        {"priority": 100, "src": "all", "table": "100"},
        {"priority": 200, "src": "all", "table": "200"},
    ]
    routes = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "200"},
    ]
    res = run_audit("10.0.0.1/32", "192.0.2.1/32", rules, routes)
    assert verdict(res, "route", 0)["cleanable"] is True  # same (dev, gateway) via rule 200
    assert verdict(res, "rule", 0)["cleanable"] is True   # rule 200 yields the same result
    assert verdict(res, "route", 1)["reason"] == "not_referenced_in_scope"
    assert verdict(res, "rule", 1)["reason"] == "not_referenced_in_scope"


def test_different_gateway_is_a_different_result():
    rules = [
        {"priority": 100, "src": "all", "table": "100"},
        {"priority": 200, "src": "all", "table": "200"},
    ]
    routes = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "198.51.100.2", "dev": "eth1", "table": "200"},
    ]
    res = run_audit("10.0.0.1/32", "192.0.2.1/32", rules, routes)
    assert verdict(res, "route", 0)["reason"] == "forwarding_changes"
    assert verdict(res, "rule", 0)["reason"] == "forwarding_changes"


# ---------------------------------------------------------------------------
# scope discipline: nothing outside the queried range can justify a verdict
# ---------------------------------------------------------------------------

def test_item_live_outside_scope_is_not_referenced_inside():
    rules = [
        {"priority": 100, "dst": "203.0.113.0/24", "table": "100"},
        MAIN_RULE,
    ]
    routes = [
        {"dst": "203.0.113.0/24", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
    ]
    # query only 192.0.2.0/24: rule 100 and its route never match here
    res = run_audit("10.0.0.1/32", "192.0.2.0/24", rules, routes)
    assert verdict(res, "rule", 0)["reason"] == "not_referenced_in_scope"
    assert verdict(res, "route", 0)["reason"] == "not_referenced_in_scope"
    # widen the query and the same items become load-bearing
    wide = run_audit("10.0.0.1/32", "0.0.0.0/0", rules, routes)
    assert verdict(wide, "rule", 0)["reason"] == "forwarding_changes"
    assert verdict(wide, "route", 0)["reason"] == "forwarding_changes"


def test_slash_zero_range_runs_symbolically():
    rules = [
        LOCAL_RULE,
        {"priority": 100, "src": "all", "table": "100"},
        MAIN_RULE,
    ]
    routes = [
        {"dst": "default", "gateway": "198.51.100.1", "dev": "eth1", "table": "100"},
        {"dst": "default", "gateway": "192.0.2.1", "dev": "eth0", "table": "main"},
    ]
    res = run_audit("0.0.0.0/0", "0.0.0.0/0", rules, routes)
    assert res["summary"]["total_pairs"] == str(2**64)
    assert verdict(res, "rule", 1)["evidence"]["matched_pairs"] == str(2**64)
    assert verdict(res, "rule", 1)["reason"] == "forwarding_changes"
    assert verdict(res, "rule", 2)["reason"] == "not_referenced_in_scope"
    assert verdict(res, "route", 1)["reason"] == "not_referenced_in_scope"


# ---------------------------------------------------------------------------
# unsupported input
# ---------------------------------------------------------------------------

def test_audit_rejects_unsupported_input_with_400_level_error():
    with pytest.raises(UnsupportedInput, match="fwmark"):
        run_audit(
            "10.0.0.0/8", "192.0.2.0/24",
            [{"priority": 100, "fwmark": "0x1", "table": "100"}], [],
        )
    with pytest.raises(UnsupportedInput, match="nexthops"):
        run_audit(
            "10.0.0.0/8", "192.0.2.0/24",
            [MAIN_RULE],
            [{"dst": "default", "nexthops": [{"dev": "eth0"}], "table": "main"}],
        )
    with pytest.raises(UnsupportedInput):
        run_audit("not-a-cidr", "192.0.2.0/24", [MAIN_RULE], [])
    with pytest.raises(UnsupportedInput):
        run_audit("10.0.0.0/8", "192.0.2.0/24", {"priority": 100}, [])


# ---------------------------------------------------------------------------
# randomized cross-check against an independent per-address oracle
# ---------------------------------------------------------------------------

def brute_oracle(src_net, dst_net, raw_rules, raw_routes):
    """Return per-index (used, cleanable) verdicts from brute per-address lookup."""
    rules = parse_rules(raw_rules, "oracle")
    tables = parse_routes(raw_routes, "oracle")

    def lookup(src_ip, dst_ip, trace=False):
        used_rules, used_routes = set(), set()
        for rule in rules:
            if src_ip in rule.src and dst_ip in rule.dst:
                used_rules.add(rule.orig_index)
                best = None
                for route in tables.get(rule.table, []):
                    if dst_ip in route.prefix and (
                        best is None or route.prefix.prefixlen > best.prefix.prefixlen
                    ):
                        best = route
                if best is None:
                    continue
                used_routes.add(best.orig_index)
                if best.rtype == "throw":
                    continue
                if best.rtype == "blackhole":
                    return ("blackhole",), used_rules, used_routes
                return ("unicast", best.dev, best.gateway), used_rules, used_routes
        return ("no_route",), used_rules, used_routes

    pairs = [(s, d) for s in src_net for d in dst_net]
    base = {}
    rule_hits, route_hits = set(), set()
    rule_counts, route_counts = {}, {}
    for s, d in pairs:
        result, ur, ut = lookup(s, d)
        base[(s, d)] = result
        rule_hits |= ur
        route_hits |= ut
        for i in ur:
            rule_counts[i] = rule_counts.get(i, 0) + 1
        for i in ut:
            route_counts[i] = route_counts.get(i, 0) + 1

    def removal_clean(kind, index):
        nonlocal rules, tables
        for s, d in pairs:
            saved_rules = rules
            saved_tables = tables
            try:
                if kind == "rule":
                    rules = [r for r in saved_rules if r.orig_index != index]
                else:
                    tables = {
                        t: [r for r in rs if r.orig_index != index]
                        for t, rs in saved_tables.items()
                    }
                result, _, _ = lookup(s, d)
            finally:
                rules = saved_rules
                tables = saved_tables
            if result != base[(s, d)]:
                return False
        return True

    rule_verdict = {
        r.orig_index: (r.orig_index in rule_hits,
                       removal_clean("rule", r.orig_index))
        for r in rules
    }
    route_verdict = {
        rt.orig_index: (rt.orig_index in route_hits,
                        removal_clean("route", rt.orig_index))
        for rs in tables.values() for rt in rs
    }
    return rule_verdict, route_verdict, rule_counts, route_counts


def random_audit_policy(rng):
    table_ids = ("100", "200", "300")
    raw_rules = [dict(LOCAL_RULE)]
    prios = rng.sample(range(100, 1000), k=rng.randint(1, 4))
    for prio in sorted(prios):
        rule = {"priority": prio, "table": rng.choice(table_ids)}
        if rng.random() < 0.6:
            rule["src"] = rng.choice(
                ["10.0.0.0/9", "10.0.0.0/10", "10.0.0.64/26", "10.0.0.0/8"]
            )
        if rng.random() < 0.5:
            rule["dst"] = rng.choice(
                ["192.0.2.0/25", "192.0.2.0/24", "192.0.2.128/25",
                 "192.0.2.0/26", "192.0.2.64/26"]
            )
        raw_rules.append(rule)
    raw_rules.append(dict(MAIN_RULE))

    raw_routes = [
        {"dst": "0.0.0.0/0", "type": "blackhole", "table": "local"},
        {"dst": "192.0.2.0/24", "type": "blackhole", "table": "local"},
    ]
    used = set()
    prefixes = ["0.0.0.0/0", "192.0.2.0/24", "192.0.2.0/25", "192.0.2.128/25",
                "192.0.2.0/26", "192.0.2.64/26"]
    for table in table_ids + ("main",):
        for _ in range(rng.randint(0, 4)):
            prefix = rng.choice(prefixes)
            if (table, prefix) in used:
                continue
            used.add((table, prefix))
            kind = rng.random()
            if kind < 0.55:
                route = {"dst": prefix, "table": table,
                         "dev": rng.choice(["eth0", "eth1", "eth2"])}
                gw = rng.choice([None, "203.0.113.1", "203.0.113.2"])
                if gw is not None:
                    route["gateway"] = gw
                raw_routes.append(route)
            elif kind < 0.78:
                raw_routes.append({"dst": prefix, "table": table, "type": "throw"})
            else:
                raw_routes.append({"dst": prefix, "table": table, "type": "blackhole"})
    return raw_rules, raw_routes


def test_audit_matches_bruteforce_on_random_policies():
    rng = random.Random(20261122)
    src_net = ipaddress.IPv4Network("10.0.0.0/26")
    dst_net = ipaddress.IPv4Network("192.0.2.0/26")
    for _ in range(50):
        raw_rules, raw_routes = random_audit_policy(rng)
        res = run_audit(str(src_net), str(dst_net), raw_rules, raw_routes)
        rule_oracle, route_oracle, rule_counts, route_counts = brute_oracle(
            src_net, dst_net, raw_rules, raw_routes
        )

        assert len(res["rules"]) == len(raw_rules)
        assert len(res["routes"]) == len(raw_routes)

        for item in res["rules"]:
            idx = item["index"]
            if item["reason"] == "local_table_excluded":
                assert idx not in rule_oracle  # local rule dropped by the parser
                continue
            used, clean = rule_oracle[idx]
            if not used:
                assert item["reason"] == "not_referenced_in_scope"
                assert item["cleanable"] is False
            elif clean:
                assert item["reason"] == "cleanable"
                assert item["cleanable"] is True
                assert item["evidence"]["changed_pairs_after_removal"] == "0"
            else:
                assert item["reason"] == "forwarding_changes"
                assert item["cleanable"] is False
                assert int(item["evidence"]["changed_pairs_after_removal"]) > 0
            if used:
                assert int(item["evidence"]["matched_pairs"]) == rule_counts[idx]

        for item in res["routes"]:
            idx = item["index"]
            if item["reason"] == "local_table_excluded":
                assert idx not in route_oracle
                continue
            used, clean = route_oracle[idx]
            if not used:
                assert item["reason"] == "not_referenced_in_scope"
                assert item["cleanable"] is False
            elif clean:
                assert item["reason"] == "cleanable"
                assert item["cleanable"] is True
            else:
                assert item["reason"] == "forwarding_changes"
                assert item["cleanable"] is False
            if used:
                assert int(item["evidence"]["matched_pairs"]) == route_counts[idx]
