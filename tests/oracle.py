"""Independent reference oracle for jankhunt42 blast-radius reachability.

Written from the documented semantics (references/connectivity.md), NOT from
jh_graph.py. It enumerates every simple path up to the depth bound
(exponential, so tiny graphs only) and takes, per node, the best path's
weakest edge. It shares no code with the production BFS.

Admissibility, stated as data:
  * refuted edges never propagate
  * authenticates-as propagates every impact at its evidence tier
  * depends-on never propagates authority
  * unknown capability on connects/calls propagates every impact, capped
    at tier 1 (potential); on exports/publishes it propagates
    confidentiality only, capped at 1
  * known capability: confidentiality via read/admin or any
    exports/publishes/calls edge; integrity via write/delete/admin;
    availability via delete/admin
Evidence tiers: provider-verified 3, observed 2, declared 2, inferred 1, unknown 0.
"""

TIER = {"provider-verified": 3, "observed": 2, "declared": 2, "inferred": 1, "unknown": 0}
CAPS_FOR = {
    "confidentiality": frozenset({"read", "admin"}),
    "integrity": frozenset({"write", "delete", "admin"}),
    "availability": frozenset({"delete", "admin"}),
}
C_KINDS = frozenset({"exports", "publishes", "calls"})
UNKNOWN_ALL = frozenset({"connects", "calls"})
UNKNOWN_C = frozenset({"exports", "publishes"})


def step_tier(e, impact):
    if e["verification"] == "refuted" or e["kind"] == "depends-on":
        return None
    t = TIER[e["verification"]]
    if e["kind"] == "authenticates-as":
        return t
    if e["capability"] == "unknown":
        if e["kind"] in UNKNOWN_ALL or (impact == "confidentiality" and e["kind"] in UNKNOWN_C):
            return min(t, 1)
        return None
    if e["capability"] in CAPS_FOR[impact]:
        return t
    if impact == "confidentiality" and e["kind"] in C_KINDS:
        return t
    return None


def reach(edges, source, impact, max_depth):
    best = {}

    def dfs(node, visited, depth, weakest):
        if depth == max_depth:
            return
        for e in edges:
            if e["source"] != node or e["target"] in visited:
                continue
            t = step_tier(e, impact)
            if t is None:
                continue
            w = min(weakest, t)
            tgt = e["target"]
            if tgt not in best or w > best[tgt]:
                best[tgt] = w
            dfs(tgt, visited | {tgt}, depth + 1, w)

    dfs(source, {source}, 0, 3)
    return best


def path_is_valid(edges_by_id, source, target, path, impact, tier, max_depth):
    """A witness path must be connected, admissible, simple, bounded, and
    have exactly the reported weakest-link tier."""
    if not path or len(path) > max_depth:
        return False
    cur = source
    seen = {source}
    weakest = 3
    for eid in path:
        e = edges_by_id[eid]
        if e["source"] != cur or e["target"] in seen:
            return False
        t = step_tier(e, impact)
        if t is None:
            return False
        weakest = min(weakest, t)
        cur = e["target"]
        seen.add(cur)
    return cur == target and weakest == tier


def strongest(edges, source, impact, max_depth):
    """Exhaustive maximum product of attenuations (missing = 1.0, 0 excluded)
    over simple admissible paths of at most max_depth edges."""
    best = {}

    def dfs(node, visited, depth, prod):
        if depth == max_depth:
            return
        for e in edges:
            if e["source"] != node or e["target"] in visited or step_tier(e, impact) is None:
                continue
            a = float(e.get("attenuation", 1.0))
            if a <= 0:
                continue
            p = prod * min(1.0, a)
            tgt = e["target"]
            if tgt not in best or p > best[tgt] + 1e-12:
                best[tgt] = p
            dfs(tgt, visited | {tgt}, depth + 1, p)

    dfs(source, {source}, 0, 1.0)
    return best
