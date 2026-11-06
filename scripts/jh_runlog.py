#!/usr/bin/env python3
"""Runtime egress logs from an agent sandbox, as passport evidence.

`passport --sandbox-log PATH` reads what a sandbox's network enforcement
recorded while an agent worked:

  * OpenShell's OCSF JSON export: Network Activity (4001) and HTTP Activity
    (4002) records, as plain JSONL or as `OCSF-JSON` lines from the
    supervisor's stderr;
  * Agent Substrate's egress gateway log: its JSON lines for allowed and
    denied requests.

Each connection becomes an attempt, compared with what the repository
declares: the hosts its map reaches, its committed sandbox policies, and the
operator's network ceiling. An attempt to anything else is undeclared
(P-RUN-003), whether the sandbox allowed it or blocked it. A blocked attempt to
a host the code needs is listed too: the fence would break the app.

What a log can and cannot say:
  * it is the operator's evidence, read from outside the repository, and it is
    not bound to a tree: it describes whatever the agent ran, so it can only
    add outcomes, never clear one;
  * both tools call collection best-effort (OpenShell drops lines when its
    queue is full), so a quiet log proves nothing;
  * Substrate refuses names outside the policy at DNS and logs nothing for
    them, and logs allowed requests only at debug level, so its logs mostly
    show blocked requests to names the policy resolves, or to addresses.
"""
from __future__ import annotations

import ipaddress
import json
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

import jh_ceiling
import jh_egress
import jh_fence
import jh_graph

MAX_LOG_BYTES = 64 * 1024 * 1024
MAX_LOGS = 8
MAX_ROWS = 100
MAX_DESTINATIONS = 20000            # distinct (host, port, outcome) kept; the rest are counted
OCSF_CLASSES = (4001, 4002)
CAVEATS = {
    "openshell": "OpenShell collects audit records best-effort and drops lines when its queue is full",
    "substrate": "Agent Substrate logs nothing for names it refuses at DNS, and allowed requests only at debug level",
}


def _endpoint(host: Any, port: Any = None) -> Optional[Tuple[str, Optional[int]]]:
    """(host, port) usable as a destination, or None: a hostile or malformed name never becomes a row."""
    h = str(host or "").strip().lower()
    p: Optional[int] = None
    if isinstance(port, int) and not isinstance(port, bool) and 0 < port < 65536:
        p = port
    if h.startswith("["):                               # [v6]:port
        closing = h.find("]")
        tail = h[closing + 1:] if closing > 0 else ""
        h = h[1:closing] if closing > 0 else h
        if p is None and tail.startswith(":") and tail[1:].isdigit() and 0 < int(tail[1:]) < 65536:
            p = int(tail[1:])
    elif h.count(":") == 1:                             # host:port
        head, _, tail = h.partition(":")
        if tail.isdigit() and 0 < int(tail) < 65536:
            h, p = head, (p or int(tail))
    try:
        return str(ipaddress.ip_address(h)), p
    except ValueError:
        pass
    clean = jh_fence.clean_host(h)
    return (clean, p) if clean and clean == h.rstrip(".") else None


def _text(value: Any, limit: int = 80) -> str:
    return jh_graph.sanitize_text(str(value), limit) if value not in (None, "") else ""


def _openshell(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if obj.get("class_uid") not in OCSF_CLASSES:
        return None
    dst = obj.get("dst_endpoint") if isinstance(obj.get("dst_endpoint"), dict) else {}
    end = _endpoint(dst.get("domain") or dst.get("hostname") or dst.get("ip"), dst.get("port"))
    action, disposition = obj.get("action_id"), obj.get("disposition_id")
    if action == 2 or disposition == 2:                # blocked wins when the two disagree: never report it reached
        outcome = "denied"
    elif action == 1 or disposition == 1:
        outcome = "allowed"
    else:
        return None                                     # no stated outcome (OpenShell documents no 4002 fields): skip
    actor = obj.get("actor") if isinstance(obj.get("actor"), dict) else {}
    process = actor.get("process") if isinstance(actor.get("process"), dict) else {}
    rule = obj.get("firewall_rule") if isinstance(obj.get("firewall_rule"), dict) else {}
    return {"source": "openshell", "endpoint": end, "outcome": outcome,
            "process": _text(process.get("name"), 60), "rule": _text(rule.get("name"), 60)}


def _substrate(obj: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    msg = obj.get("msg")
    if not isinstance(msg, str) or not msg.startswith(("egress denied", "egress allowed")):
        return None
    end = _endpoint(obj.get("host") or obj.get("sni") or obj.get("authority"), obj.get("dialedPort"))
    actor = obj.get("actor") if isinstance(obj.get("actor"), dict) else {}
    who = "/".join(_text(actor.get(k), 40) for k in ("atespace", "name") if actor.get(k))
    return {"source": "substrate", "endpoint": end,
            "outcome": "allowed" if msg.startswith("egress allowed") else "denied",
            "process": who, "rule": _text(msg.partition(":")[2].strip(), 60)}


def parse(text: str) -> Dict[str, Any]:
    """The network events in one log, with counts of what was read and skipped."""
    events: List[Dict[str, Any]] = []
    lines = unparsed = 0
    for raw in text.splitlines():
        line = raw.strip()
        if not line:
            continue
        lines += 1
        start = line.find("{")
        if start < 0 or (start > 0 and " OCSF-JSON " not in " " + line[:start] + " "):
            unparsed += 1                               # shorthand, text and other components' lines
            continue
        try:
            obj = json.loads(line[start:])
        except (ValueError, RecursionError):
            unparsed += 1
            continue
        event = (_openshell(obj) or _substrate(obj)) if isinstance(obj, dict) else None
        if event is None:
            unparsed += 1
        else:
            events.append(event)
    return {"events": events, "lines": lines, "unparsed": unparsed}


def _declared(map_report: Optional[Dict[str, Any]], ceiling: Optional[Iterable[Tuple[str, int]]],
              package_sources: Optional[Dict[str, Any]] = None
              ) -> Tuple[Dict[str, Optional[Set[int]]], Set[str], List[str]]:
    """Exact hosts with their ports (None: any port), the hosts the code needs (its map, and what the emitted
    fence would allow: public endpoints and package registries), and wildcard and committed policy patterns."""
    ports: Dict[str, Optional[Set[int]]] = {}

    def declare(host: Any, port: Any) -> None:
        end = _endpoint(host, port)
        if not end:
            return
        h, p = end
        if p is None:
            ports[h] = None
        elif ports.get(h, set()) is not None:
            ports.setdefault(h, set()).add(p)

    nodes = ((map_report or {}).get("graph") or {}).get("nodes") or []
    for node in nodes.values() if isinstance(nodes, dict) else nodes:
        if isinstance(node, dict):
            attrs = node.get("attributes") or {}
            declare(attrs.get("host"), attrs.get("port"))
    wild: List[str] = []
    if map_report:                      # what the emitted fence allows: public endpoints and package registries
        for row in jh_fence.plan(map_report, package_sources)["allow"]:
            if row["host"].startswith("*."):
                wild.append(row["host"])
            else:
                declare(row["host"], row["port"])
    mapped = set(ports)                 # what the code and its tooling need, before the operator's approvals
    for host, port in ceiling or ():
        declare(host, port)
    patterns = wild + [str(p) for b in ((map_report or {}).get("egress") or {}).get("boundaries") or []
                if b.get("selected") and b.get("enabled") and not b.get("open") for p in b.get("allow") or []]
    return ports, mapped, patterns


def evidence(paths: Sequence[str], root: str, map_report: Optional[Dict[str, Any]],
             ceiling: Optional[Iterable[Tuple[str, int]]] = None,
             package_sources: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """The logs as passport evidence: `{"state": "observed", ...}`, or `{"state": "not-supplied"}`."""
    if not paths:
        return {"state": "not-supplied"}
    if len(paths) > MAX_LOGS:
        raise ValueError("at most %d sandbox logs" % MAX_LOGS)
    events: List[Dict[str, Any]] = []
    lines = unparsed = 0
    for path in paths:
        raw = jh_ceiling.read_external_bytes(path, root, "sandbox log", MAX_LOG_BYTES)
        got = parse(raw.decode("utf-8", "replace"))
        events += got["events"]
        lines += got["lines"]
        unparsed += got["unparsed"]
    ports, mapped, patterns = _declared(map_report, ceiling, package_sources)

    def declared(host: str, port: Optional[int]) -> bool:
        if host in ports and (ports[host] is None or port is None or port in ports[host]):
            return True
        return any(jh_egress.matches(host, p) for p in patterns)

    rows: Dict[Tuple[str, Optional[int], str], Dict[str, Any]] = {}
    nameless = overflow = 0
    for e in events:
        if not e["endpoint"]:
            nameless += 1
            continue
        host, port = e["endpoint"]
        if (host, port, e["outcome"]) not in rows and len(rows) >= MAX_DESTINATIONS:
            overflow += 1
            continue
        row = rows.setdefault((host, port, e["outcome"]), {
            "target": host if port is None else ("[%s]:%d" % (host, port) if ":" in host else "%s:%d" % (host, port)),
            "outcome": e["outcome"], "count": 0, "declared": declared(host, port),
            "needed": host in mapped, "sources": [], "processes": []})
        row["count"] += 1
        for key, value in (("sources", e["source"]), ("processes", e["process"])):
            if value and value not in row[key] and len(row[key]) < 3:
                row[key].append(value)
    ordered = sorted(rows.values(), key=lambda r: (r["declared"], r["outcome"] != "allowed", -r["count"], r["target"]))
    undeclared = [r for r in ordered if not r["declared"]]
    sources = sorted({e["source"] for e in events})
    return {
        "state": "observed", "evidence_tier": "runtime-log", "bound_to_tree": False,
        "sources": sources, "logs": len(paths), "lines": lines, "unparsed": unparsed,
        "counts": {"events": len(events), "allowed": sum(1 for e in events if e["outcome"] == "allowed"),
                   "denied": sum(1 for e in events if e["outcome"] == "denied"), "no_destination": nameless,
                   "beyond_limit": overflow,
                   "destinations": len(rows), "undeclared": len(undeclared),
                   "undeclared_allowed": sum(1 for r in undeclared if r["outcome"] == "allowed"),
                   "blocked_needed": sum(1 for r in ordered if r["outcome"] == "denied" and r["needed"])},
        "undeclared": undeclared[:MAX_ROWS],
        "blocked_needed": [r for r in ordered if r["outcome"] == "denied" and r["needed"]][:MAX_ROWS],
        "destinations": ordered[:MAX_ROWS],
        "caveats": [CAVEATS[s] for s in sources] + ["a log is not bound to this tree, so it can only add outcomes"],
    }


def passport_line(ev: Dict[str, Any]) -> str:
    """One plain line for the passport's approver view."""
    if ev.get("state") != "observed":
        return ""
    c = ev["counts"]
    parts = ["Sandbox log (%s, not bound to this tree): %d connection(s), %d blocked" % (
        ", ".join(ev["sources"]) or "no network events", c["events"], c["denied"])]
    if c["undeclared"]:
        parts.append("%d destination(s) the repository does not declare (%d reached)" % (
            c["undeclared"], c["undeclared_allowed"]))
    if c["blocked_needed"]:
        parts.append("%d blocked destination(s) the repository needs" % c["blocked_needed"])
    if not c["undeclared"]:
        parts.append("a quiet log proves nothing about what it did not record")
    return "; ".join(parts) + "."
