#!/usr/bin/env python3
"""Typed connectivity graph, endpoint sanitizing, CIA reachability, and
exposure classification for `jankhunt42 map` and `jankhunt42 passport`.

The graph is a *static* picture: every edge records how it was learned
(`verification`) and what it may allow (`capability`). Nothing here proves
runtime access. A connection string is not a grant, an SDK import is not a
data flow, and an unknown capability is never treated as read-only.

Direction convention (fixed, tested by an independent oracle in tests/):
an edge `A -> B` means "A acts on B" (A connects to, reads, writes, calls,
authenticates as, or depends on B). Blast radius walks edges forward from a
principal (an application or workload). Availability additionally reports
the principals that depend on anything the principal could disrupt.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import math
import re
import urllib.parse
from collections import deque
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

MAP_SCHEMA = "jankhunt.map.v1"
EXPOSURE_MODEL = "jankhunt.exposure.v1"

NODE_KINDS = ("application", "workload", "identity", "database", "api", "storage",
              "queue", "external", "unknown")
PRINCIPAL_KINDS = ("application", "workload")
ASSET_KINDS = ("database", "api", "storage", "queue", "external", "unknown", "workload", "application")
EDGE_KINDS = ("connects", "authenticates-as", "reads", "writes", "deletes", "administers",
              "calls", "publishes", "exports", "depends-on")
CAPABILITIES = ("none", "read", "write", "delete", "admin", "unknown")
CAP_RANK = {"none": 0, "read": 1, "write": 2, "delete": 3, "admin": 4, "unknown": -1}
VERIFICATIONS = ("provider-verified", "observed", "declared", "inferred", "unknown", "refuted")
VER_RANK = {"refuted": -1, "unknown": 0, "inferred": 1, "declared": 2, "observed": 2,
            "provider-verified": 3}
CONFIDENCES = ("low", "medium", "high")
CONF_RANK = {"low": 0, "medium": 1, "high": 2}
SENSITIVITIES = ("public", "internal", "confidential", "restricted", "unknown")
CRITICALITIES = ("low", "medium", "high", "critical", "unknown")
ENVIRONMENTS = ("production", "non-production", "unknown")
TRUST_DOMAINS = ("local", "internal", "external", "unknown")

# Evidence tiers for paths: a path is only as strong as its weakest edge.
TIER_NAMES = {3: "verified", 2: "supported", 1: "inferred", 0: "unknown"}
TIER_BY_NAME = {v: k for k, v in TIER_NAMES.items()}
IMPACTS = ("confidentiality", "integrity", "availability")
EXPOSURE_CLASSES = ("Unknown", "Low", "Moderate", "High", "Critical")
EXPOSURE_RANK = {"Low": 1, "Moderate": 2, "High": 3, "Critical": 4, "Unknown": 0}

MAX_NODES = 5000
MAX_EDGES = 20000
MAX_EVIDENCE = 50000
DEFAULT_DEPTH = 4
MAX_DEPTH = 8


def canonical_json(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha(text: str, n: int = 16) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:n]


# ---------------------------------------------------------------------------
# Sanitizing: applied before hashing, display, logging, or persistence.
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"(?<![A-Za-z])([a-zA-Z][a-zA-Z0-9+.\-]{0,30})://([^\s'\"`<>(){},;\\]+)")
_KV_SECRET_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|access[_-]?key|"
    r"accountkey|sharedaccesskey|sharedaccesssignature|sig|client[_-]?secret|"
    r"user\s*id|uid|username|user)(\s*[=:]\s*)(\"[^\"]*\"|'[^']*'|[^;,\s&\"']+)")
_PRIVATE_KEY_RE = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?(-----END [A-Z ]*PRIVATE KEY-----|$)", re.S)
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}")
_LONG_SECRETISH_RE = re.compile(r"(?<![A-Za-z0-9/+_\-])[A-Za-z0-9+/_\-]{40,}={0,2}(?![A-Za-z0-9/+_\-])")
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")


def _strip_url(match: "re.Match[str]") -> str:
    scheme, rest = match.group(1), match.group(2)
    try:
        parts = urllib.parse.urlsplit("%s://%s" % (scheme, rest))
        host = parts.hostname or ""
        port = ""
        try:
            if parts.port:
                port = ":%d" % parts.port
        except ValueError:
            port = ""
        # Drop the path entirely: path segments routinely carry tokens
        # (webhook URLs, signed paths, embedded credentials). The host is
        # the evidence; the receipt's path:line points at the rest.
        path = "/…" if [x for x in (parts.path or "").split("/") if x] else ""
    except ValueError:
        return "%s://<redacted>" % scheme
    if "@" in rest.split("/")[0] and not host:
        return "%s://<redacted>" % scheme
    out = "%s://%s%s%s" % (scheme.lower(), host, port, path)
    if parts.query:
        out += "?<redacted>"
    return out


def sanitize_text(text: str, limit: int = 200) -> str:
    """Redact credentials from free text (an evidence line, a config value).

    URLs lose userinfo, query, and fragment; key=value credentials lose their
    value; private keys, JWTs, long opaque tokens, and email addresses go too.
    The result is also stripped of control characters and length-capped.
    """
    from jh_core import redact_secrets, safe_text
    out = _PRIVATE_KEY_RE.sub("<redacted-private-key>", safe_text(text))
    out = _URL_RE.sub(_strip_url, out)
    out = _KV_SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", out)
    out = redact_secrets(out)
    out = _JWT_RE.sub("<redacted-token>", out)
    out = _LONG_SECRETISH_RE.sub("<redacted-token>", out)
    out = _EMAIL_RE.sub("<redacted-email>", out)
    out = " ".join(safe_text(out).split())
    if len(out) > limit:
        out = out[: limit - 1] + "…"
    return out


DB_SCHEMES = {
    "postgres": "postgresql", "postgresql": "postgresql", "postgresql+psycopg2": "postgresql",
    "postgresql+psycopg": "postgresql", "postgresql+asyncpg": "postgresql",
    "mysql": "mysql", "mysql+pymysql": "mysql", "mariadb": "mysql",
    "mssql": "sqlserver", "sqlserver": "sqlserver", "mssql+pyodbc": "sqlserver",
    "mongodb": "mongodb", "mongodb+srv": "mongodb",
    "redis": "redis", "rediss": "redis",
    "sqlite": "sqlite", "sqlite3": "sqlite",
    "cassandra": "cassandra", "neo4j": "neo4j", "bolt": "neo4j",
    "clickhouse": "clickhouse", "snowflake": "snowflake", "databricks": "databricks",
    "oracle": "oracle", "oracle+cx_oracle": "oracle", "cockroachdb": "postgresql",
}
QUEUE_SCHEMES = {"amqp": "amqp", "amqps": "amqp", "kafka": "kafka", "nats": "nats",
                 "mqtt": "mqtt", "sb": "servicebus"}
STORAGE_SCHEMES = {"s3": "s3", "gs": "gcs", "abfs": "azure-blob", "abfss": "azure-blob",
                   "wasb": "azure-blob", "wasbs": "azure-blob", "ftp": "ftp", "sftp": "sftp"}
HTTP_SCHEMES = {"http", "https", "ws", "wss"}
DEFAULT_PORTS = {"postgresql": 5432, "mysql": 3306, "sqlserver": 1433, "mongodb": 27017,
                 "redis": 6379, "amqp": 5672, "kafka": 9092, "http": 80, "https": 443}

_SCHEME_ONLY_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9+.\-]{1,30})://(\S*)")
_PLACEHOLDER_RE = re.compile(r"\$\{|\{\{|%\(|<[A-Za-z_]|\$[A-Z_]|%[A-Z_]+%|__[A-Z_]+__")

KNOWN_EXTERNAL = {
    "api.openai.com": ("external", "openai"),
    "api.anthropic.com": ("external", "anthropic"),
    "generativelanguage.googleapis.com": ("external", "google-ai"),
    "api.stripe.com": ("external", "stripe"),
    "api.github.com": ("api", "github"),
    "hooks.slack.com": ("external", "slack"),
    "api.sendgrid.com": ("external", "sendgrid"),
    "api.twilio.com": ("external", "twilio"),
}
_PROD_TOKENS = ("prod", "production", "prd", "live")
_NONPROD_TOKENS = ("dev", "develop", "development", "test", "testing", "staging", "stage",
                   "stg", "qa", "uat", "sandbox", "local", "preview")


def infer_environment(*hints: str) -> str:
    tokens: Set[str] = set()
    for hint in hints:
        if hint:
            tokens.update(t for t in re.split(r"[^a-z0-9]+", hint.lower()) if t)
    if tokens & set(_PROD_TOKENS):
        return "production"
    if tokens & set(_NONPROD_TOKENS):
        return "non-production"
    return "unknown"


def trust_domain_for_host(host: str, engine: str = "") -> str:
    if engine == "sqlite":
        return "local"
    if not host:
        return "unknown"
    host = host.strip("[]").lower()
    if host in ("localhost", "localhost.localdomain") or host.endswith(".localhost"):
        return "local"
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_loopback:
            return "local"
        if ip.is_private or ip.is_link_local:
            return "internal"
        return "external"
    except ValueError:
        ip = None  # not an IP literal: classify it as a hostname below
    if "." not in host:
        return "internal"
    if re.search(r"\.(local|internal|intranet|lan|corp|home|svc|cluster\.local|consul)$", host) \
            or ".svc." in host:
        return "internal"
    if host.endswith((".example", ".test", ".invalid")) or host.endswith(".example.com") \
            or host == "example.com":
        return "external"
    return "external"


def parse_endpoint(raw: str) -> Optional[Dict[str, Any]]:
    """Parse a URL or .NET-style connection string into a sanitized endpoint.

    Returns None when nothing endpoint-like is present. Never returns
    credentials, query strings, or fragments. A value with a template
    placeholder in the host is reported as unresolved (no invented host).
    """
    raw = raw.strip().strip("\"'`")
    if not raw:
        return None
    sm = _SCHEME_ONLY_RE.search(raw)
    if sm and _PLACEHOLDER_RE.match(sm.group(2)):
        scheme = sm.group(1).lower()
        fam = (("database", DB_SCHEMES[scheme]) if scheme in DB_SCHEMES else
               ("queue", QUEUE_SCHEMES[scheme]) if scheme in QUEUE_SCHEMES else
               ("storage", STORAGE_SCHEMES[scheme]) if scheme in STORAGE_SCHEMES else
               ("api", "https") if scheme in HTTP_SCHEMES else None)
        if fam:
            return {"kind": fam[0], "engine": fam[1], "host": "", "port": None, "path": "",
                    "resolved": False, "scheme": scheme}
    m = _URL_RE.search(raw)
    if m:
        scheme = m.group(1).lower()
        engine = DB_SCHEMES.get(scheme)
        kind = "database" if engine else None
        if not kind and scheme in QUEUE_SCHEMES:
            kind, engine = "queue", QUEUE_SCHEMES[scheme]
        if not kind and scheme in STORAGE_SCHEMES:
            kind, engine = "storage", STORAGE_SCHEMES[scheme]
        if not kind and scheme in HTTP_SCHEMES:
            kind, engine = "api", scheme.replace("wss", "https").replace("ws", "http")
        if not kind:
            return None
        rest = m.group(2)
        tail = raw[m.start(2):].split()[0] if raw[m.start(2):].split() else ""
        hostpart = tail.split("/")[0].split("@")[-1]
        if _PLACEHOLDER_RE.search(hostpart) or not re.match(r"^\[?[A-Za-z0-9._\-:\]]+$", hostpart or "x"):
            return {"kind": kind, "engine": engine, "host": "", "port": None, "path": "",
                    "resolved": False, "scheme": scheme}
        try:
            parts = urllib.parse.urlsplit("%s://%s" % (scheme, rest))
            host = (parts.hostname or "").lower()
            port = parts.port
        except ValueError:
            host, port = "", None
            parts = None
        path = ""
        if parts is not None and parts.path and engine != "sqlite":
            seg = [p for p in parts.path.split("/") if p]
            path = seg[0] if seg else ""
            if _PLACEHOLDER_RE.search(path):
                path = ""
        if engine == "sqlite":
            return {"kind": "database", "engine": "sqlite", "host": "", "port": None,
                    "path": "local file", "resolved": True, "scheme": scheme}
        if port and DEFAULT_PORTS.get(engine) == port:
            port = None
        if kind == "api":
            known = KNOWN_EXTERNAL.get(host)
            if known:
                kind, engine = known
            elif trust_domain_for_host(host) == "external":
                kind = "external"
        return {"kind": kind, "engine": engine, "host": host, "port": port,
                "path": path if kind in ("database", "storage", "queue") else "",
                "resolved": bool(host), "scheme": scheme}
    # .NET / ODBC connection strings: Server=...;Database=...;Password=...
    if ";" in raw and "=" in raw:
        fields: Dict[str, str] = {}
        for part in raw.split(";"):
            if "=" in part:
                k, v = part.split("=", 1)
                fields[k.strip().lower()] = v.strip()
        host = fields.get("server") or fields.get("data source") or fields.get("host") \
            or fields.get("address") or fields.get("addr")
        account = fields.get("accountname")
        endpoint = fields.get("endpoint")
        if account or "defaultendpointsprotocol" in fields:
            return {"kind": "storage", "engine": "azure-storage",
                    "host": ("%s.blob" % account.lower()) if account else "", "port": None,
                    "path": "", "resolved": bool(account), "scheme": "azure-storage"}
        if endpoint and "sharedaccesskeyname" in fields:
            ep = parse_endpoint(endpoint) or {}
            return {"kind": "queue", "engine": "servicebus", "host": ep.get("host", ""),
                    "port": None, "path": "", "resolved": bool(ep.get("host")),
                    "scheme": "servicebus"}
        if host:
            host = host.split(",")[0]
            if host.lower().startswith("tcp:"):
                host = host[4:]
            engine = "postgresql" if "host" in fields and "server" not in fields else "sqlserver"
            if "data source" in fields and fields["data source"].lower().endswith(".db"):
                engine = "sqlite"
            if _PLACEHOLDER_RE.search(host):
                return {"kind": "database", "engine": engine, "host": "", "port": None,
                        "path": "", "resolved": False, "scheme": engine}
            db = fields.get("database") or fields.get("initial catalog") or ""
            if _PLACEHOLDER_RE.search(db):
                db = ""
            if engine == "sqlite":
                return {"kind": "database", "engine": "sqlite", "host": "", "port": None,
                        "path": "local file", "resolved": True, "scheme": "sqlite"}
            return {"kind": "database", "engine": engine, "host": host.lower().strip("[]"),
                    "port": None, "path": db, "resolved": True, "scheme": engine}
    return None


def endpoint_label(ep: Dict[str, Any]) -> str:
    if not ep.get("resolved"):
        return "%s (unresolved target)" % ep.get("engine", "endpoint")
    if ep.get("engine") == "sqlite":
        return "sqlite (local file)"
    host = ep.get("host", "")
    if ep.get("port"):
        host += ":%s" % ep["port"]
    label = "%s %s" % (ep.get("engine", ep.get("kind")), host)
    if ep.get("path"):
        label += "/" + ep["path"]
    return sanitize_text(label, 120)


# ---------------------------------------------------------------------------
# Graph container
# ---------------------------------------------------------------------------

class Graph:
    """Typed directed multigraph with merged, deduplicated evidence.

    Adding the same logical node or edge twice merges evidence references;
    it never creates a second asset or inflates any count.
    """

    def __init__(self, snapshot: str = "working-tree") -> None:
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: Dict[str, Dict[str, Any]] = {}
        self.evidence: Dict[str, Dict[str, Any]] = {}
        self.snapshot = snapshot
        self.truncated: List[str] = []

    # -- evidence ----------------------------------------------------------
    def add_evidence(self, path: str, line: int, adapter: str, snippet: str, state: str,
                     assumptions: Sequence[str] = (), counterevidence: Sequence[str] = ()) -> Optional[str]:
        from jh_core import safe_text
        clean = sanitize_text(snippet, 160)
        path = safe_text(path).replace("\\", "/")
        key = canonical_json([path, int(line), adapter, clean])
        eid = "ev:" + sha(key)
        if eid in self.evidence:
            return eid
        if len(self.evidence) >= MAX_EVIDENCE:
            self._truncate("evidence limit %d reached" % MAX_EVIDENCE)
            return None
        self.evidence[eid] = {
            "id": eid,
            "path": path,
            "line": int(line),
            "adapter": adapter,
            "snippet": clean,
            "hash": hashlib.sha256(key.encode("utf-8")).hexdigest(),
            "state": state,
            "source_snapshot": self.snapshot,
            "assumptions": sorted(set(assumptions)),
            "counterevidence": sorted(set(counterevidence)),
        }
        return eid

    def _truncate(self, reason: str) -> None:
        if reason not in self.truncated:
            self.truncated.append(reason)

    # -- nodes -------------------------------------------------------------
    def add_node(self, kind: str, key: Sequence[Any], label: str, *,
                 trust_domain: str = "unknown", environment: str = "unknown",
                 sensitivity: str = "unknown", criticality: str = "unknown",
                 attributes: Optional[Dict[str, Any]] = None,
                 evidence: Optional[str] = None) -> Optional[str]:
        if kind not in NODE_KINDS:
            raise ValueError("unknown node kind %r" % kind)
        nid = "%s:%s" % (kind, sha(canonical_json([kind] + [str(k) for k in key])))
        node = self.nodes.get(nid)
        if node is None:
            if len(self.nodes) >= MAX_NODES:
                self._truncate("node limit %d reached" % MAX_NODES)
                return None
            node = {
                "id": nid, "kind": kind, "display_label": sanitize_text(label, 120),
                "trust_domain": trust_domain, "environment": environment,
                "sensitivity": sensitivity, "criticality": criticality,
                "attributes": {}, "evidence_refs": [],
                "classification_source": "default-unknown",
            }
            self.nodes[nid] = node
        for k, v in (attributes or {}).items():
            if isinstance(v, list):
                merged = sorted(set(node["attributes"].get(k, [])) | set(v))
                node["attributes"][k] = merged[:50]
            elif k not in node["attributes"]:
                node["attributes"][k] = v
        if node["environment"] == "unknown" and environment != "unknown":
            node["environment"] = environment
        if node["trust_domain"] == "unknown" and trust_domain != "unknown":
            node["trust_domain"] = trust_domain
        if evidence and evidence not in node["evidence_refs"]:
            node["evidence_refs"].append(evidence)
        return nid

    # -- edges -------------------------------------------------------------
    def add_edge(self, source: Optional[str], target: Optional[str], kind: str, capability: str,
                 verification: str, confidence: str, *, evidence: Optional[str] = None,
                 identity: Optional[str] = None, source_trust: str = "repository",
                 assumptions: Sequence[str] = ()) -> Optional[str]:
        if not source or not target:
            return None
        if kind not in EDGE_KINDS or capability not in CAPABILITIES or verification not in VERIFICATIONS:
            raise ValueError("invalid edge %r/%r/%r" % (kind, capability, verification))
        eid = "e:" + sha(canonical_json([source, target, kind, capability, identity or ""]))
        edge = self.edges.get(eid)
        if edge is None:
            if len(self.edges) >= MAX_EDGES:
                self._truncate("edge limit %d reached" % MAX_EDGES)
                return None
            edge = {
                "id": eid, "source": source, "target": target, "kind": kind,
                "capability": capability, "identity_ref": identity,
                "verification": verification, "confidence": confidence,
                "source_trust": source_trust, "evidence_refs": [],
                "assumptions": [],
            }
            self.edges[eid] = edge
        else:
            # Strongest claim wins; refuted only replaces when nothing else supports it.
            if VER_RANK[verification] > VER_RANK[edge["verification"]]:
                edge["verification"] = verification
                edge["source_trust"] = source_trust
            if CONF_RANK[confidence] > CONF_RANK[edge["confidence"]]:
                edge["confidence"] = confidence
        if evidence and evidence not in edge["evidence_refs"]:
            edge["evidence_refs"].append(evidence)
        for a in assumptions:
            if a not in edge["assumptions"]:
                edge["assumptions"].append(a)
        return eid

    # -- output ------------------------------------------------------------
    def finalize(self) -> None:
        """Annotate trust-boundary crossings and sort every list."""
        for edge in self.edges.values():
            s = self.nodes[edge["source"]]
            t = self.nodes[edge["target"]]
            crossing = None
            if s["trust_domain"] != t["trust_domain"] and "unknown" not in (s["trust_domain"], t["trust_domain"]):
                crossing = "%s->%s" % (s["trust_domain"], t["trust_domain"])
            env = None
            if s["environment"] != t["environment"] and "unknown" not in (s["environment"], t["environment"]):
                env = "%s->%s" % (s["environment"], t["environment"])
            edge["trust_boundary"] = {"domain": crossing, "environment": env}
            edge["evidence_refs"].sort()
            edge["assumptions"].sort()
        for node in self.nodes.values():
            node["evidence_refs"].sort()

    def node_list(self) -> List[Dict[str, Any]]:
        return [self.nodes[k] for k in sorted(self.nodes)]

    def edge_list(self) -> List[Dict[str, Any]]:
        return [self.edges[k] for k in sorted(self.edges)]

    def evidence_list(self) -> List[Dict[str, Any]]:
        return [self.evidence[k] for k in sorted(self.evidence)]


# ---------------------------------------------------------------------------
# Reachability
# ---------------------------------------------------------------------------

def edge_tier(edge: Dict[str, Any], impact: str) -> Optional[int]:
    """Tier at which `edge` is admissible for `impact`, or None.

    The table is deliberately small and explicit. Generic `connects`/`calls`
    with unknown capability is admissible for every impact, but only as a
    potential (at most `inferred`) step: unknown is never read-only and never
    verified write authority.
    """
    ver = edge.get("verification", "unknown")
    if ver == "refuted":
        return None
    base = VER_RANK.get(ver, 0)
    kind = edge.get("kind")
    cap = edge.get("capability", "unknown")
    if kind == "authenticates-as":
        return base
    if kind == "depends-on":
        return None  # availability dependents only; never authority
    if cap == "unknown":
        if kind in ("connects", "calls"):
            return min(base, 1)
        if impact == "confidentiality" and kind in ("exports", "publishes"):
            return min(base, 1)
        return None
    if impact == "confidentiality":
        # A call carries data both ways; a write-capable call is a possible egress.
        if cap in ("read", "admin") or kind in ("exports", "publishes", "calls"):
            return base
        return None
    if impact == "integrity":
        return base if cap in ("write", "delete", "admin") else None
    if impact == "availability":
        return base if cap in ("delete", "admin") else None
    return None


def _adjacency(edges: Iterable[Dict[str, Any]], impact: str) -> Dict[str, List[Tuple[str, str, int]]]:
    adj: Dict[str, List[Tuple[str, str, int]]] = {}
    for e in edges:
        t = edge_tier(e, impact)
        if t is None:
            continue
        adj.setdefault(e["source"], []).append((e["target"], e["id"], t))
    for k in adj:
        adj[k].sort(key=lambda x: (x[0], x[1]))
    return adj


def reach(edges: Sequence[Dict[str, Any]], source: str, impact: str,
          max_depth: int = DEFAULT_DEPTH) -> Tuple[Dict[str, Dict[str, Any]], bool]:
    """Bounded reachability from `source` for one impact.

    Returns ({node_id: {"tier": int, "path": [edge ids], "depth": n}}, truncated).
    A node's tier is the best (max over paths) of the weakest edge on the
    path (min over edges), within max_depth hops. Each node appears once,
    however many routes reach it. Cycles terminate because each tier pass is
    a plain BFS with a visited set.
    """
    adj = _adjacency(edges, impact)
    result: Dict[str, Dict[str, Any]] = {}
    truncated = False
    for tier in (3, 2, 1, 0):
        seen = {source: []}
        q = deque([(source, 0)])
        while q:
            node, depth = q.popleft()
            for tgt, eid, t in adj.get(node, ()):
                if t < tier or tgt in seen:
                    continue
                if depth >= max_depth:
                    truncated = True
                    continue
                seen[tgt] = seen[node] + [eid]
                q.append((tgt, depth + 1))
        for nid, path in seen.items():
            if nid == source or nid in result:
                continue
            result[nid] = {"tier": tier, "path": path, "depth": len(path)}
    return result, truncated


def dependents(edges: Sequence[Dict[str, Any]], targets: Set[str], exclude: str) -> Dict[str, Dict[str, Any]]:
    """Principals or services that directly use any node in `targets`
    (one reverse hop). They lose availability if those targets are disrupted."""
    out: Dict[str, Dict[str, Any]] = {}
    for e in sorted(edges, key=lambda x: x["id"]):
        if e["target"] in targets and e["source"] != exclude and e.get("verification") != "refuted" \
                and e["kind"] != "authenticates-as":
            prev = out.get(e["source"])
            t = VER_RANK.get(e["verification"], 0)
            if prev is None or t > prev["tier"]:
                out[e["source"]] = {"tier": t, "via": e["id"], "target": e["target"]}
    return out


def blast_radius(graph_nodes: Dict[str, Dict[str, Any]], edges: Sequence[Dict[str, Any]],
                 principal: str, max_depth: int = DEFAULT_DEPTH) -> Dict[str, Any]:
    impacts: Dict[str, Any] = {}
    truncated = False
    for impact in IMPACTS:
        r, trunc = reach(edges, principal, impact, max_depth)
        truncated = truncated or trunc
        impacts[impact] = {nid: info for nid, info in sorted(r.items())}
    disrupted = {nid for nid in impacts["availability"]}
    deps = dependents(edges, disrupted, principal) if disrupted else {}
    crossings: Set[str] = set()
    domains: Set[str] = set()
    edge_by_id = {e["id"]: e for e in edges}
    for impact in IMPACTS:
        for info in impacts[impact].values():
            for eid in info["path"]:
                tb = edge_by_id[eid].get("trust_boundary") or {}
                if tb.get("domain"):
                    crossings.add(tb["domain"])
                if tb.get("environment"):
                    crossings.add("env:" + tb["environment"])
    for impact in IMPACTS:
        for nid in impacts[impact]:
            node = graph_nodes.get(nid, {})
            if node.get("kind") not in ("identity",) and node.get("trust_domain") not in (None, "unknown"):
                domains.add("%s/%s" % (node["trust_domain"], node.get("environment", "unknown")))
    return {
        "principal": principal,
        "max_depth": max_depth,
        "truncated": truncated,
        "impacts": impacts,
        "availability_dependents": {k: deps[k] for k in sorted(deps)},
        "trust_boundary_crossings": sorted(crossings),
        "distinct_trust_domains": sorted(domains),
    }


def breadth_indicator(n: int, alpha: float = 0.5, tau: float = 4.0) -> float:
    """Saturating complexity indicator 1 + alpha*(1 - exp(-max(0, n-1)/tau)).

    Informational only: shown next to the exposure class, never used to
    block a release and never able to lower a class.
    """
    return round(1.0 + alpha * (1.0 - math.exp(-max(0, n - 1) / tau)), 3)


# ---------------------------------------------------------------------------
# Exposure classification (qualitative, monotone by construction)
# ---------------------------------------------------------------------------

def _sens_high(node: Dict[str, Any]) -> bool:
    return node.get("sensitivity") in ("confidential", "restricted")


def _crit_high(node: Dict[str, Any]) -> bool:
    return node.get("criticality") in ("high", "critical") or node.get("environment") == "production"


def _crit_top(node: Dict[str, Any]) -> bool:
    return node.get("criticality") == "critical" or node.get("sensitivity") == "restricted"


def classify_principal(nodes: Dict[str, Dict[str, Any]], br: Dict[str, Any],
                       edges_by_id: Dict[str, Dict[str, Any]]) -> Tuple[str, List[Dict[str, Any]]]:
    """Return (class, drivers) for one principal's blast radius.

    Every condition is upward-closed in tier, capability, sensitivity,
    criticality, and reach, so adding evidence or authority can never lower
    the class. Unknown sensitivity or capability is never treated as safe:
    it lands in Moderate, not Low.
    """
    drivers: List[Dict[str, Any]] = []
    level = 1

    def bump(new_level: int, rule: str, nid: str, info: Dict[str, Any], impact: str, why: str) -> None:
        nonlocal level
        drivers.append({"level": EXPOSURE_CLASSES[new_level], "rule": rule, "node": nid,
                        "impact": impact, "tier": TIER_NAMES[info["tier"]],
                        "path": list(info["path"]), "why": why})
        level = max(level, new_level)

    imp = br["impacts"]
    for impact in ("integrity", "availability"):
        for nid, info in imp[impact].items():
            node = nodes[nid]
            if node["kind"] == "identity":
                continue
            if info["tier"] == 3 and _crit_top(node):
                bump(4, "X-CRIT-AUTH", nid, info, impact,
                     "verified mutating/destructive authority over a critical or restricted asset")
            elif _crit_high(node) or _sens_high(node):
                bump(3, "X-HIGH-AUTH", nid, info, impact,
                     "possible mutating/destructive authority over a production, critical, or sensitive asset")
            elif node["trust_domain"] != "local":
                bump(2, "X-MOD-AUTH", nid, info, impact,
                     "possible mutating authority over a non-local asset (capability or classification not established)")
    sensitive_c = {nid: info for nid, info in imp["confidentiality"].items()
                   if _sens_high(nodes[nid]) and nodes[nid]["kind"] != "identity"}
    external_c = {nid: info for nid, info in imp["confidentiality"].items()
                  if nodes[nid]["trust_domain"] == "external" and nodes[nid]["kind"] != "identity"}
    for nid, info in imp["confidentiality"].items():
        node = nodes[nid]
        if node["kind"] == "identity":
            continue
        if node.get("sensitivity") == "restricted" and info["tier"] >= 2:
            bump(3, "X-HIGH-READ", nid, info, "confidentiality",
                 "supported read reach to restricted data")
        elif node["trust_domain"] != "local":
            bump(2, "X-MOD-REACH", nid, info, "confidentiality",
                 "possible read or data-transfer reach to a non-local system")
    if sensitive_c and external_c:
        s_id = sorted(sensitive_c)[0]
        x_id = sorted(external_c)[0]
        bump(3, "X-HIGH-EGRESS", s_id, sensitive_c[s_id], "confidentiality",
             "sensitive source and external destination are reachable from the same principal "
             "(possible egress path; no data-flow evidence implied)")
        drivers[-1]["external"] = x_id
    # Verified export of sensitive data to an external destination.
    for nid, info in imp["confidentiality"].items():
        if not info["path"]:
            continue
        last = edges_by_id[info["path"][-1]]
        if last["kind"] == "exports" and nodes[nid]["trust_domain"] == "external" \
                and info["tier"] == 3 and (last.get("data_sensitivity") in ("confidential", "restricted")):
            bump(4, "X-CRIT-EGRESS", nid, info, "confidentiality",
                 "verified export of sensitive data to an external destination")
    drivers.sort(key=lambda d: (-EXPOSURE_RANK[d["level"]], d["rule"], d["node"]))
    return EXPOSURE_CLASSES[level], drivers


def assess(graph: Dict[str, Any], files_inspected: int, max_depth: int = DEFAULT_DEPTH) -> Dict[str, Any]:
    """Blast radius for every principal plus the overall exposure class."""
    nodes = {n["id"]: n for n in graph["nodes"]}
    edges = graph["edges"]
    edges_by_id = {e["id"]: e for e in edges}
    principals = sorted(n["id"] for n in graph["nodes"] if n["kind"] in PRINCIPAL_KINDS)
    radii: Dict[str, Any] = {}
    per: Dict[str, Any] = {}
    overall = "Low"
    truncated = False
    all_domains: Set[str] = set()
    for p in principals:
        br = blast_radius(nodes, edges, p, max_depth)
        cls, drivers = classify_principal(nodes, br, edges_by_id)
        br["exposure"] = cls
        br["drivers"] = drivers[:25]
        radii[p] = br
        truncated = truncated or br["truncated"]
        all_domains.update(br["distinct_trust_domains"])
        per[p] = cls
        if EXPOSURE_RANK[cls] > EXPOSURE_RANK[overall]:
            overall = cls
    if files_inspected <= 0:
        overall = "Unknown"
    tiers: Dict[str, int] = {name: 0 for name in TIER_NAMES.values()}
    for e in edges:
        tiers[TIER_NAMES[max(0, VER_RANK.get(e["verification"], 0))]] += 0 if e["verification"] == "refuted" else 1
    unknown_caps = sum(1 for e in edges if e["capability"] == "unknown" and e["kind"] in ("connects", "calls"))
    return {
        "model": EXPOSURE_MODEL,
        "exposure": {
            "class": overall,
            "per_principal": per,
            "basis": ("qualitative rules over static evidence; a path is a possibility, "
                      "not proof of access or exploitability"),
        },
        "evidence_tiers": tiers,
        "unknown_capability_edges": unknown_caps,
        "breadth": {"distinct_trust_domains": len(all_domains),
                    "indicator": breadth_indicator(len(all_domains)),
                    "note": "saturating complexity indicator; informational, never blocks"},
        "truncated_reachability": truncated,
        "blast_radius": radii,
    }


# ---------------------------------------------------------------------------
# Graph diff
# ---------------------------------------------------------------------------

def _perm_key(e: Dict[str, Any]) -> Tuple[str, str, str]:
    return (e["source"], e["target"], e.get("identity_ref") or "")


def diff(base: Dict[str, Any], head: Dict[str, Any]) -> Dict[str, Any]:
    """Compare two map reports (graph + assessment) by stable IDs."""
    bn = {n["id"]: n for n in base["graph"]["nodes"]}
    hn = {n["id"]: n for n in head["graph"]["nodes"]}
    be = {e["id"]: e for e in base["graph"]["edges"]}
    he = {e["id"]: e for e in head["graph"]["edges"]}
    head_paths = set(head.get("coverage", {}).get("inspected_paths", []))
    base_ev = {ev["id"]: ev for ev in base.get("evidence", [])}

    def removal_state(refs: Sequence[str]) -> str:
        paths = {base_ev[r]["path"] for r in refs if r in base_ev}
        if paths and not (paths & head_paths) and any(p in head.get("coverage", {}).get("skipped_paths", []) for p in paths):
            return "not-observed"
        return "removed"

    added_nodes = sorted(set(hn) - set(bn))
    removed_nodes = [{"id": n, "state": removal_state(bn[n]["evidence_refs"])} for n in sorted(set(bn) - set(hn))]
    added_edges = sorted(set(he) - set(be))
    removed_edges = [{"id": e, "state": removal_state(be[e]["evidence_refs"])} for e in sorted(set(be) - set(he))]

    def caps(edges: Dict[str, Dict[str, Any]]) -> Dict[Tuple[str, str, str], Dict[str, str]]:
        out: Dict[Tuple[str, str, str], Dict[str, str]] = {}
        for e in edges.values():
            if e["verification"] == "refuted":
                continue
            out.setdefault(_perm_key(e), {})[e["capability"]] = e["verification"]
        return out

    bc, hc = caps(be), caps(he)
    escalations = []
    reductions = []
    for key in sorted(set(bc) | set(hc)):
        before = bc.get(key, {})
        after = hc.get(key, {})
        bmax = max((CAP_RANK[c] for c in before), default=-2)
        amax = max((CAP_RANK[c] for c in after), default=-2)
        new_caps = sorted(set(after) - set(before))
        if not before:
            continue
        if amax > bmax or (new_caps and amax >= bmax and any(CAP_RANK[c] > bmax for c in new_caps)):
            escalations.append({"source": key[0], "target": key[1], "identity_ref": key[2] or None,
                                "before": sorted(before), "after": sorted(after)})
        elif after and amax < bmax:
            reductions.append({"source": key[0], "target": key[1], "identity_ref": key[2] or None,
                               "before": sorted(before), "after": sorted(after)})
    # Newly reachable assets per principal and impact.
    newly: List[Dict[str, Any]] = []
    br_b = base.get("assessment", {}).get("blast_radius", {})
    br_h = head.get("assessment", {}).get("blast_radius", {})
    for p in sorted(br_h):
        for impact in IMPACTS:
            hset = br_h[p]["impacts"][impact]
            bset = br_b.get(p, {}).get("impacts", {}).get(impact, {})
            for nid in sorted(set(hset) - set(bset)):
                node = hn.get(nid, {})
                newly.append({"principal": p, "impact": impact, "node": nid,
                              "tier": TIER_NAMES[hset[nid]["tier"]], "path": hset[nid]["path"],
                              "sensitive": _sens_high(node) or _crit_high(node)})
            for nid in sorted(set(bset) & set(hset)):
                if hset[nid]["tier"] > bset[nid]["tier"]:
                    newly.append({"principal": p, "impact": impact, "node": nid,
                                  "tier": TIER_NAMES[hset[nid]["tier"]], "path": hset[nid]["path"],
                                  "sensitive": _sens_high(hn.get(nid, {})) or _crit_high(hn.get(nid, {})),
                                  "change": "stronger evidence"})

    def crossings(rep: Dict[str, Any]) -> Set[str]:
        out = set()
        for e in rep["graph"]["edges"]:
            tb = e.get("trust_boundary") or {}
            if tb.get("domain"):
                out.add(tb["domain"])
            if tb.get("environment"):
                out.add("env:" + tb["environment"])
        return out

    bx, hx = crossings(base), crossings(head)
    b_cls = base.get("assessment", {}).get("exposure", {}).get("class", "Unknown")
    h_cls = head.get("assessment", {}).get("exposure", {}).get("class", "Unknown")
    b_cov = base.get("coverage", {}).get("files_inspected", 0)
    h_cov = head.get("coverage", {}).get("files_inspected", 0)
    return {
        "base": base.get("scope", {}).get("snapshot"),
        "head": head.get("scope", {}).get("snapshot"),
        "nodes": {"added": added_nodes, "removed": removed_nodes},
        "edges": {"added": added_edges, "removed": removed_edges},
        "permission_escalations": escalations,
        "permission_reductions": reductions,
        "newly_reachable": newly,
        "newly_reachable_sensitive": [n for n in newly if n["sensitive"]],
        "trust_boundaries": {"added": sorted(hx - bx), "removed": sorted(bx - hx)},
        "exposure": {"base": b_cls, "head": h_cls,
                     "changed": b_cls != h_cls},
        "coverage": {"base_files_inspected": b_cov, "head_files_inspected": h_cov,
                     "regressed": h_cov < b_cov},
        "note": "a removed edge is 'not-observed' when its evidence file was skipped on the head side, "
                "which is not the same as the connection having been removed",
    }


# ---------------------------------------------------------------------------
# Shareable redaction
# ---------------------------------------------------------------------------

def pseudonymize(report: Dict[str, Any]) -> Dict[str, Any]:
    """Return a deep-copied report safe to share outside the team.

    Node and edge IDs become ordinal aliases, labels lose hostnames and
    database names, evidence keeps only path/line/adapter (no snippets), and
    attributes that could reveal topology are dropped. The mapping is
    deterministic for a given graph.
    """
    rep = json.loads(json.dumps(report))
    nodes = rep["graph"]["nodes"]
    counters: Dict[str, int] = {}
    alias: Dict[str, str] = {}
    for n in sorted(nodes, key=lambda x: x["id"]):
        counters[n["kind"]] = counters.get(n["kind"], 0) + 1
        alias[n["id"]] = "%s-%d" % (n["kind"], counters[n["kind"]])
    edge_alias = {e["id"]: "edge-%d" % i for i, e in enumerate(sorted(rep["graph"]["edges"], key=lambda x: x["id"]), 1)}
    ev_alias = {ev["id"]: "evidence-%d" % i for i, ev in enumerate(sorted(rep.get("evidence", []), key=lambda x: x["id"]), 1)}

    def sub(value: Any) -> Any:
        if isinstance(value, str):
            return alias.get(value) or edge_alias.get(value) or ev_alias.get(value) or value
        if isinstance(value, list):
            return [sub(v) for v in value]
        if isinstance(value, dict):
            return {alias.get(k, edge_alias.get(k, k)): sub(v) for k, v in value.items()}
        return value

    for n in nodes:
        engine = n.get("attributes", {}).get("engine", "")
        n["display_label"] = "%s %s" % (engine or n["kind"], alias[n["id"]].split("-")[-1])
        n["attributes"] = {k: v for k, v in n.get("attributes", {}).items() if k in ("engine",)}
    for ev in rep.get("evidence", []):
        ev["snippet"] = ""
        ev["hash"] = ""
    rep = sub(rep)
    rep["scope"]["redaction"] = "share"
    rep["scope"]["root"] = "."
    rep["scope"]["name"] = "application"
    return rep
