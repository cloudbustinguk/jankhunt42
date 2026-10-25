#!/usr/bin/env python3
"""Declared egress boundary versus observed reach.

A boundary is a structured network allowlist committed with the repository:
Codex network-proxy domains and permission profiles, Claude Code sandbox
allowedDomains/deniedDomains, and OpenShell network policy endpoints. It is
compared with the hosts the connectivity map shows the code and its agent
tooling reaching:

  * outside: a reached host no boundary allows (or one it denies);
  * unused: an allowed entry nothing in the map reaches (tooling such as
    package registries may still need it, so this is informational);
  * wildcard: an entry that admits many hosts.

With no boundary declared the result is `unknown`, never "open" or "closed".
A declared boundary is what the configuration says; whether the sandbox
enforces it at runtime is not verified here.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import jh_agent
import jh_yaml
from jh_core import _looks_like_sandbox_policy as looks_like_sandbox_policy

TIER = {3: "verified", 2: "supported", 1: "inferred", 0: "unknown"}


def _strip_toml_comment(line: str) -> str:
    """The line without a `#` comment that is outside quotes."""
    quote, k = None, 0
    while k < len(line):
        ch = line[k]
        if quote:
            if ch == "\\" and quote == '"':
                k += 2                      # the escaped character cannot close the string
                continue
            if ch == quote:
                quote = None
        elif ch in "\"'":
            quote = ch
        elif ch == "#":
            return line[:k]
        k += 1
    return line


def _toml_tables(text: str) -> List[Tuple[int, str, str, str]]:
    section, out = "", []
    for i, line in enumerate(text.split("\n"), 1):
        line = _strip_toml_comment(line)
        m = re.match(r"^\s*\[\s*([^\]]+?)\s*\]\s*$", line)
        if m:
            section = m.group(1).replace('"', "").replace("'", "")
            continue
        m = re.match(r"""^\s*("[^"]*"|'[^']*'|[\w.\-*]+)\s*=\s*(.+?)\s*$""", line)
        if m:
            out.append((i, section, m.group(1).strip("\"'"), m.group(2).strip()))
    return out


def _codex(rel: str, text: str) -> List[Dict[str, Any]]:
    allow: List[str] = []
    deny: List[str] = []
    line0, enabled, open_net = 0, None, False
    for line, section, key, value in _toml_tables(text):
        v = value.strip("\"'").lower()
        if (section.endswith("network_proxy.domains") or re.search(r"(?:^|\.)network\.domains$", section)) and v in ("allow", "deny"):
            (allow if v == "allow" else deny).append(key)
            line0 = line0 or line
        elif section.endswith("network_proxy") and key == "enabled":
            enabled = v == "true"
        elif section == "sandbox_workspace_write" and key == "network_access" and v == "true":
            open_net, line0 = True, line0 or line
        elif re.match(r"^permissions\.[^.]+\.network$", section) and key == "mode" and v == "full":
            open_net, line0 = True, line0 or line
    if not (allow or deny or open_net):
        return []
    note = "domain rules are not enforced while features.network_proxy.enabled is false" if allow and enabled is not True \
        else ""
    return [{"tool": "codex", "path": rel, "line": line0, "allow": sorted(set(allow)), "deny": sorted(set(deny)),
             "open": open_net and not allow, "note": note}]


def _claude(rel: str, text: str) -> List[Dict[str, Any]]:
    try:
        data = jh_agent.loads_jsonc(text)
    except ValueError:
        return []
    box = data.get("sandbox") if isinstance(data, dict) else None
    if not isinstance(box, dict):
        return []
    net = box.get("network") if isinstance(box.get("network"), dict) else {}
    allow = [str(d) for d in net.get("allowedDomains") or [] if isinstance(d, str)]
    deny = [str(d) for d in net.get("deniedDomains") or [] if isinstance(d, str)]
    if not (allow or deny):
        return []
    line = next((i for i, ln in enumerate(text.split("\n"), 1) if "allowedDomains" in ln or "deniedDomains" in ln), 1)
    return [{"tool": "claude-code", "path": rel, "line": line, "allow": sorted(set(allow)), "deny": sorted(set(deny)),
             "open": False, "note": "" if box.get("enabled") is True else
             "sandbox.enabled is not true in this file; the allowlist applies only when the sandbox is on"}]


def _openshell(rel: str, text: str) -> List[Dict[str, Any]]:
    try:
        docs = [jh_agent.loads_jsonc(text)] if text.lstrip().startswith("{") else jh_yaml.load_all(text)
    except (jh_yaml.YamlError, ValueError):
        return []
    out = []
    for doc in docs:
        pols = doc.get("network_policies") if isinstance(doc, dict) and isinstance(doc.get("network_policies"), dict) else {}
        allow = []
        for pol in pols.values():
            for ep in (pol or {}).get("endpoints") or [] if isinstance(pol, dict) else []:
                if isinstance(ep, dict):
                    if ep.get("host"):
                        allow.append(str(ep["host"]))
                    for ip in ep.get("allowed_ips") or []:
                        allow.append(str(ip))
        line = next((i for i, ln in enumerate(text.split("\n"), 1) if "network_policies" in ln), 1)
        out.append({"tool": "openshell", "path": rel, "line": line, "allow": sorted(set(allow)), "deny": [],
                    "open": False, "note": "default deny: only the listed endpoints are reachable"})
    return out


def boundaries(items: Sequence[Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for item in items:
        posix = "/" + item.rel.lower()
        try:
            if posix.endswith(".codex/config.toml"):
                out += _codex(item.rel, item.text)
            elif "/.claude/settings" in posix and posix.endswith(".json"):
                out += _claude(item.rel, item.text)
            elif posix.endswith((".yaml", ".yml", ".json")) and looks_like_sandbox_policy(item.text):
                out += _openshell(item.rel, item.text)
        except (RecursionError, ValueError, TypeError, AttributeError):
            continue                    # a malformed or hostile file is not a boundary
    return sorted(out, key=lambda b: (b["path"], b["line"]))


def matches(host: str, pattern: str) -> bool:
    """Host pattern semantics shared by the three tools, read permissively:
    exact name, `*.d` and `**.d` for subdomains (`**.d` also the apex), `*`
    for everything. Ports are ignored."""
    h = host.lower().rstrip(".")
    p = pattern.lower().strip().split(":")[0].rstrip(".")
    if p in ("*", "**"):
        return True
    if p.startswith("**."):
        return h == p[3:] or h.endswith(p[2:])
    if p.startswith("*."):
        return h.endswith(p[1:])
    if "*" in p:
        return bool(re.fullmatch(re.escape(p).replace(r"\*", "[^.]*"), h))
    return h == p


def _wild(pattern: str) -> bool:
    return "*" in pattern or pattern.strip() in ("0.0.0.0/0", "::/0")


def compare(bounds: Sequence[Dict[str, Any]], report: Dict[str, Any]) -> Dict[str, Any]:
    if not bounds:
        return {"state": "unknown", "boundaries": [], "outside": [], "unused": [], "wildcards": [],
                "note": "no structured egress allowlist is committed; the reachable network is unknown, not open"}
    nodes = {n["id"]: n for n in report["graph"]["nodes"]}
    radii = report["assessment"].get("blast_radius", {})
    reached: Dict[str, Dict[str, Any]] = {}
    for principal, br in radii.items():
        for impact in br["impacts"].values():
            for nid, info in impact.items():
                n = nodes.get(nid, {})
                host = n.get("attributes", {}).get("host")
                if not host or n.get("trust_domain") == "local" or n.get("kind") == "identity":
                    continue
                cur = reached.setdefault(host, {"host": host, "tier": info["tier"], "reached_by": set(), "node": nid})
                cur["tier"] = max(cur["tier"], info["tier"])
                cur["reached_by"].add(nodes.get(principal, {}).get("display_label", principal))
    allow = [(p, b) for b in bounds for p in b["allow"]]
    deny = [(p, b) for b in bounds for p in b["deny"]]
    any_open = any(b["open"] for b in bounds)
    outside = []
    for host, r in sorted(reached.items()):
        denied = [b for p, b in deny if matches(host, p)]
        allowed = any(matches(host, p) for p, _ in allow)
        if denied or (not allowed and not any_open):
            outside.append({"host": host, "tier": TIER[r["tier"]], "reached_by": sorted(r["reached_by"])[:5],
                            "why": "denied by %s" % denied[0]["path"] if denied else "not in any declared allowlist"})
    unused = sorted({"%s (%s)" % (p, b["path"]) for p, b in allow if not _wild(p) and not any(matches(h, p) for h in reached)})
    wildcards = sorted({"%s (%s)" % (p, b["path"]) for p, b in allow if _wild(p)})
    return {"state": "declared", "boundaries": [dict(b, allow=b["allow"][:50], deny=b["deny"][:50]) for b in bounds],
            "outside": outside[:100], "unused": unused[:100], "wildcards": wildcards[:50],
            "note": "declared allowlists compared with hosts the map reaches; enforcement at runtime is not verified"}
