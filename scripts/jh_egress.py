#!/usr/bin/env python3
"""Declared egress boundary versus observed reach.

A boundary is a structured network allowlist committed with the repository:
Codex network-proxy domains and permission profiles, Claude Code sandbox
allowedDomains/deniedDomains, and OpenShell network policy endpoints. It is
compared with the hosts the connectivity map shows the code and its agent
tooling reaching:

  * outside: a reached endpoint the one selected declared context does not admit;
  * unassessed: reach whose context or declared activation is unresolved;
  * unused: an allowed entry nothing in the map reaches (tooling such as
    package registries may still need it, so this is informational);
  * wildcard: an entry that admits many hosts.

With no boundary declared the result is `unknown`, never "open" or "closed".
A declared boundary is what the configuration says. Different tools, scopes
and inactive profiles never grant permissions to each other. Effective settings
and enforcement at runtime are not verified here.
"""
from __future__ import annotations

import json
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import jh_agent
import jh_yaml
from jh_core import _looks_like_sandbox_policy as looks_like_sandbox_policy

TIER = {3: "verified", 2: "supported", 1: "inferred", 0: "unknown"}


def _string(value: str) -> Optional[str]:
    value = value.strip()
    if len(value) >= 2 and value[0] == value[-1] == "'":
        return value[1:-1]
    try:
        parsed = json.loads(value)
    except ValueError:
        return None
    return parsed if isinstance(parsed, str) else None


def _context_supported(text: str) -> bool:
    """Only credit the bounded, unambiguous declaration subset we understand."""
    seen = set()
    section = ""
    for raw in text.splitlines():
        line = _strip_toml_comment(raw).strip()
        if not line:
            continue
        # Multiline values and array tables can contain apparent control lines.
        if '\"\"\"' in line or "'''" in line or line.startswith("[["):
            return False
        if line.startswith("["):
            if not re.fullmatch(r"\[[A-Za-z0-9_.-]+\]", line):
                return False
            section = line[1:-1]
            continue
        match = re.match(r'''^("(?:[^"\\]|\\.)*"|'[^']*'|[A-Za-z0-9_-]+)\s*=\s*(.+)$''', line)
        if not match:
            return False
        key = _string(match.group(1)) if match.group(1)[0] in "\"'" else match.group(1)
        if key is None or (section, key) in seen or match.group(2).lstrip().startswith("{"):
            return False
        seen.add((section, key))
    return True


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
        m = re.match(r"""^\s*("(?:[^"\\]|\\.)*"|'[^']*'|[\w.\-*]+)\s*=\s*(.+?)\s*$""", line)
        if m:
            key = _string(m.group(1)) if m.group(1)[0] in "\"'" else m.group(1)
            if key is not None:
                out.append((i, section, key, m.group(2).strip()))
    return out


def _codex(rel: str, text: str) -> List[Dict[str, Any]]:
    records: Dict[str, Dict[str, Any]] = {}
    selected, proxy, supported = None, None, _context_supported(text)
    global_rules = False
    proxy_forms = set()

    def record(profile: str) -> Dict[str, Any]:
        return records.setdefault(profile, {"tool": "codex", "path": rel, "line": 1,
            "profile": profile or None, "allow": [], "deny": [], "open": False,
            "enabled": None, "selected": None, "note": "", "extends_unknown": False})

    for line, section, key, value in _toml_tables(text):
        value = value.strip()
        if not section and key == "default_permissions":
            selected = _string(value)
            supported = supported and selected is not None
        elif not section and key == "sandbox_mode":
            # Legacy selection can override named profiles; managed exceptions
            # and higher-precedence layers are not resolved by this reader.
            supported = False
        elif (section == "features.network_proxy" and key == "enabled") or \
                (section == "features" and key == "network_proxy"):
            # Both documented forms are accepted by the native consumer.
            proxy_forms.add(section)
            supported = supported and len(proxy_forms) == 1
            proxy = True if value == "true" else False if value == "false" else None
        match = re.fullmatch(r"permissions\.([A-Za-z0-9_-]+)(?:\.(network)(?:\.(domains))?)?", section)
        if match:
            boundary = record(match.group(1))
            if match.group(3):
                decision = _string(value)
                if decision not in ("allow", "deny"):
                    supported = False
                    continue
                boundary[decision].append(key)
                boundary["line"] = line
            elif match.group(2) and key == "enabled":
                boundary["enabled"] = True if value == "true" else False if value == "false" else None
            elif not match.group(2) and key == "extends":
                parent = _string(value)
                boundary["extends_unknown"] = parent not in (":workspace", ":read-only")
            elif match.group(2) and key == "mode" and _string(value) == "full":
                boundary["open"] = True
        elif section in ("features.network_proxy.domains", "network_proxy.domains"):
            boundary = record("")
            decision = _string(value)
            if decision not in ("allow", "deny"):
                supported = False
                continue
            boundary[decision].append(key)
            boundary["line"] = line
            global_rules = True
        elif section == "sandbox_workspace_write" and key == "network_access":
            boundary = record("")
            boundary["enabled"] = True if value == "true" else False if value == "false" else None
            boundary["open"] = value == "true"
    out = []
    for profile, boundary in sorted(records.items()):
        boundary["allow"] = sorted(set(boundary["allow"]))
        boundary["deny"] = sorted(set(boundary["deny"]))
        boundary["selected"] = (profile == selected) if selected is not None else (None if profile else True)
        enabled = boundary["enabled"]
        inherited = boundary.pop("extends_unknown")
        boundary["enabled"] = False if proxy is False or enabled is False else \
            True if proxy is True and (enabled is True or not profile) else None
        if not supported or inherited or global_rules and len(records) > 1:
            boundary["enabled"] = None
            boundary["note"] = "declaration syntax or inheritance is not fully modeled; applicability is unknown"
        elif boundary["selected"] is False:
            boundary["note"] = "inactive permission profile; excluded from selected coverage"
        elif boundary["selected"] is None:
            boundary["note"] = "no permission profile is selected in this declaration"
        elif boundary["enabled"] is not True:
            boundary["note"] = "proxy or command-network activation is disabled or unresolved"
        boundary["open"] = bool(boundary["open"] and not boundary["allow"])
        out.append(boundary)
    return out


def _claude(rel: str, text: str) -> List[Dict[str, Any]]:
    try:
        data = jh_agent.loads_jsonc(text)
    except ValueError:
        return []
    box = data.get("sandbox") if isinstance(data, dict) else None
    if not isinstance(box, dict):
        return []
    net = box.get("network") if isinstance(box.get("network"), dict) else {}
    raw_allow, raw_deny = net.get("allowedDomains", []), net.get("deniedDomains", [])
    valid = isinstance(raw_allow, list) and isinstance(raw_deny, list) and \
        all(isinstance(value, str) for value in raw_allow + raw_deny)
    allow, deny = (raw_allow, raw_deny) if valid else ([], [])
    if not any(key in net for key in ("allowedDomains", "deniedDomains")):
        return []
    enabled = box.get("enabled") if valid and isinstance(box.get("enabled"), bool) else None
    note = "domain declarations are invalid; applicability is unknown" if not valid else "" if enabled is True else \
        "sandbox.enabled is not true in this file; the allowlist applies only when the sandbox is on"
    if any(key in net for key in ("httpProxyPort", "socksProxyPort")):
        enabled = None
        note = "a custom proxy can replace built-in domain filtering; its policy and applicability are unknown"
    line = next((i for i, ln in enumerate(text.split("\n"), 1) if "allowedDomains" in ln or "deniedDomains" in ln), 1)
    return [{"tool": "claude-code", "path": rel, "line": line, "allow": sorted(set(allow)), "deny": sorted(set(deny)),
             "profile": None, "selected": True, "enabled": enabled, "open": False, "note": note}]


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
                    "profile": None, "selected": True, "enabled": True,
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
    unassessed = [{"host": host, "tier": TIER[row["tier"]], "reached_by": sorted(row["reached_by"])[:5]}
                  for host, row in sorted(reached.items())][:100]

    def assess(boundary: Dict[str, Any]) -> Dict[str, Any]:
        result = {key: boundary.get(key) for key in ("tool", "path", "profile", "selected", "enabled")}
        if boundary.get("selected") is not True or boundary.get("enabled") is not True:
            result.update(state="unknown", outside=[], unused=[], wildcards=[], unassessed=unassessed)
            return result
        allow, deny = boundary["allow"], boundary["deny"]
        outside = []
        for host, row in sorted(reached.items()):
            denied = any(matches(host, pattern) for pattern in deny)
            allowed = any(matches(host, pattern) for pattern in allow)
            if denied or (not allowed and not boundary["open"]):
                outside.append({"host": host, "tier": TIER[row["tier"]], "reached_by": sorted(row["reached_by"])[:5],
                    "why": "denied by %s" % boundary["path"] if denied else "not in the selected declared allowlist"})
        result.update(state="declared", outside=outside[:100], unassessed=[],
            unused=sorted({"%s (%s)" % (pattern, boundary["path"]) for pattern in allow
                           if not _wild(pattern) and not any(matches(host, pattern) for host in reached)})[:100],
            wildcards=sorted({"%s (%s)" % (pattern, boundary["path"]) for pattern in allow if _wild(pattern)})[:50])
        return result

    contexts = [assess(boundary) for boundary in bounds[:50]]
    chosen = [contexts[i] for i, boundary in enumerate(bounds[:50]) if boundary.get("selected") is not False]
    tools = [context["tool"] for context in chosen]
    one_each = len(tools) == len(set(tools))        # two scopes of one tool merge in ways not modeled here
    known = bool(chosen) and one_each and len(bounds) <= 50 and all(c["state"] == "declared" for c in chosen)
    outside: Dict[str, Dict[str, Any]] = {}
    for context in chosen if known else []:         # each tool on its own: outside if any one of them misses it
        label = context["tool"] + (" [%s]" % context["profile"] if context.get("profile") else "")
        for row in context["outside"]:
            outside.setdefault(row["host"], dict(row, contexts=[]))["contexts"].append(label)
    if not bounds:
        note = "no structured egress allowlist is committed; the reachable network is unknown, not open"
    elif not chosen:
        note = "no declaration is selected; coverage is unknown"
    elif not one_each:
        note = "one tool has several settings scopes, and how they merge is not modeled; coverage is unknown"
    elif not known:
        note = "a selected declaration is disabled, unsupported or unresolved; coverage is unknown"
    elif len(chosen) > 1:
        note = ("each tool's selected declaration is compared with mapped reach on its own, and a host is outside "
                "when any one of them does not admit it; effective settings and runtime enforcement are not verified")
    else:
        note = "one selected declared context compared with mapped reach; effective settings and runtime enforcement are not verified"
    return {"state": "declared" if known else "unknown",
            "boundaries": [dict(b, allow=b["allow"][:50], deny=b["deny"][:50]) for b in bounds[:50]],
            "contexts": contexts, "unassessed": [] if known else unassessed,
            "outside": [outside[host] for host in sorted(outside)][:100],
            "unused": sorted({row for c in chosen for row in c["unused"]})[:100] if known else [],
            "wildcards": sorted({row for c in chosen for row in c["wildcards"]})[:50] if known else [], "note": note}
