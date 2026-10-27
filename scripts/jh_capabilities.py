"""Semantic, unsuppressed access requests between immutable Git snapshots.

Static possibilities, never runtime grants or an approval record. Evidence
locations do not participate in request identity; credential values never do.
"""
from __future__ import annotations

import hashlib
import html
import json
import os
import re
import tempfile
from contextlib import contextmanager
from pathlib import Path

import jh_agent
import jh_config
import jh_graph as G
import jh_map
import jh_n8n
from jh_core import VERSION, source_from_text, is_mcp_config
from jh_rules import ScanOptions, scan_sources

MODEL = "jankhunt.capability-delta.v1"
DISPLAY_LIMIT = 100
MAX_REQUESTS = 20000
MUTATING = ("write", "delete", "admin")
AGENT_RULES = {"JH%d" % i for i in range(701, 712)} | {"JH432"}


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":"),
                                     ensure_ascii=True).encode()).hexdigest()


def not_requested():
    return dict(model=MODEL, state="not-requested", base_sha=None, head_sha=None,
                context_hash=None, delta_hash=None, counts={}, requests=[], unknowns=[],
                truncation={"truncated": False, "omitted": 0, "reasons": []})


def _subject(node):
    a = node["attributes"]
    if a.get('platform') == 'n8n' and a.get('n8n_key'):
        return a['n8n_key']
    if node["kind"] == "application":
        return "application"
    if a.get("platform") == "ai-agent":
        return "agent:" + a.get("client", "unknown")
    if a.get("platform") == "mcp":
        return "mcp:" + str(a.get("mcp_server", "unknown"))
    return G.sanitize_text(node["kind"] + ":" + node["display_label"], 200)


def _target(node):
    a = node["attributes"]
    # Environment is deliberately separate: reclassification must be visible.
    fields = ("engine", "host", "port", "catalog", "schema", "table", "resource", "service",
              "scope", "credential_refs", "platform", "mcp_server", "transport",
              "command", "launcher", "package", "pinned", "unresolved", "via")
    attrs = {k: sorted(a[k]) if isinstance(a[k], list) else a[k] for k in fields if k in a}
    if a.get("host"):
        attrs["port"] = a.get("port") or G.DEFAULT_PORTS.get(a.get("engine"))
    if not a.get("host") and not a.get("credential_refs"):
        attrs["logical_name"] = _subject(node)
    return {"kind": node["kind"], **attrs}


def _targets(node):
    scopes = [(key, value) for key in ("databases", "paths") for value in node["attributes"].get(key, [])]
    return [dict(_target(node), resource_scope={key: value}) for key, value in scopes] or [_target(node)]


def inventory(report, items):
    """Project direct and reachable actions without ranking away dimensions."""
    nodes = {n["id"]: n for n in report["graph"]["nodes"]}
    edges = [e for e in report["graph"]["edges"] if e["verification"] != "refuted"]
    by_edge = {e["id"]: e for e in edges}
    evidence = {e["id"]: e for e in report["evidence"]}
    adjacency = {impact: G._adjacency(edges, impact) for impact in ("confidentiality", "integrity", "availability")}
    rows, unknowns = {}, {}
    capped = False
    reasons = list(report["coverage"]["partial_reasons"]) + list(report["truncation"]["reasons"])
    if report["coverage"].get("skipped", {}).get("too-large"):
        reasons.append("oversized snapshot files omitted")
    if report["coverage"].get("skipped", {}).get("symlink-or-submodule"):
        reasons.append("snapshot links or submodules are not inspected")

    def receipt(row, path, line, source=None):
        item = dict(snapshot=report["source_revision"], path=G.sanitize_text(path, 300), line=line)
        if source and "json_pointer" in source:
            item.update(json_pointer=source["json_pointer"], code_line=source["code_line"])
        if item not in row["evidence"]:
            if len(row["evidence"]) < 20:
                row["evidence"].append(item)
            else:
                row["evidence_omitted"] = row.get("evidence_omitted", 0) + 1

    def add(kind, principal, target, action, refs=(), path=(), uncertain=False, production=False, location=None):
        nonlocal capped
        semantic = dict(kind=kind, principal=principal, target=target, action=action)
        key = digest(semantic)
        if key not in rows and len(rows) >= MAX_REQUESTS:
            capped = True
            return
        row = rows.setdefault(key, dict(semantic, id=key, certainty="supported", production=production,
                                        evidence=[], witness=[]))
        row["production"] |= production
        if uncertain:
            row["certainty"] = "unresolved"
            unknowns[key] = dict(id=key, kind=kind, principal=principal, target=target,
                                 detail="binding, authority or execution arguments remain unresolved")
        for ref in refs:
            ev = evidence.get(ref)
            if ev:
                receipt(row, ev["path"], ev["line"], ev)
        if location:
            receipt(row, *location)
        row["witness"] = [report["source_revision"] + ":" + eid for eid in path]

    for principal in nodes.values():
        if capped:
            break
        if principal["kind"] not in ("application", "workload", "identity"):
            continue
        sid, subject = principal["id"], _subject(principal)
        trigger = principal['attributes'].get('trigger')
        if trigger:
            add('trigger', subject, dict(trigger), 'receive' if trigger['direction'] == 'inbound' else 'run-unattended',
                principal['evidence_refs'], uncertain=True)
        reaches, mutation_reach = {}, {}
        for impact in ("confidentiality", "integrity", "availability"):
            reach, depth_capped = G.reach(edges, sid, impact, report["scope"]["max_depth"], adjacency[impact])
            if impact == "integrity":
                mutation_reach = reach
            for nid, item in reach.items():
                if item["tier"] >= reaches.get(nid, {}).get("tier", -1):
                    reaches[nid] = item
            if depth_capped:
                reasons.append("capability reachability depth limit reached")
        for nid, reach in reaches.items():
            node, path = nodes[nid], reach["path"]
            a, target = node["attributes"], _target(node)
            refs = [ref for eid in path for ref in by_edge[eid]["evidence_refs"]]
            uncertain = bool(a.get("unresolved")) or reach["tier"] == 0
            if node["trust_domain"] == "external" and (a.get("host") or a.get("unresolved")):
                # Only documented engine defaults; unknown is never implicit 443.
                port = a.get("port") or G.DEFAULT_PORTS.get(a.get("engine"))
                network = dict(host=a.get("host"), port=port)
                add("network", subject, network, "connect", refs, path,
                    uncertain or not a.get("host") or not port, node["environment"] == "production")
            if a.get("unresolved") or node["kind"] == "unknown":
                add("binding", subject, target, "resolve", refs, path, True)
            if node["kind"] in ("database", "storage", "queue") and by_edge[path[-1]]["capability"] == "unknown":
                for scoped in _targets(node):
                    add("authority", subject, scoped, "resolve-authority", refs, path, True,
                        node["environment"] == "production")
            if node["environment"] == "production":
                for scoped in _targets(node):
                    add("production", subject, scoped, "reach", refs, path, uncertain, True)
            if node["kind"] == "identity":
                for name in a.get("credential_refs", []):
                    add("credential", subject, {"logical_name": name}, "pass", refs, path)
        # Enumerate each final action independently; strongest-path ranking must
        # not hide a newly added delete because an admin edge already existed.
        for edge in edges:
            if edge["capability"] not in MUTATING or (edge["source"] != sid and edge["source"] not in mutation_reach):
                continue
            target = nodes[edge["target"]]
            if target["kind"] not in ("database", "storage", "queue", "api", "external", "unknown"):
                continue
            path = ([] if edge["source"] == sid else mutation_reach[edge["source"]]["path"]) + [edge["id"]]
            if len(path) > report["scope"]["max_depth"]:
                reasons.append("capability action path exceeds depth limit")
                continue
            refs = [ref for eid in path for ref in by_edge[eid]["evidence_refs"]]
            for scoped in _targets(target):
                add("authority", subject, scoped, edge["capability"], refs, path,
                    (not target["attributes"].get("host") and not target["attributes"].get("catalog")) or
                    target["kind"] == "unknown" or any(by_edge[e]["capability"] == "unknown" or
                        by_edge[e]["verification"] == "unknown" for e in path),
                    target["environment"] == "production")
        for name in principal["attributes"].get("credential_refs", []):
            add("credential", subject, {"logical_name": name}, "pass", principal["evidence_refs"])
    sources = []
    for item in items:
        if capped:
            break
        sf = source_from_text(item.rel, item.rel, item.text)
        if sf:
            sources.append(sf)
            if sf.lang in ("shell", "powershell", "ruby", "php", "scala", "swift", "c", "cpp", "sql", "lua", "perl", "r"):
                add("binding", "application", {"logical_name": sf.lang + " connectivity"}, "resolve-analysis",
                    uncertain=True, location=(item.rel, 1))
            # Read variable names only, using the same comment-free source view.
            code = sf.nocomment if sf.lang in ("python", "js", "ts", "csharp", "java", "kotlin", "rust", "go") else []
            for line, text in enumerate(code, 1):
                for pattern in jh_map._ENV_RES:
                    for match in pattern.finditer(text):
                        if not sf.code[line - 1][match.start():match.start() + 2].strip():
                            continue  # an example inside a string is not an environment read
                        name = match.group(1)
                        if jh_map._SECRETISH.search(name):
                            add("credential", "application", {"logical_name": name}, "read", location=(item.rel, line))
        if not is_mcp_config(item.rel, item.text):
            continue
        try:
            if item.rel.lower().endswith(".toml"):
                try:
                    import tomllib
                except ImportError:
                    reasons.append("MCP TOML validation unavailable")
                else:
                    tomllib.loads(item.text)
            elif not isinstance(jh_agent.loads_jsonc(item.text), dict):
                raise ValueError("expected MCP configuration object")
            servers = jh_agent.mcp_servers(item.rel, item.text)
        except (ValueError, TypeError, RecursionError):
            reasons.append("MCP configuration could not be parsed")
            continue
        if len(servers) >= jh_agent.MAX_SERVERS:
            reasons.append("MCP server extraction limit reached")
        for server in servers:
            if server.disabled:
                continue
            launch = jh_agent.launch_source(server.command, server.args) or {}
            ep = G.parse_endpoint(server.url) if server.url else None
            target = dict(name=G.sanitize_text(server.name), transport=server.transport,
                          command=G.sanitize_text(os.path.basename(server.command)),
                          launch=launch, endpoint={k: ep[k] for k in ("host", "port", "engine") if k in ep} if ep else {})
            # General executable arguments/tool schemas are opaque. Do not hash
            # or disclose them: they may include credential literals.
            add("agent", "agent:" + jh_agent.client_for(item.rel), target, "start-mcp", uncertain=True,
                location=(item.rel, server.line))
            for name in jh_agent.credential_names(server):
                add("credential", "mcp:" + G.sanitize_text(server.name), {"logical_name": G.sanitize_text(name)}, "pass",
                    location=(item.rel, server.line))
    controls = scan_sources(sources, ScanOptions(min_severity="info", rule_ids=AGENT_RULES,
                            max_per_file_rule=1000, max_per_rule=100000, honor_suppressions=False))
    for finding in controls.findings:
        # A lead can contain arbitrary shell. Keep the control name only, and
        # explicitly retain uncertainty even if the same lead existed at base.
        add("agent", "application", {"control": finding.rule}, "agent-control", uncertain=True,
            location=(finding.path, finding.line))
    per_file = {}
    for finding in controls.findings:
        key = (finding.path, finding.rule)
        per_file[key] = per_file.get(key, 0) + 1
    if any(n >= 1000 for n in per_file.values()) or any(n >= 100000 for n in controls.fired_by_rule.values()) or capped:
        reasons.append("capability or agent extraction limit reached")
    for node in nodes.values():
        if any(isinstance(v, list) and len(v) >= 50 for v in node["attributes"].values()):
            reasons.append("graph attribute extraction limit reached")
    return rows, unknowns, sorted(set(reasons))


def _mcp_definitions(items):
    """({server name: definitions}, {config path: definitions}): command, arguments, env and header NAMES, URL,
    transport. Values are left out: a changed credential value alone is not new access."""
    out, by_file = {}, {}
    for item in items:
        if not is_mcp_config(item.rel, item.text):
            continue
        try:
            servers = jh_agent.mcp_servers(item.rel, item.text)
        except (ValueError, TypeError, RecursionError):
            continue
        for s in servers:
            text = json.dumps(dict(
                command=s.command, args=list(s.args or ()), env=sorted(s.env or {}),
                url=s.url, transport=s.transport, disabled=s.disabled, headers=sorted(s.headers or {}),
                token_env=s.token_env), sort_keys=True)
            out.setdefault(s.name, []).append(text)
            by_file.setdefault(item.rel, []).append(text)
    return {name: sorted(defs) for name, defs in out.items()}, {rel: sorted(defs) for rel, defs in by_file.items()}


def _definition(row, lines, mcp, n8n):
    """What an opaque request stands for in one snapshot, compared in memory and never exported: an MCP server's
    normalized definition, else the text around each evidence line (locations dropped, so a move is no change).
    None when nothing comparable was captured, which counts as changed."""
    if row['principal'].startswith('n8n:'):
        return n8n.get(row['principal'])
    if row["kind"] == "agent" and row["action"] == "start-mcp":
        defs = mcp[0].get(row["target"].get("name"))
        return digest(defs) if defs else None
    if row.get("evidence_omitted") or not row.get("evidence"):
        return None
    parts = []
    for ev in row["evidence"]:
        if ev["path"] in mcp[1]:                    # a control inside an MCP config: its servers, values left out
            parts.append(json.dumps(mcp[1][ev["path"]]))
            continue
        text = lines.get(ev["path"])
        if text is None or not 1 <= ev["line"] <= len(text):
            return None
        if row["action"] == "resolve-analysis":
            # a whole file in a language without a connectivity reader: any edit anywhere may change it
            parts.append("\n".join(x.rstrip() for x in text))
            continue
        parts.append("\n".join(x.strip() for x in text[max(0, ev["line"] - 3):ev["line"] + 2]))
    return digest(sorted(parts))


def compare(base, head, base_items, head_items, ceiling, context):
    before, bu, br = inventory(base, base_items)
    after, hu, hr = inventory(head, head_items)
    requests = []
    for key, row in after.items():
        if key in before:
            continue
        row["change"] = "added"
        row["ceiling"] = ("unknown" if not row["target"].get("host") or not row["target"].get("port") else
                          "within" if ceiling is not None and (row["target"].get("host"),
                            row["target"].get("port")) in ceiling else "outside" if ceiling is not None else "unknown") \
                            if row["kind"] == "network" else "not-applicable"
        row["approval"] = "within-network-ceiling" if row["ceiling"] == "within" else "needs-approval"
        requests.append(row)
    requests.sort(key=lambda r: (not (r["production"] and r["kind"] == "authority" and r["action"] in MUTATING),
                                 not r["production"], r["kind"] not in ("credential", "agent"), r["id"]))
    # New in head, or unresolved at base and apparently resolved in head (a resolution can hide new authority):
    # both need review. Unresolved and unchanged in both is listed but does not force review on every change.
    for key in hu.keys() - bu.keys():
        hu[key]["change"] = "new"
    # Unresolved in both is non-gating only when what it stands for is demonstrably the same: a hook whose command
    # was replaced, or an MCP server whose arguments changed, keeps its coarse identity and must still be reviewed.
    base_view = ({i.rel: i.text.split("\n") for i in base_items}, _mcp_definitions(base_items), jh_n8n.definitions(base_items))
    head_view = ({i.rel: i.text.split("\n") for i in head_items}, _mcp_definitions(head_items), jh_n8n.definitions(head_items))
    for key in hu.keys() & bu.keys():
        old, new = _definition(before[key], *base_view), _definition(after[key], *head_view)
        if old is None or old != new:
            hu[key]["change"] = "definition-changed"
            bu.pop(key)
    for key in bu.keys() - hu.keys():
        bu[key]["change"] = "resolved-in-head"
    unknowns = sorted([u for k, u in {**bu, **hu}.items() if not (k in bu and k in hu)], key=lambda u: u["id"])
    persisting = sorted([hu[k] for k in hu.keys() & bu.keys()], key=lambda u: u["id"])
    reasons = sorted(set(br + hr))
    counts = {kind: sum(r["kind"] == kind for r in requests) for kind in
              ("network", "credential", "authority", "production", "agent", "binding", "trigger")}
    counts.update(total=len(requests), lower_bound=bool(reasons), needs_approval=sum(r["approval"] == "needs-approval" for r in requests),
                  unknown=len(unknowns), unchanged_unknown=len(persisting), before=len(before), after=len(after))
    context_hash = digest(context)
    delta_hash = digest(dict(context=context_hash, base=base["source_revision"], head=head["source_revision"],
                             requests=[{k: r[k] for k in ("id", "certainty", "approval", "production")} for r in requests],
                             unknowns=unknowns, incomplete=reasons))
    return dict(model=MODEL, state="incomplete" if reasons else "complete", base_sha=base["source_revision"],
                head_sha=head["source_revision"], context_hash=context_hash, delta_hash=delta_hash, counts=counts,
                requests=requests[:DISPLAY_LIMIT], unknowns=unknowns[:DISPLAY_LIMIT],
                unchanged_unknowns=persisting[:DISPLAY_LIMIT],
                truncation=dict(truncated=bool(reasons or len(requests) > DISPLAY_LIMIT or len(unknowns) > DISPLAY_LIMIT),
                                omitted=max(0, len(requests) - DISPLAY_LIMIT),
                                unknowns_omitted=max(0, len(unknowns) - DISPLAY_LIMIT), reasons=reasons))


def _label(target):
    label = target.get("logical_name") or target.get("name") or target.get("host") or target.get("catalog")
    if not label:
        label = {"JH702": "approval bypass", "JH703": "disabled approvals", "JH704": "workspace hook or command",
                 "JH701": "suspicious agent instruction", "JH705": "unpinned agent tool", "JH706": "MCP credential exposure",
                 "JH707": "plaintext MCP transport", "JH708": "untrusted agent prompt input", "JH432": "agent CI with secrets",
                 "JH709": "broad sandbox access", "JH710": "unenforced sandbox", "JH711": "weakened container isolation"}.get(
                     target.get("control"), target.get("kind", "unresolved target"))
    if target.get("port"):
        label += ":%s" % target["port"]
    if target.get("resource_scope"):
        label += "/" + "/".join(str(v) for v in target["resource_scope"].values())
    return label


def approver_lines(delta):
    if delta.get("state") == "not-requested":
        return ["Access comparison: not requested (use --base REF)."]
    lines = ["Access comparison: %s; %d new requests, %d unresolved." % (
        delta["state"], delta["counts"]["total"], delta["counts"]["unknown"])]
    for row in delta["requests"][:10]:
        target = row["target"]
        label = _label(target)
        if row["kind"] == "network" and not target.get("port"):
            label += " (unknown port)"
        ev = row["evidence"][0] if row["evidence"] else None
        where = "; %s:%s" % (ev["path"], ev["line"]) if ev else ""
        if ev and 'json_pointer' in ev:
            where += ' %s, code line %d' % (ev['json_pointer'], ev['code_line'])
        lines.append("%s: %s may %s %s (%s; %s%s)." % (
            "Within network ceiling" if row["ceiling"] == "within" else "Needs approval",
            row["principal"], row["action"], label, row["certainty"], row["ceiling"], where))
    for unknown in delta["unknowns"][:3]:
        lines.append("Resolve first: %s for %s %s." % (
            _label(unknown.get("target") or {}), unknown.get("principal", "principal"),
            "is newly unresolved" if unknown.get("change") == "new" else
            "changed its definition; check what it now does" if unknown.get("change") == "definition-changed" else
            "was unresolved at the base; check what resolved it"))
    if delta["counts"].get("unchanged_unknown"):
        lines.append("Unchanged: %d item(s) were already unresolved at the base and still are; they do not "
                     "need review for this change." % delta["counts"]["unchanged_unknown"])
    if delta["counts"]["total"] > 10:
        lines.append("Showing 10 requests; JSON counts include every extracted request.")
    return [G.sanitize_text(line, 600) for line in lines]


def markdown_line(line):
    for char in "\\`*_{}[]()!|":
        line = line.replace(char, "\\" + char)
    return html.escape(line, quote=False)


@contextmanager
def snapshots(args):
    """Freeze both trees and operator inventory once; materialize text only.

    The temporary head directory is used only for offline supply/lock readers.
    Trust decisions continue to use the original repository path.
    """
    root = os.path.realpath(args.path)
    top = jh_map.git_toplevel(root)
    if not top:
        raise ValueError("--base needs a git repository")
    base_sha, head_sha = jh_map.git_revision(top, args.base), jh_map.git_revision(top)
    if any(not sha or not re.fullmatch(r"(?:[0-9a-f]{40}|[0-9a-f]{64})", sha) for sha in (base_sha, head_sha)):
        raise ValueError("--base and HEAD must resolve to commits")
    prefix = os.path.relpath(os.path.realpath(root), os.path.realpath(top)).replace(os.sep, "/")
    prefix = "" if prefix == "." else prefix + "/"
    inventory = None
    if args.inventory:
        if jh_map.inside(args.inventory, top):
            raise ValueError("--base requires operator inventory outside the repository")
        inventory = jh_map.load_json_file(args.inventory)
    external_cfg = jh_config.load_config(args.config) if args.config and not args.no_config and \
        not jh_map.inside(args.config, top) else None

    def config_at(sha):
        if args.no_config:
            return jh_config.Config()
        if external_cfg is not None:
            return external_cfg
        candidates = [os.path.abspath(args.config)] if args.config else []
        cur = root
        while not args.config:
            candidates.extend(os.path.join(cur, n) for n in (".jankhunt42.toml", ".jankhunt42.json"))
            if cur == top:
                break
            cur = os.path.dirname(cur)
        for path in candidates:
            rel = os.path.relpath(path, top).replace(os.sep, "/")
            obj = sha + ":" + rel
            try:
                size = int(jh_map._git(top, ["cat-file", "-s", obj]))
            except jh_map.GitError:
                continue
            if size > args.max_file_bytes:
                cfg = jh_config.Config()
                cfg.warnings.append("committed config exceeds the file byte limit")
                return cfg
            cfg = jh_config.load_config(path, jh_map._git(top, ["cat-file", "blob", obj]).decode("utf-8"))
            return cfg
        if args.config:
            raise ValueError("explicit repository --config must exist at both compared revisions")
        return jh_config.Config()

    reports, collections, configs = [], [], []
    for sha in (base_sha, head_sha):
        col = jh_map.collect_git(top, sha, args.exclude or (), args.max_files, args.max_file_bytes,
                                prefix, include_locks=True)
        for item in col.items:
            item.rel = item.rel[len(prefix):]
        cfg = config_at(sha)
        warnings = list(cfg.warnings)
        declarations = cfg.passport
        reports.append(jh_map.build_report(col, root, os.path.basename(root), "git:" + sha, sha,
                       declarations, inventory, bool(inventory), os.path.basename(args.inventory or ""),
                       max(1, min(G.MAX_DEPTH, args.max_depth)), warnings))
        if warnings:
            reports[-1]["coverage"]["partial_reasons"].append("snapshot config was not completely parsed")
            reports[-1]["coverage"]["status"] = "partial"
        collections.append(col)
        configs.append(cfg)
    with tempfile.TemporaryDirectory(prefix="jh-cap-head-") as frozen:
        for item in collections[1].items:
            path = Path(frozen, item.rel)
            if not path.resolve().is_relative_to(Path(frozen).resolve()):
                raise ValueError("unsafe Git snapshot path")
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(item.text, encoding="utf-8")
        yield dict(root=root, map=reports[1], col=collections[1], frozen=frozen, cfg=configs[1],
                   reports=reports, collections=collections, inventory=inventory,
                   operator_config=external_cfg.passport if external_cfg is not None else None)
