#!/usr/bin/env python3
"""A least-privilege network fence for an AI coding agent, from what the code reaches.

`passport --emit-sandbox-policy FORMAT` writes a default-deny allowlist in the
native format of Claude Code (settings JSON), Codex (a config.toml permission
profile) or OpenShell (policy YAML). It is a review artefact: jankhunt42 never
applies it, and a fence is only as strong as the tool that enforces it.

What goes in:
  * hosts the connectivity map shows the code reaching, outside production;
  * the well-known endpoints of services the map names without a host;
  * the package registries the repository installs from (or the ecosystem's
    default when nothing is configured).

What stays out, listed for a decision, never guessed:
  * production assets: an agent editing code should get a non-production
    endpoint, not the production database;
  * endpoints the map could not resolve (an environment variable, a secret);
  * local services, and host names that are not plain DNS names or IPs (a
    hostile name must not become a rule).
"""
from __future__ import annotations

import ipaddress
import json
import re
from typing import AbstractSet, Any, Dict, List, Optional, Sequence, Tuple

import jh_yaml

FORMATS = ("claude-code", "codex", "openshell")
PROFILE = "jankhunt42-fence"
CLAUDE_PORT_NOTE = ("port-qualified entries verified on Claude Code 2.1.310; earlier versions are unverified, and the "
                    "sandbox runtime before July 2026 rejected port suffixes")

# a plain DNS name, optionally with a leading `*.` label, or an IPv4 address
_HOST_RE = re.compile(r"^(?:\*\.)?(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$")
_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")

# services the map names by engine without a host: their public API endpoints
ENGINE_HOSTS = {
    "openai": ["api.openai.com"],
    "anthropic": ["api.anthropic.com"],
    "github": ["api.github.com", "github.com"],
    "gitlab": ["gitlab.com"],
    "stripe": ["api.stripe.com"],
    "s3": ["s3.amazonaws.com", "*.s3.amazonaws.com"],
    "supabase": ["*.supabase.co"],
    "firebase": ["firestore.googleapis.com", "*.firebaseio.com", "identitytoolkit.googleapis.com"],
    "gemini": ["generativelanguage.googleapis.com"],
    "mistral": ["api.mistral.ai"],
    "groq": ["api.groq.com"],
    "openrouter": ["openrouter.ai"],
    "sendgrid": ["api.sendgrid.com"],
    "twilio": ["api.twilio.com"],
    "slack": ["slack.com", "hooks.slack.com"],
    "azure": ["management.azure.com", "login.microsoftonline.com"],
}
DEFAULT_PORTS = {"http": 80, "postgresql": 5432, "mysql": 3306, "mariadb": 3306, "redis": 6379, "mongodb": 27017,
                 "mssql": 1433, "cassandra": 9042, "elasticsearch": 9200, "rabbitmq": 5672, "kafka": 9092,
                 "nats": 4222}
# hosts a registry needs besides its index
REGISTRY_EXTRA = {"pypi.org": ["files.pythonhosted.org"], "crates.io": ["index.crates.io", "static.crates.io"],
                  "proxy.golang.org": ["sum.golang.org"]}
# OpenShell matches real executable paths; these are the usual places in Debian/Ubuntu-based images
RUNTIME_BINARIES = {
    "npm": ["/usr/bin/node", "/usr/local/bin/node"],
    "pypi": ["/usr/bin/python3*", "/usr/local/bin/python3*"],
    "maven": ["/usr/lib/jvm/*/bin/java"],
    "gradle": ["/usr/lib/jvm/*/bin/java"],
    "nuget": ["/usr/share/dotnet/dotnet", "/usr/lib/dotnet/dotnet"],
    "cargo": ["/usr/local/cargo/bin/cargo"],
}
# credential stores a sandboxed command should not read (Claude Code `~/` paths)
CREDENTIAL_PATHS = ["~/.aws", "~/.azure", "~/.config/gcloud", "~/.docker/config.json", "~/.git-credentials",
                    "~/.kube", "~/.netrc", "~/.npmrc", "~/.pypirc", "~/.ssh"]


def clean_host(value: Any, wildcard: bool = False) -> Optional[str]:
    """A host name usable as a rule, or None: lowercase, no scheme, path or
    port, and only DNS characters (or an IPv4 address). A leading `*.` only
    with wildcard=True: names read from a repository never widen the fence."""
    h = str(value or "").strip().lower()
    h = re.sub(r"^[a-z][a-z0-9+.-]*://", "", h).split("/", 1)[0].split("@")[-1]
    h = re.sub(r":\d{1,5}$", "", h).rstrip(".")
    if h.startswith("*") and not wildcard:
        return None
    if re.fullmatch(r"[\d.]+", h):                  # all digits: a valid IPv4 address or nothing
        return h if _IPV4_RE.match(h) and all(int(p) < 256 for p in h.split(".")) else None
    if _HOST_RE.match(h) and "." in h.lstrip("*.") or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", h):
        return h
    return None


def split_claude_domain(value: Any, deny: bool = False) -> Optional[Tuple[str, Optional[int]]]:
    """The bounded native domain/optional-port subset; invalid input grants nothing.

    Port-less entries mean every port. Brackets disambiguate IPv6 literals.
    Only deny lists may contain a bare `*`; `*.` means strict subdomains.
    """
    if not isinstance(value, str) or not value or value != value.strip():
        return None
    if value.startswith("["):
        closing = value.find("]")
        if closing < 0 or "%" in value:
            return None
        try:
            host = str(ipaddress.IPv6Address(value[1:closing]))
        except ValueError:
            return None
        suffix = value[closing + 1:]
    else:
        host, colon, tail = value.partition(":")
        suffix = colon + tail
        host = host.lower().rstrip(".")
        if host != "*" or not deny:
            if clean_host(host, wildcard=True) != host:
                return None
    if not suffix:
        return host, None
    if not re.fullmatch(r":[1-9][0-9]{0,4}", suffix) or int(suffix[1:]) > 65535:
        return None
    return host, int(suffix[1:])


def plan(report: Dict[str, Any], package_sources: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """{"allow": [{host, port, group, why}], "excluded": [{what, why}], "runtimes": [...]}."""
    allow: Dict[Tuple[str, int], Dict[str, Any]] = {}
    excluded: List[Dict[str, str]] = []

    def add(host: str, port: int, group: str, why: str) -> None:
        allow.setdefault((host, port), {"host": host, "port": port, "group": group, "why": why})

    for n in report.get("graph", {}).get("nodes", []):
        kind, attrs = n.get("kind"), n.get("attributes") or {}
        if kind in ("application", "workload", "identity"):
            continue
        label = str(n.get("display_label") or n.get("id"))[:80]
        engine = str(attrs.get("engine") or "").lower()
        if n.get("trust_domain") == "local":
            excluded.append({"what": label, "why": "a local service: not part of the network fence"})
            continue
        if n.get("environment") == "production":
            excluded.append({"what": label, "why": "production: give the agent a non-production endpoint instead"})
            continue
        raw = attrs.get("host")
        if raw:
            host = clean_host(raw)
            if host:
                group = "source_control" if engine in ("github", "gitlab") else "app_egress"
                port = attrs.get("port") if isinstance(attrs.get("port"), int) else DEFAULT_PORTS.get(engine, 443)
                add(host, port, group, "the code reaches it (%s)" % (engine or kind))
            else:
                excluded.append({"what": label, "why": "not a plain host name; a fence rule needs one"})
        elif engine in ENGINE_HOSTS:
            group = "source_control" if engine in ("github", "gitlab") else "app_egress"
            for host in ENGINE_HOSTS[engine]:
                add(host, 443, group, "the public endpoint of %s, which the code uses" % engine)
        else:
            excluded.append({"what": label, "why": "the map could not name the host (an environment variable, a "
                                                   "secret or a cloud resource): decide, then add it by hand"})
    runtimes = []
    for eco, d in sorted(((package_sources or {}).get("ecosystems") or {}).items()):
        if not d.get("in_use"):
            continue
        runtimes.append(eco)
        urls = [s.get("url") for s in d.get("sources") or []] or [d.get("default_if_unconfigured")]
        for url in urls:
            host = clean_host(url)
            if not host:
                continue
            why = "the %s registry the repository installs from" % eco if d.get("sources") else \
                "the default %s registry (nothing is configured)" % eco
            add(host, 443, "package_registries", why)
            for extra in REGISTRY_EXTRA.get(host, []):
                add(extra, 443, "package_registries", "serves the %s registry's files" % eco)
    rows = sorted(allow.values(), key=lambda r: (r["group"], r["host"].lstrip("*."), r["host"], r["port"]))
    seen = set()
    excluded = [e for e in excluded if not ((e["what"], e["why"]) in seen or seen.add((e["what"], e["why"])))]
    return {"allow": rows, "excluded": sorted(excluded, key=lambda e: (e["why"], e["what"])), "runtimes": runtimes}


def _hosts(p: Dict[str, Any]) -> List[str]:
    return sorted({r["host"] for r in p["allow"]}, key=lambda h: (h.lstrip("*."), h))


def render(fmt: str, p: Dict[str, Any], version: str, port_qualified: bool = False) -> Tuple[str, List[str]]:
    """(policy text, notes for stderr). Deterministic for a given plan and version."""
    notes = ["%d host(s) allowed; everything else is denied by the sandbox, where the tool enforces it" % len(_hosts(p))]
    notes += ["excluded: %s: %s" % (e["what"], e["why"]) for e in p["excluded"]]
    if fmt == "claude-code":
        domains = sorted({"%s:%d" % (r["host"], r["port"]) for r in p["allow"]}) if port_qualified else _hosts(p)
        doc = {"$schema": "https://json.schemastore.org/claude-code-settings.json",
               "sandbox": {"enabled": True, "failIfUnavailable": True, "allowUnsandboxedCommands": False,
                           "network": {"allowedDomains": domains},
                           "filesystem": {"denyRead": CREDENTIAL_PATHS}}}
        notes.append("merge into .claude/settings.json; a project file only pre-allows these hosts: to deny every "
                     "other host instead of prompting, set sandbox.network.strictAllowlist to true in "
                     "~/.claude/settings.json or managed settings (a project file cannot)")
        if port_qualified:
            notes.append(CLAUDE_PORT_NOTE)
        return json.dumps(doc, indent=2) + "\n", notes
    if fmt == "codex":
        lines = ["# Least-privilege network fence for Codex, written by jankhunt42 %s." % version,
                 "# Review it before use; jankhunt42 never applies it. Domain rules need the network proxy.",
                 'default_permissions = "%s"' % PROFILE, "", "[features]", "network_proxy = true", "",
                 "[permissions.%s]" % PROFILE, 'extends = ":workspace"', "",
                 "[permissions.%s.network]" % PROFILE, "enabled = true", "",
                 "[permissions.%s.network.domains]" % PROFILE]
        group = None
        for r in sorted(p["allow"], key=lambda r: (r["group"], r["host"].lstrip("*."), r["host"])):
            if r["group"] != group:
                group = r["group"]
                lines.append("# %s" % group.replace("_", " "))
            lines.append('"%s" = "allow"  # %s' % (r["host"], r["why"]))
        notes.append("put this in .codex/config.toml (trusted project) or ~/.codex/config.toml; permission profiles "
                     "are a Codex beta feature, and hosts on private networks also need its local-network settings")
        return "\n".join(_dedupe_domain_lines(lines)) + "\n", notes
    if fmt == "openshell":
        out = ["# Least-privilege network policy for OpenShell, written by jankhunt42 %s." % version,
               "# Review it before use; jankhunt42 never applies it. Binary paths are the usual locations in",
               "# Debian/Ubuntu images: replace them with your image's real paths (OpenShell does not follow",
               "# symlinks). A rule with no binaries matches nothing.", "version: 1",
               "network_policies:" if p["allow"] else "network_policies: {}"]
        groups: Dict[str, List[Dict[str, Any]]] = {}
        for r in p["allow"]:
            groups.setdefault(r["group"], []).append(r)
        app_bins = sorted({b for eco in p["runtimes"] for b in RUNTIME_BINARIES.get(eco, [])})
        bins = {"app_egress": app_bins, "package_registries": app_bins,
                "source_control": sorted({"/usr/bin/git"} | set(app_bins))}
        for group in sorted(groups):
            out += ["  %s:" % group, "    endpoints:"]
            for r in groups[group]:
                out += ["      - host: %s  # %s" % (_yaml_scalar(r["host"]), r["why"]), "        port: %d" % r["port"]]
            out.append("    binaries:" + ("" if bins.get(group) else " []"))
            out += ["      - path: %s" % _yaml_scalar(b) for b in bins.get(group, [])]
        if not app_bins and any(g in groups for g in ("app_egress", "package_registries")):
            notes.append("no runtime was detected: add the interpreter that runs the app to the binaries lists")
        notes.append("load it with `openshell policy set`; endpoints without rules allow any request to that "
                     "host and port, so add `access` or `rules` where an endpoint needs less")
        return "\n".join(out) + "\n", notes
    raise ValueError("unknown sandbox policy format: %s" % fmt)


def _yaml_scalar(s: str) -> str:
    return "'%s'" % s                   # always quoted: a host named `true` or `null` is still a string


def _dedupe_domain_lines(lines: List[str]) -> List[str]:
    seen, out = set(), []
    for line in lines:
        key = line.split("=", 1)[0].strip() if line.startswith('"') else None
        if key and key in seen:
            continue
        if key:
            seen.add(key)
        out.append(line)
    return out


def validate(fmt: str, text: str) -> List[str]:
    """Problems with an emitted policy against the documented subset jankhunt42 writes."""
    problems: List[str] = []
    if fmt == "claude-code":
        doc = json.loads(text)
        if set(doc) - {"$schema", "sandbox"}:
            problems.append("unexpected top-level keys")
        box = doc.get("sandbox", {})
        if set(box) - {"enabled", "failIfUnavailable", "allowUnsandboxedCommands", "network", "filesystem"}:
            problems.append("unexpected sandbox keys")
        if box.get("enabled") is not True:
            problems.append("sandbox.enabled is not true")
        for key, expected in (("failIfUnavailable", True), ("allowUnsandboxedCommands", False)):
            if box.get(key) is not expected:
                problems.append("sandbox.%s is not %s" % (key, str(expected).lower()))
        filesystem = box.get("filesystem")
        read_denies = filesystem.get("denyRead") if isinstance(filesystem, dict) else None
        if not isinstance(read_denies, list) or not all(isinstance(path, str) for path in read_denies):
            problems.append("sandbox.filesystem.denyRead is not a list of paths")
        elif not set(CREDENTIAL_PATHS).issubset(read_denies):
            problems.append("sandbox.filesystem.denyRead is missing required credential paths")
        hosts = box.get("network", {}).get("allowedDomains", [])
        if not isinstance(hosts, list):
            problems.append("allowedDomains is not a list")
        else:
            problems += ["bad host %r" % h for h in hosts if split_claude_domain(h) is None]
    elif fmt == "codex":
        table, domains, required = "", {}, set()
        for raw in text.split("\n"):
            line = raw.split("#", 1)[0].strip()
            m = re.match(r"^\[([^\]]+)\]$", line)
            if m:
                table = m.group(1)
                continue
            m = re.match(r'^("[^"]*"|[\w-]+)\s*=\s*(.+)$', line)
            if not m:
                continue
            key, value = m.group(1).strip('"'), m.group(2).strip()
            if table == "permissions.%s.network.domains" % PROFILE:
                domains[key] = value
            else:
                required.add((table, key, value))
        for need in (("", "default_permissions", '"%s"' % PROFILE), ("features", "network_proxy", "true"),
                     ("permissions.%s.network" % PROFILE, "enabled", "true")):
            if need not in required:
                problems.append("missing %s.%s = %s" % need)
        problems += ["bad host %r" % h for h in domains if clean_host(h, wildcard=True) != h]
        problems += ["domain %r is not allow" % h for h, v in domains.items() if v != '"allow"']
    elif fmt == "openshell":
        docs = jh_yaml.load_all(text)
        doc = docs[0] if len(docs) == 1 else None
        if not isinstance(doc, dict) or doc.get("version") != 1:
            return ["version must be 1"]
        for name, pol in (doc.get("network_policies") or {}).items():
            if str(name).startswith("_provider_"):
                problems.append("reserved rule name %s" % name)
            for ep in pol.get("endpoints") or []:
                h = str(ep.get("host", ""))
                if clean_host(h, wildcard=True) != h:
                    problems.append("bad host %r" % h)
                if h.startswith("*") and h.count(".") < 2:
                    problems.append("wildcard host %r needs at least three labels" % h)
                if not isinstance(ep.get("port"), int):
                    problems.append("endpoint %r has no port" % h)
            for b in pol.get("binaries") or []:
                if not str(b.get("path", "")).startswith("/"):
                    problems.append("binary path %r is not absolute" % b.get("path"))
    else:
        problems.append("unknown format")
    return problems


def emit(fmt: str, report: Dict[str, Any], package_sources: Optional[Dict[str, Any]], version: str,
         network_ceiling: Optional[AbstractSet[Tuple[str, int]]] = None
         ) -> Tuple[str, List[str]]:
    proposed = plan(report, package_sources)
    if network_ceiling is not None:
        if fmt not in ("openshell", "claude-code"):
            raise ValueError("the network ceiling requires openshell or claude-code: codex domain rules discard destination ports")
        import jh_ceiling
        proposed = jh_ceiling.constrain(proposed, network_ceiling)
    text, notes = render(fmt, proposed, version, port_qualified=fmt == "claude-code" and network_ceiling is not None)
    if network_ceiling is not None:
        notes.append("operator network ceiling applied: only approved discovered host/port pairs retained; "
                     "native enforcement is not verified")
    problems = validate(fmt, text)
    if problems:                        # never hand over a policy that fails its own check
        raise ValueError("emitted %s policy failed validation: %s" % (fmt, "; ".join(problems)))
    return text, notes
