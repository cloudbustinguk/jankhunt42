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

FORMATS = ("claude-code", "codex", "openshell", "substrate")
# AI APIs the Agent Substrate egress gateway can sign requests to, so the key stays out of the
# sandbox: the header each one reads its key from, and the prefix before the key
SUBSTRATE_KEY_HEADERS = {
    "api.anthropic.com": ("x-api-key", "", "anthropic"),
    "api.openai.com": ("Authorization", "Bearer ", "openai"),
    "generativelanguage.googleapis.com": ("x-goog-api-key", "", "gemini"),
    "api.mistral.ai": ("Authorization", "Bearer ", "mistral"),
    "api.groq.com": ("Authorization", "Bearer ", "groq"),
    "openrouter.ai": ("Authorization", "Bearer ", "openrouter"),
}
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
# database and broker ports: their protocols are neither HTTP nor TLS with SNI from the first byte,
# so Agent Substrate's egress gateway cannot pass them by host name
SUBSTRATE_UNSUPPORTED_PORTS = frozenset(p for e, p in DEFAULT_PORTS.items() if e != "http")
SUBSTRATE_SECRET_URI = "ate-secret://k8s.io/default/replace-with-namespace/%s-api-key/api-key"
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
    if fmt == "substrate":
        return _render_substrate(p, version, notes)
    raise ValueError("unknown sandbox policy format: %s" % fmt)


def _render_substrate(p: Dict[str, Any], version: str, notes: List[str]) -> Tuple[str, List[str]]:
    """An Agent Substrate EgressPolicy. AI APIs the gateway can sign requests to get
    an intercepted https rule that injects the key; other keyed APIs an https rule;
    everything else TLS passthrough on its port, so the gateway does not decrypt it."""
    import jh_substrate
    keyed: List[Dict[str, Any]] = []
    https: Dict[int, List[Dict[str, Any]]] = {}
    passthrough: Dict[int, List[Dict[str, Any]]] = {}
    http: List[Dict[str, Any]] = []
    for r in p["allow"]:
        host, port = r["host"], r["port"]
        if _IPV4_RE.match(host):
            notes.append("excluded: %s: Substrate egress rules take host names, not IP addresses" % host)
        elif port in SUBSTRATE_UNSUPPORTED_PORTS:
            notes.append("excluded: %s:%d: the egress gateway passes only HTTP and TLS with a server name; give the "
                         "agent an HTTPS API for it, or a tlsPassthrough rule if the client starts TLS at once"
                         % (host, port))
        elif port == 80:
            http.append(r)
        elif port == 443 and host in SUBSTRATE_KEY_HEADERS:
            keyed.append(r)
        elif jh_substrate.keyed_api(host):
            https.setdefault(port, []).append(r)
        else:
            passthrough.setdefault(port, []).append(r)
    out = ["# Least-privilege egress policy for an Agent Substrate actor, written by jankhunt42 %s." % version,
           "# Review it before use; jankhunt42 never applies it. Load it with",
           "# `kubectl ate create egress-policy <actor> -a <atespace> -f <this file>`."]
    if keyed:
        out += ["# The gateway signs requests to the AI APIs below with keys from a Secret, so no key enters the",
                "# sandbox: create each Secret and replace replace-with-namespace with its namespace."]
    rules: List[str] = []

    def hosts(rows: List[Dict[str, Any]]) -> List[str]:
        return ["    - %s  # %s" % (_yaml_scalar(r["host"]), r["why"])
                for r in sorted(rows, key=lambda r: (r["host"].lstrip("*."), r["host"]))]

    for r in sorted(keyed, key=lambda r: r["host"]):
        header, prefix, name = SUBSTRATE_KEY_HEADERS[r["host"]]
        rules += ["- https:", "    hostnames:"] + hosts([r]) + [
            "    effects:", "      replaceHeaders:", "      - header: %s" % _yaml_scalar(header)]
        if prefix:
            rules.append("        prefix: %s" % _yaml_scalar(prefix))
        rules.append("        credentialUri: %s" % _yaml_scalar(SUBSTRATE_SECRET_URI % name))
    for port in sorted(https):
        rules += ["- https:", "    hostnames:"] + hosts(https[port])
        if port != 443:
            rules += ["    ports:", "      numbers: [%d]" % port]
    for port in sorted(passthrough):
        rules += ["- tlsPassthrough:", "    hostnames:"] + hosts(passthrough[port]) + [
            "    ports:", "      numbers: [%d]" % port]
    if http:
        rules += ["- http:", "    hostnames:"] + hosts(http)
    out += ["rules:"] + rules if rules else ["rules: []"]
    emitted = {r["host"] for rows in [keyed, http] + list(https.values()) + list(passthrough.values()) for r in rows}
    notes[0] = "%d host(s) allowed; everything else is denied by the egress gateway" % len(emitted)
    if keyed:
        notes.append("the actor sends each injected header with a placeholder value (for example "
                     "ANTHROPIC_API_KEY=placeholder) and must trust the gateway's CA: mount the egress-mitm.ate.dev "
                     "trust bundle and point SSL_CERT_FILE or NODE_EXTRA_CA_CERTS at it; a cluster admin must also "
                     "grant the actor's atespace access to the Secret's namespace")
    if https:
        notes.append("https rules are decrypted by the gateway, so the actor must trust its CA; add a replaceHeaders "
                     "effect where the agent signs in to that API, so its key stays out of the sandbox too")
    if passthrough:
        notes.append("tlsPassthrough rules relay TLS without decrypting it: the gateway checks only the server name")
    return "\n".join(out) + "\n", notes


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
    elif fmt == "substrate":
        problems += _validate_substrate(text)
    else:
        problems.append("unknown format")
    return problems


def _validate_substrate(text: str) -> List[str]:
    """The EgressPolicy subset jankhunt42 writes, against the API's documented rules."""
    docs = jh_yaml.load_all(text)
    doc = docs[0] if len(docs) == 1 else None
    if not isinstance(doc, dict) or set(doc) != {"rules"} or not isinstance(doc["rules"], list):
        return ["the policy must be one document with a rules list"]
    problems: List[str] = []
    taken = set()
    for item in doc["rules"]:
        if not isinstance(item, dict) or len(item) != 1 or next(iter(item)) not in ("http", "https", "tlsPassthrough"):
            problems.append("a rule must be exactly one of http, https or tlsPassthrough")
            continue
        kind, body = next(iter(item.items()))
        names = body.get("hostnames") if isinstance(body, dict) else None
        if not isinstance(names, list) or not names:
            problems.append("a %s rule has no hostnames" % kind)
            continue
        ports = body.get("ports")
        numbers = ports.get("numbers") if isinstance(ports, dict) else None
        if kind == "tlsPassthrough" and not numbers:
            problems.append("a tlsPassthrough rule needs port numbers")
        if numbers is not None and not (isinstance(numbers, list) and numbers and
                                        all(isinstance(n, int) and 0 < n < 65536 for n in numbers)):
            problems.append("bad port numbers %r" % numbers)
            numbers = None
        for h in names:
            if not isinstance(h, str) or clean_host(h, wildcard=True) != h or _IPV4_RE.match(h) or h != h.lower():
                problems.append("bad host %r" % h)
            for port in numbers or [80 if kind == "http" else 443]:
                if (h, port) in taken:
                    problems.append("two rules for %s on port %d" % (h, port))
                taken.add((h, port))
        effects = body.get("effects")
        if effects is not None:
            if kind != "https":
                problems.append("credential effects on a %s rule" % kind)
            for e in (effects or {}).get("replaceHeaders") or []:
                if not e.get("header") or not str(e.get("credentialUri", "")).startswith("ate-secret://"):
                    problems.append("a replaceHeaders entry needs a header and an ate-secret:// credentialUri")
    return problems


def emit(fmt: str, report: Dict[str, Any], package_sources: Optional[Dict[str, Any]], version: str,
         network_ceiling: Optional[AbstractSet[Tuple[str, int]]] = None
         ) -> Tuple[str, List[str]]:
    proposed = plan(report, package_sources)
    if network_ceiling is not None:
        if fmt not in ("openshell", "claude-code", "substrate"):
            raise ValueError("the network ceiling requires openshell, claude-code or substrate: codex domain rules "
                             "discard destination ports")
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
