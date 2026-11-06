#!/usr/bin/env python3
"""Agent Substrate manifests: egress policies and actor templates.

Agent Substrate runs each AI agent (an actor) in a sandbox and sends all of its
outbound traffic through an egress gateway. The gateway allows only what the
actor's egress policy lists, and an `https` rule can carry a `replaceHeaders`
effect that puts a credential into the request at the gateway, so the key
never enters the sandbox.

This module reads the manifests `kubectl ate` applies, as committed: an
EgressPolicy (`rules:`), or an ActorTemplate (`containers:`, with an optional
`goldenEgressPolicy`). Templates rendered with `${VAR}` substitution
(`*.yaml.tmpl`) are read as written. Policies kept only in Substrate's
database, or built in code, are out of reach.
"""
from __future__ import annotations

import re
from typing import Any, Dict, Iterator, List, Optional, Tuple

import jh_agent
import jh_yaml

RULE_KINDS = {"http": "http", "https": "https", "tlsPassthrough": "tlsPassthrough",
              "tls_passthrough": "tlsPassthrough"}

# APIs an agent signs in to with a key in a request header. TLS passthrough to one of
# these means the gateway cannot inject the key, so the key has to be in the sandbox.
KEYED_API_HOSTS = (
    "api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com", "api.mistral.ai",
    "api.groq.com", "openrouter.ai", "api.cohere.com", "api.cohere.ai", "api.deepseek.com",
    "api.together.xyz", "api.fireworks.ai", "api.x.ai", "api.perplexity.ai", "api.voyageai.com",
    "api.github.com", "api.stripe.com", "api.sendgrid.com", "api.twilio.com", "slack.com",
)
KEYED_API_SUFFIXES = (".openai.azure.com", ".cognitiveservices.azure.com")

# credential-named env vars whose value is a location or a switch, not the secret itself
_NOT_SECRET_NAME_RE = re.compile(r"(?i)_(?:URL|URI|ENDPOINT|HOST|PATH|FILE|DIR|ID|NAME|HEADER|TTL|EXPIRY|"
                                 r"ENABLED|TYPE|PREFIX|REGION)$")
_SUBSTITUTION_RE = re.compile(r"\$\{\s*[A-Za-z_]\w*\s*\}")


def docs(text: str) -> List[Dict[str, Any]]:
    """The manifest documents, or [] when the file does not parse."""
    try:
        if text.lstrip().startswith("{"):
            found = [jh_agent.loads_jsonc(text)]
        else:
            found = jh_yaml.load_all(text)
    except (jh_yaml.YamlError, ValueError, RecursionError):
        return []
    return [d for d in found if isinstance(d, dict)]


def _get(d: Dict[str, Any], *names: str) -> Any:
    for n in names:
        if n in d:
            return d[n]
    return None


def rules(doc: Dict[str, Any]) -> Iterator[Tuple[str, Dict[str, Any]]]:
    """(kind, body) for each rule of an EgressPolicy, or of an ActorTemplate's
    goldenEgressPolicy; kind is http, https or tlsPassthrough."""
    holder = doc
    golden = _get(doc, "goldenEgressPolicy", "golden_egress_policy")
    if isinstance(golden, dict):
        holder = golden
    items = holder.get("rules") if isinstance(holder.get("rules"), list) else []
    for item in items:
        if not isinstance(item, dict):
            continue
        for key, body in item.items():
            if key in RULE_KINDS and isinstance(body, dict):
                yield RULE_KINDS[key], body


def hostnames(body: Dict[str, Any]) -> List[str]:
    names = body.get("hostnames") if isinstance(body.get("hostnames"), list) else []
    return [str(h).strip() for h in names if isinstance(h, (str, int))]


def all_ports(body: Dict[str, Any]) -> bool:
    ports = body.get("ports")
    return isinstance(ports, dict) and "all" in ports


def header_effects(body: Dict[str, Any]) -> List[Dict[str, Any]]:
    effects = body.get("effects") if isinstance(body.get("effects"), dict) else {}
    found = _get(effects, "replaceHeaders", "replace_headers")
    return [e for e in found if isinstance(e, dict)] if isinstance(found, list) else []


def keyed_api(host: str) -> Optional[str]:
    """The keyed API a hostname pattern covers, or None. `*` alone is not
    named here: JH709 reports a rule that allows every host."""
    h = host.lower().rstrip(".")
    if h in KEYED_API_HOSTS or h.endswith(KEYED_API_SUFFIXES):
        return h
    if h.startswith("*.") and h.count(".") >= 2:
        parent = h[1:]
        hit = next((k for k in KEYED_API_HOSTS if k.endswith(parent) and "." not in k[:-len(parent)]), None)
        if hit:
            return hit
    return None


def env_vars(doc: Dict[str, Any]) -> Iterator[Tuple[str, str, Any]]:
    """(container, name, value) for each container env var of an ActorTemplate."""
    for c in doc.get("containers") if isinstance(doc.get("containers"), list) else []:
        if not isinstance(c, dict):
            continue
        for e in c.get("env") if isinstance(c.get("env"), list) else []:
            if isinstance(e, dict) and isinstance(e.get("name"), str):
                yield str(c.get("name") or ""), e["name"], e.get("value")


def credential_value(name: str, value: Any) -> Optional[str]:
    """How a credential reaches the sandbox through this env var: "rendered"
    (a ${VAR} substitution at apply time), "literal", or None."""
    if not jh_agent._SECRET_NAME_RE.search(name) or _NOT_SECRET_NAME_RE.search(name):
        return None
    if not isinstance(value, str):
        return None
    v = value.strip()
    if _SUBSTITUTION_RE.fullmatch(v):
        return "rendered"
    if v.startswith(("/", "./")) or (re.match(r"(?i)^https?://", v) and "@" not in v):
        return None                     # a mounted file, or a URL without credentials in it
    if v.lower() in ("true", "false") or v.isdigit():
        return None
    if len(set(re.sub(r"^[A-Za-z]{2,10}[_-]", "", v))) <= 1:
        return None                     # a dummy such as crsr_000…0: a prefix and one repeated character
    return "literal" if jh_agent._literal(v) else None


def cluster_internal(host: str) -> bool:
    """A Kubernetes service name, reachable only inside the cluster."""
    h = host.lower().rstrip(".")
    return h.endswith((".svc.cluster.local", ".svc", ".cluster.local")) or (bool(h) and "." not in h)
