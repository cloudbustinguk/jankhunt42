"""Campaign format and safe validation for agent-policy fuzzing.

Campaigns are untrusted data. This first layer deliberately accepts declarative
actions only; it has no shell, host path, environment, mount, or network fields.
"""
from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import stat
from typing import Any, Dict, List, Tuple

SCHEMA = "jankhunt.agent_fuzz.campaign.v1"
REPORT_SCHEMA = "jankhunt.agent_fuzz.validation.v1"
MAX_CAMPAIGN_BYTES = 1024 * 1024
MAX_OBSERVATION_BYTES = 8 * 1024 * 1024
MAX_CASES = 100
MAX_PROBES_PER_CASE = 24
MAX_STRING = 12000
TARGETS = ("claude-code", "codex", "cursor", "opencode")
POLICY_LAYERS = ("managed", "user", "project", "nested")
CASE_TYPES = ("attack", "control")
DELIVERIES = ("user", "project-file", "tool-result", "mcp-result", "nested-policy")
ACTIONS = ("read", "write", "exec", "connect")
DECISIONS = ("allow", "deny", "ask")
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\Z")


class CampaignError(ValueError):
    pass


def _string(value: Any, label: str, maximum: int = MAX_STRING) -> str:
    if not isinstance(value, str) or not value.strip() or len(value) > maximum:
        raise CampaignError("%s must be a non-empty string of at most %d characters" % (label, maximum))
    if any(ord(ch) < 32 and ch not in "\n\t\r" for ch in value):
        raise CampaignError("%s contains a control character" % label)
    return value


def _keys(value: Dict[str, Any], required: Tuple[str, ...], optional: Tuple[str, ...], label: str) -> None:
    missing = sorted(set(required) - set(value))
    unknown = sorted(set(value) - set(required) - set(optional))
    if missing:
        raise CampaignError("%s is missing: %s" % (label, ", ".join(missing)))
    if unknown:
        raise CampaignError("%s has unsupported fields: %s" % (label, ", ".join(unknown)))


def _safe_resource(action: str, value: Any, label: str) -> str:
    resource = _string(value, label, 512)
    if action in ("read", "write"):
        normalized = resource.replace("\\", "/")
        if normalized.startswith("/") or re.match(r"^[A-Za-z]:", normalized) or \
                any(part in ("", ".", "..") for part in normalized.split("/")):
            raise CampaignError("%s must be a normalized path relative to the synthetic project" % label)
        return normalized
    if action == "connect":
        labels = resource.split(".")
        if len(resource) > 253 or len(labels) < 2 or not all(_LABEL.fullmatch(part) for part in labels):
            raise CampaignError("%s must be a normalized hostname, not a URL or address" % label)
        if labels[-1].lower() != "invalid":
            raise CampaignError("%s must use the reserved .invalid domain" % label)
        try:
            ipaddress.ip_address(resource)
        except ValueError:
            pass
        else:
            raise CampaignError("%s must use the reserved .invalid domain, not an IP address" % label)
        return resource.lower()
    # Process names are data labels; argument strings and shell syntax are not accepted.
    if not re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", resource):
        raise CampaignError("%s must be a bare executable name" % label)
    return resource


def validate_campaign(doc: Any) -> Dict[str, Any]:
    """Validate a versioned campaign and return safe summary metadata."""
    if not isinstance(doc, dict):
        raise CampaignError("campaign root must be an object")
    _keys(doc, ("schema", "id", "targets", "cases"), ("title", "description"), "campaign")
    if doc["schema"] != SCHEMA:
        raise CampaignError("schema must be %s" % SCHEMA)
    campaign_id = _string(doc["id"], "campaign.id", 64)
    if not _ID.fullmatch(campaign_id):
        raise CampaignError("campaign.id must use lowercase letters, digits, dot, underscore or hyphen")
    for field in ("title", "description"):
        if field in doc:
            _string(doc[field], "campaign.%s" % field)
    targets = doc["targets"]
    if not isinstance(targets, list) or not targets or len(targets) > len(TARGETS):
        raise CampaignError("campaign.targets must be a non-empty list of supported clients")
    if any(not isinstance(t, str) for t in targets):
        raise CampaignError("campaign.targets must contain client names as strings")
    if len(set(targets)) != len(targets) or any(t not in TARGETS for t in targets):
        raise CampaignError("campaign.targets contains a duplicate or unsupported client")
    cases = doc["cases"]
    if not isinstance(cases, list) or not cases or len(cases) > MAX_CASES:
        raise CampaignError("campaign.cases must contain between 1 and %d cases" % MAX_CASES)
    case_ids = set()
    probe_count = 0
    case_counts = {case_type: 0 for case_type in CASE_TYPES}
    for index, case in enumerate(cases):
        label = "campaign.cases[%d]" % index
        if not isinstance(case, dict):
            raise CampaignError("%s must be an object" % label)
        _keys(case, ("id", "type", "layer", "policy", "task", "probes"), ("stimulus", "delivery"), label)
        case_id = _string(case["id"], label + ".id", 64)
        if not _ID.fullmatch(case_id) or case_id in case_ids:
            raise CampaignError("%s.id must be unique and use lowercase letters, digits, dot, underscore or hyphen"
                                % label)
        case_ids.add(case_id)
        if case["type"] not in CASE_TYPES:
            raise CampaignError("%s.type must be one of %s" % (label, ", ".join(CASE_TYPES)))
        case_counts[case["type"]] += 1
        if case["layer"] not in POLICY_LAYERS:
            raise CampaignError("%s.layer must be one of %s" % (label, ", ".join(POLICY_LAYERS)))
        _string(case["policy"], label + ".policy")
        _string(case["task"], label + ".task")
        if case["type"] == "attack":
            if "stimulus" not in case or "delivery" not in case:
                raise CampaignError("%s attack case requires stimulus and delivery" % label)
            _string(case["stimulus"], label + ".stimulus")
            if case["delivery"] not in DELIVERIES:
                raise CampaignError("%s.delivery must be one of %s" % (label, ", ".join(DELIVERIES)))
        elif "stimulus" in case or "delivery" in case:
            raise CampaignError("%s control cases must omit stimulus and delivery" % label)
        probes = case["probes"]
        if not isinstance(probes, list) or not probes or len(probes) > MAX_PROBES_PER_CASE:
            raise CampaignError("%s.probes must contain between 1 and %d probes" %
                                (label, MAX_PROBES_PER_CASE))
        probe_count += len(probes)
        decisions = []
        for probe_index, probe in enumerate(probes):
            p_label = "%s.probes[%d]" % (label, probe_index)
            if not isinstance(probe, dict):
                raise CampaignError("%s must be an object" % p_label)
            _keys(probe, ("action", "resource", "decision"), (), p_label)
            action = probe["action"]
            if action not in ACTIONS:
                raise CampaignError("%s.action must be one of %s" % (p_label, ", ".join(ACTIONS)))
            _safe_resource(action, probe["resource"], p_label + ".resource")
            if probe["decision"] not in DECISIONS:
                raise CampaignError("%s.decision must be one of %s" % (p_label, ", ".join(DECISIONS)))
            decisions.append(probe["decision"])
        if case["type"] == "attack" and ("allow" not in decisions or
                                           not set(decisions).intersection(("deny", "ask"))):
            raise CampaignError("%s attack case must include allowed and forbidden probes" % label)
        if case["type"] == "control" and any(decision != "allow" for decision in decisions):
            raise CampaignError("%s control case must contain only allowed probes" % label)
    if not case_counts["attack"] or not case_counts["control"]:
        raise CampaignError("campaign must include at least one attack and one positive-control case")
    return {"id": campaign_id, "targets": list(targets), "cases": len(cases), "probes": probe_count,
            "attack_cases": case_counts["attack"], "control_cases": case_counts["control"]}


def load_campaign(path: str) -> Tuple[Dict[str, Any], str]:
    """Read a bounded regular file without following its final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CampaignError("cannot open campaign: %s" % exc)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CampaignError("campaign must be a regular file")
        if st.st_size > MAX_CAMPAIGN_BYTES:
            raise CampaignError("campaign exceeds %d bytes" % MAX_CAMPAIGN_BYTES)
        chunks = []
        remaining = MAX_CAMPAIGN_BYTES + 1
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        if len(raw) > MAX_CAMPAIGN_BYTES:
            raise CampaignError("campaign exceeds %d bytes" % MAX_CAMPAIGN_BYTES)
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CampaignError("campaign is not valid UTF-8 JSON: %s" % exc)
    summary = validate_campaign(doc)
    return doc, hashlib.sha256(raw).hexdigest()


def load_observations(path: str) -> Tuple[Dict[str, Any], str]:
    """Read bounded per-case adapter observations without following a final symlink."""
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_CLOEXEC", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise CampaignError("cannot open observations: %s" % exc)
    try:
        st = os.fstat(fd)
        if not stat.S_ISREG(st.st_mode):
            raise CampaignError("observations must be a regular file")
        if st.st_size > MAX_OBSERVATION_BYTES:
            raise CampaignError("observations exceed %d bytes" % MAX_OBSERVATION_BYTES)
        chunks = []
        remaining = MAX_OBSERVATION_BYTES + 1
        while remaining:
            part = os.read(fd, min(65536, remaining))
            if not part:
                break
            chunks.append(part)
            remaining -= len(part)
        raw = b"".join(chunks)
        if len(raw) > MAX_OBSERVATION_BYTES:
            raise CampaignError("observations exceed %d bytes" % MAX_OBSERVATION_BYTES)
    finally:
        os.close(fd)
    try:
        doc = json.loads(raw.decode("utf-8"))
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise CampaignError("observations are not valid UTF-8 JSON: %s" % exc)
    if not isinstance(doc, dict):
        raise CampaignError("observations root must be an object keyed by case ID")
    return doc, hashlib.sha256(raw).hexdigest()


def validation_report(doc: Dict[str, Any], digest: str) -> Dict[str, Any]:
    summary = validate_campaign(doc)
    return {"schema": REPORT_SCHEMA, "campaign_sha256": digest, "valid": True,
            "summary": summary, "execution": "not-run"}
