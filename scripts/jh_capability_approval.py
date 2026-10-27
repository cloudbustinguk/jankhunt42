"""External, declared-by-operator acceptance of an exact concrete access delta.

No signature, actor authentication, application acceptance or runtime grant.
The operator must protect both the policy and record from the agent's writes.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import jh_capabilities as C
import jh_ceiling
import jh_graph as G

SCHEMA = "jankhunt.capability-approval.v1"
BINDINGS = ("model", "subject_id", "base_sha", "head_sha", "context_hash", "delta_hash", "policy_hash")
FIELDS = {"schema", *BINDINGS, "approved_request_ids", "approved_by", "issued_at", "expires_at", "rationale"}
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}\Z")


def configuration(raw):
    """Validate partial policy settings; an empty object grants nothing."""
    if not isinstance(raw, dict) or set(raw) - {"subject_id", "approvers", "max_lifetime_seconds"}:
        raise ValueError("invalid capability_approvals policy fields")
    out = dict(raw)
    if "subject_id" in out and (not isinstance(out["subject_id"], str) or not IDENTIFIER.fullmatch(out["subject_id"])):
        raise ValueError("capability_approvals subject_id must be an opaque identifier")
    if "approvers" in out:
        values = out["approvers"]
        if not isinstance(values, list) or len(values) > 100 or any(not isinstance(v, str) or not IDENTIFIER.fullmatch(v) for v in values):
            raise ValueError("capability_approvals approvers must be a bounded list of identifiers")
        out["approvers"] = sorted(set(values))
    if "max_lifetime_seconds" in out and (type(out["max_lifetime_seconds"]) is not int or
                                          not 1 <= out["max_lifetime_seconds"] <= 2592000):
        raise ValueError("capability_approvals lifetime must be 1 through 2592000 seconds")
    return out


def _settings(policy):
    cfg = policy.get("capability_approvals") or {}
    if not cfg.get("subject_id") or not cfg.get("approvers") or not cfg.get("max_lifetime_seconds"):
        raise ValueError("external policy must configure capability_approvals subject_id, approvers and max_lifetime_seconds")
    return cfg


def unreviewable(delta):
    reasons = []
    if delta.get("model") != C.MODEL or delta.get("state") != "complete":
        reasons.append("comparison-incomplete")
    counts, trunc = delta.get("counts") or {}, delta.get("truncation") or {}
    if counts.get("lower_bound"):
        reasons.append("lower-bound-counts")
    if trunc.get("truncated") or any(counts.get(key, 0) != len(delta.get(field) or []) for key, field in
            (("total", "requests"), ("unknown", "unknowns"), ("unchanged_unknown", "unchanged_unknowns"))):
        reasons.append("review-rows-omitted")
    if counts.get("unknown") or delta.get("unknowns"):
        reasons.append("active-unknowns")
    if any(r.get("certainty") != "supported" for r in delta.get("requests", [])):
        reasons.append("requests-not-concrete")
    return reasons


def _bindings(delta, cfg, policy_hash):
    return {key: cfg["subject_id"] if key == "subject_id" else policy_hash if key == "policy_hash" else delta[key]
            for key in BINDINGS}


def _now():
    # Approval validity uses the real clock, never SOURCE_DATE_EPOCH.
    return datetime.now(timezone.utc).replace(microsecond=0)


def _utc(text):
    if not isinstance(text, str) or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", text):
        raise ValueError("dates must be UTC timestamps with seconds and Z")
    return datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def template(delta, policy, policy_hash, now=None):
    problems = unreviewable(delta)
    if problems:
        raise ValueError("cannot emit capability approval: " + ", ".join(problems))
    cfg = _settings(policy)
    return dict(schema=SCHEMA, **_bindings(delta, cfg, policy_hash),
                approved_request_ids=sorted(r["id"] for r in delta["requests"]),
                issued_at=(now or _now()).strftime("%Y-%m-%dT%H:%M:%SZ"),
                approved_by="", expires_at="", rationale="")


def _shape(doc):
    if not isinstance(doc, dict) or set(doc) != FIELDS or doc.get("schema") != SCHEMA:
        raise ValueError("unsupported capability approval schema or fields")
    if any(not isinstance(doc[key], str) for key in FIELDS - {"approved_request_ids"}):
        raise ValueError("capability approval fields must be strings")
    ids = doc["approved_request_ids"]
    if not isinstance(ids, list) or len(ids) > C.MAX_REQUESTS or any(not isinstance(v, str) or
            not re.fullmatch(r"[0-9a-f]{64}", v) for v in ids) or len(set(ids)) != len(ids):
        raise ValueError("capability approval needs unique exact request IDs, without wildcards")
    if len(doc["rationale"]) > 2000:
        raise ValueError("capability approval rationale exceeds the length limit")


def load(path, root):
    doc = jh_ceiling.read_external_json(path, root, "capability approval")
    _shape(doc)
    return doc


def evaluate(record, delta, policy, policy_hash, label="", now=None):
    result = dict(schema=SCHEMA, state="not-supplied", assurance="none", reasons=[])
    if record is None:
        return result
    result.update(state="invalid", record=G.sanitize_text(label, 200))
    try:
        _shape(record)
        cfg = _settings(policy)
    except ValueError:
        result["reasons"] = ["record-or-operator-policy-invalid"]
        return result
    reasons = unreviewable(delta)
    expected = _bindings(delta, cfg, policy_hash)
    for key in BINDINGS:
        if record[key] != expected[key]:
            reasons.append(key + "-mismatch")
    required = {r["id"] for r in delta["requests"]}
    if set(record["approved_request_ids"]) != required:
        reasons.append("request-coverage-mismatch")
    if record["approved_by"] not in cfg["approvers"]:
        reasons.append("approver-not-allowed")
    if not record["rationale"].strip():
        reasons.append("rationale-missing")
    try:
        issued, expires = _utc(record["issued_at"]), _utc(record["expires_at"])
        clock = now or _now()
        if not issued <= clock < expires:
            reasons.append("record-future-or-expired")
        if expires <= issued or (expires - issued).total_seconds() > cfg["max_lifetime_seconds"]:
            reasons.append("lifetime-not-allowed")
    except ValueError:
        reasons.append("invalid-utc-dates")
    result["reasons"] = sorted(set(reasons))
    if not reasons:
        result.update(state="accepted", assurance="declared-by-operator", subject_id=cfg["subject_id"],
                      approved_by=record["approved_by"], issued_at=record["issued_at"], expires_at=record["expires_at"],
                      rationale=G.sanitize_text(record["rationale"], 2000), approved_request_ids=sorted(required))
    return result


def approver_line(approval):
    if approval.get("state") == "accepted":
        return "Access change accepted by operator record (%s; declared-by-operator); expires %s." % (
            approval["approved_by"], approval["expires_at"])
    if approval.get("state") == "invalid":
        return "Access approval record invalid: " + ", ".join(approval["reasons"]) + "."
    return ""
