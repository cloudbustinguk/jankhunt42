#!/usr/bin/env python3
"""Minimal, explainable release-assessment policy for `jankhunt42 passport`.

The decision is pass | review | insufficient-evidence | block. It is the
most severe outcome of a handful of named rules, never a weighted average,
and every triggered rule names the evidence behind it.

Precedence: operator policy (a --policy file outside the scanned
repository) > defaults; repository config can only *tighten* whatever is
in force. A policy path inside the repository is repository-controlled and
gets tighten-only treatment, whatever it claims about itself. A local path
alone does not establish organizational authority, so the strongest label
this tool ever applies is "operator-supplied".

Hard floors no policy can lower:
  * no files assessed, no supported files mapped, or truncated analysis
    -> insufficient-evidence (a partial scan never passes)
  * verified (provider-verified) sensitive export to an external
    destination -> block
"""
from __future__ import annotations

import copy
import json
from typing import Any, Dict, List, Optional, Sequence, Tuple

import jh_graph as G

POLICY_SCHEMA = "jankhunt.policy.v1"
OUTCOMES = ("pass", "review", "insufficient-evidence", "block")
OUTCOME_RANK = {o: i for i, o in enumerate(OUTCOMES)}
ACTIONS = ("off", "review", "insufficient-evidence", "block")
ACTION_RANK = {a: i for i, a in enumerate(ACTIONS)}

RULES = {
    "P-COV-001": "assessment coverage is missing, partial, or truncated (hard floor)",
    "P-OWN-001": "accountable owner not established",
    "P-DAT-001": "sensitive data export to an external destination",
    "P-DAT-002": "mutating, destructive, or unknown authority over a production, critical, or restricted asset",
    "P-EVD-001": "mandatory supply-chain evidence missing",
    "P-JNK-001": "Jank Score policy failed or blocker-severity leads present",
    "P-EXP-001": "exposure class above the policy maximum",
}

DEFAULT_POLICY: Dict[str, Any] = {
    "schema_version": POLICY_SCHEMA,
    "require": {"owner": False, "sbom": False, "attestation": False, "verified_attestation": False},
    "actions": {"P-OWN-001": "review", "P-DAT-001": "review", "P-DAT-002": "review",
                "P-EVD-001": "insufficient-evidence", "P-JNK-001": "review", "P-EXP-001": "review"},
    "max_exposure": None,
}


class PolicyError(ValueError):
    pass


def _validate(raw: Dict[str, Any], label: str, warnings: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"require": {}, "actions": {}}
    req = raw.get("require") or {}
    if isinstance(req, dict):
        for k, v in req.items():
            if k in DEFAULT_POLICY["require"] and isinstance(v, bool):
                out["require"][k] = v
            else:
                warnings.append("%s policy: ignored require.%s" % (label, str(k)[:30]))
    acts = raw.get("actions") or {}
    if isinstance(acts, dict):
        for k, v in acts.items():
            if k in DEFAULT_POLICY["actions"] and v in ACTIONS:
                out["actions"][k] = v
            else:
                warnings.append("%s policy: ignored actions.%s" % (label, str(k)[:30]))
    mx = raw.get("max_exposure")
    if mx is not None:
        if mx in ("Low", "Moderate", "High", "Critical"):
            out["max_exposure"] = mx
        else:
            warnings.append("%s policy: ignored max_exposure %r" % (label, str(mx)[:20]))
    return out


def merge(operator: Optional[Dict[str, Any]], repository: Optional[Dict[str, Any]],
          warnings: List[str]) -> Dict[str, Any]:
    """Effective policy: defaults, then operator overrides, then repository
    tightening. Repository input can raise actions, add requirements, and
    lower max_exposure; it can never relax anything."""
    eff = copy.deepcopy(DEFAULT_POLICY)
    if operator:
        op = _validate(operator, "operator", warnings)
        eff["require"].update(op["require"])
        eff["actions"].update(op["actions"])
        if "max_exposure" in op:
            eff["max_exposure"] = op["max_exposure"]
    if repository:
        rp = _validate(repository, "repository", warnings)
        for k, v in rp["require"].items():
            if v and not eff["require"][k]:
                eff["require"][k] = True
            elif not v and eff["require"][k]:
                warnings.append("repository policy cannot relax require.%s; ignored" % k)
        for k, v in rp["actions"].items():
            if ACTION_RANK[v] > ACTION_RANK[eff["actions"][k]]:
                eff["actions"][k] = v
            elif ACTION_RANK[v] < ACTION_RANK[eff["actions"][k]]:
                warnings.append("repository policy cannot weaken %s from %s to %s; ignored" % (k, eff["actions"][k], v))
        mx = rp.get("max_exposure")
        if mx:
            cur = eff["max_exposure"]
            if cur is None or G.EXPOSURE_RANK[mx] < G.EXPOSURE_RANK[cur]:
                eff["max_exposure"] = mx
            elif G.EXPOSURE_RANK[mx] > G.EXPOSURE_RANK[cur]:
                warnings.append("repository policy cannot raise max_exposure above %s; ignored" % cur)
    return eff


def policy_hash(policy: Dict[str, Any]) -> str:
    return G.sha(G.canonical_json(policy), 32)


def _outcome_for(action: str) -> str:
    return "pass" if action == "off" else action


def _sensitive(node: Dict[str, Any]) -> bool:
    return node.get("sensitivity") in ("confidential", "restricted")


def _critical(node: Dict[str, Any]) -> bool:
    return (node.get("environment") == "production" or node.get("criticality") in ("high", "critical")
            or node.get("sensitivity") == "restricted")


def evaluate(policy: Dict[str, Any], facts: Dict[str, Any], graph: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """Evaluate every rule. Returns {"result", "rules": [...], "reasons": [...]}."""
    results: List[Dict[str, Any]] = []
    acts = policy["actions"]

    def add(rule: str, outcome: str, message: str, refs: Sequence[str] = (), floor: bool = False) -> None:
        results.append({"rule": rule, "title": RULES[rule], "outcome": outcome, "message": message,
                        "evidence_refs": sorted(set(refs))[:20], "hard_floor": floor})

    # P-COV-001 (floor)
    cov_reasons = []
    if facts.get("files_scanned", 0) <= 0:
        cov_reasons.append("no files were scanned")
    if graph is None:
        cov_reasons.append("connectivity map not available")
    elif facts.get("map_files_inspected", 0) <= 0:
        cov_reasons.append("no supported files for connectivity discovery")
    if facts.get("truncated"):
        cov_reasons.append("analysis truncated: %s" % "; ".join(facts.get("truncation_reasons") or ["limit reached"]))
    if facts.get("map_status") == "partial":
        cov_reasons.append("connectivity coverage partial: %s" % "; ".join(facts.get("map_partial_reasons") or []))
    add("P-COV-001", "insufficient-evidence" if cov_reasons else "pass",
        "; ".join(cov_reasons) or "scan and map coverage present", floor=True)

    exposure = facts.get("exposure", "Unknown")
    # P-OWN-001
    owner = facts.get("owner_state", "unknown")
    if owner == "unknown":
        if policy["require"]["owner"]:
            outcome = OUTCOMES[max(OUTCOME_RANK["insufficient-evidence"], OUTCOME_RANK[_outcome_for(acts["P-OWN-001"])])]
            add("P-OWN-001", outcome, "policy requires an accountable owner; none observed or declared")
        elif G.EXPOSURE_RANK.get(exposure, 0) >= G.EXPOSURE_RANK["High"]:
            add("P-OWN-001", _outcome_for(acts["P-OWN-001"]),
                "exposure is %s and no accountable owner is observed or declared" % exposure)
        else:
            add("P-OWN-001", "pass", "owner not established; not required at exposure %s" % exposure)
    else:
        add("P-OWN-001", "pass", "owner %s" % owner)

    nodes = {n["id"]: n for n in (graph or {}).get("nodes", [])}
    edges = [e for e in (graph or {}).get("edges", []) if e.get("verification") != "refuted"]
    # P-DAT-001
    verified_x, static_x = [], []
    for e in edges:
        t = nodes.get(e["target"], {})
        if e["kind"] == "exports" and t.get("trust_domain") == "external" and \
                (e.get("data_sensitivity") in ("confidential", "restricted") or _sensitive(nodes.get(e["source"], {}))):
            (verified_x if e["verification"] == "provider-verified" else static_x).append(e["id"])
    if verified_x:
        add("P-DAT-001", "block", "verified export of sensitive data to an external destination", verified_x, floor=True)
    elif static_x:
        add("P-DAT-001", _outcome_for(acts["P-DAT-001"]) if acts["P-DAT-001"] != "block" else "review",
            "declared or observed sensitive export to an external destination; verify the flow", static_x)
    else:
        add("P-DAT-001", "pass", "0 sensitive external exports observed (co-reachability alone is not a flow)")
    # P-DAT-002
    verified_a, potential_a = [], []
    for e in edges:
        t = nodes.get(e["target"], {})
        if not _critical(t):
            continue
        if e["capability"] in ("write", "delete", "admin"):
            (verified_a if e["verification"] == "provider-verified" else potential_a).append(e["id"])
        elif e["capability"] == "unknown" and e["kind"] in ("connects", "calls"):
            potential_a.append(e["id"])
    if verified_a:
        add("P-DAT-002", _outcome_for(acts["P-DAT-002"]),
            "verified mutating/destructive authority over a production, critical, or restricted asset", verified_a)
    elif potential_a:
        # Static leads never block by themselves: they ask for grant verification.
        add("P-DAT-002", "review" if acts["P-DAT-002"] != "off" else "pass",
            "possible mutating, destructive, or unknown authority over a production, critical, or restricted asset; "
            "verify effective grants", potential_a)
    else:
        add("P-DAT-002", "pass", "0 such authorities observed")
    # P-EVD-001
    sup = facts.get("supply") or {}
    missing = []
    if policy["require"]["sbom"] and not sup.get("sbom"):
        missing.append("SBOM")
    if policy["require"]["attestation"] and not sup.get("attestations"):
        missing.append("attestation")
    if policy["require"]["verified_attestation"] and not sup.get("verified_attestations"):
        missing.append("verified attestation (exporter- or tool-verified)")
    if sup.get("verification_problems"):
        # --verify was requested and did not complete cleanly: never a pass.
        missing.append("completed attestation verification (%d problem(s))" % len(sup["verification_problems"]))
    if missing:
        add("P-EVD-001", _outcome_for(acts["P-EVD-001"]), "required evidence missing: %s" % ", ".join(missing))
    else:
        add("P-EVD-001", "pass", "no mandatory supply-chain evidence missing")
    # P-JNK-001
    jp = facts.get("jank_policy", "pass")
    blockers = int(facts.get("blocker_leads", 0))
    if jp == "fail" or blockers:
        add("P-JNK-001", _outcome_for(acts["P-JNK-001"]),
            "Jank Score policy %s; %d blocker-severity lead(s) (leads, not confirmed defects)" % (jp, blockers))
    else:
        add("P-JNK-001", "pass", "Jank Score policy %s; 0 blocker leads" % jp)
    # P-EXP-001
    mx = policy.get("max_exposure")
    if mx:
        if exposure == "Unknown":
            add("P-EXP-001", "insufficient-evidence", "exposure Unknown; policy maximum is %s" % mx)
        elif G.EXPOSURE_RANK[exposure] > G.EXPOSURE_RANK[mx]:
            add("P-EXP-001", _outcome_for(acts["P-EXP-001"]), "exposure %s exceeds policy maximum %s" % (exposure, mx))
        else:
            add("P-EXP-001", "pass", "exposure %s within policy maximum %s" % (exposure, mx))
    else:
        add("P-EXP-001", "pass", "no maximum exposure configured")

    result = "pass"
    for r in results:
        if OUTCOME_RANK[r["outcome"]] > OUTCOME_RANK[result]:
            result = r["outcome"]
    reasons = [r for r in results if r["outcome"] != "pass"]
    return {"result": result, "rules": results, "reasons": reasons}


def load_policy_file(path: str) -> Dict[str, Any]:
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError) as exc:
        raise PolicyError("cannot read policy %s: %s" % (path, exc))
    if not isinstance(data, dict):
        raise PolicyError("policy must be a JSON object")
    return data


def fails(decision: str, fail_on: Optional[str]) -> bool:
    """Enforcement is opt-in: only an explicit --fail-on gates the exit code."""
    if not fail_on:
        return False
    return OUTCOME_RANK[decision] >= OUTCOME_RANK[fail_on]
