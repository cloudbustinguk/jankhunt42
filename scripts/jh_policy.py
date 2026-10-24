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

Profiles. `citizen` is for software built by people who are not software
engineers, typically with an AI coding agent. It tightens everything: a
named engineering custodian, observed tests and CI, declared data
classification, and no agent-guardrail bypasses or public exposure are
required, and unverified authority over production or restricted data
blocks instead of asking for review. A profile only ever tightens; the
repository can opt into `citizen` but never out of it.
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
    "P-CUS-001": "no engineering custodian named for the software",
    "P-DAT-001": "sensitive data export to an external destination",
    "P-DAT-002": "mutating, destructive, or unknown authority over a production, critical, or restricted asset",
    "P-DAT-003": "reachable data stores without a declared classification",
    "P-SEC-001": "credentials or data exposed to the public",
    "P-AGT-001": "AI agent guardrails bypassed, or agent tooling unpinned",
    "P-AI-001": "sensitive data and an external AI service are reachable together",
    "P-OPS-001": "automated tests or CI not observed",
    "P-EVD-001": "mandatory supply-chain evidence missing",
    "P-JNK-001": "Jank Score policy failed or blocker-severity leads present",
    "P-EXP-001": "exposure class above the policy maximum",
}
PROFILES = ("standard", "citizen")

DEFAULT_POLICY: Dict[str, Any] = {
    "schema_version": POLICY_SCHEMA,
    "profile": "standard",
    "require": {"owner": False, "sbom": False, "sbom_minimum": False, "attestation": False,
                "verified_attestation": False, "custodian": False, "tests": False, "ci": False,
                "classification": False},
    "actions": {"P-OWN-001": "review", "P-CUS-001": "block", "P-DAT-001": "review", "P-DAT-002": "review",
                "P-DAT-003": "insufficient-evidence", "P-SEC-001": "review", "P-AGT-001": "review",
                "P-AI-001": "review", "P-OPS-001": "review", "P-EVD-001": "insufficient-evidence",
                "P-JNK-001": "review", "P-EXP-001": "review"},
    "max_exposure": None,
    # What unverified (static) authority and export leads may do at most.
    "static_leads": "review",
}

# The citizen-developer profile: applied tighten-only on top of whatever is
# in force, so it can only make a decision stricter.
CITIZEN_PRESET: Dict[str, Any] = {
    "require": {"owner": True, "custodian": True, "tests": True, "ci": True, "classification": True},
    "actions": {"P-OWN-001": "block", "P-CUS-001": "block", "P-DAT-001": "block", "P-DAT-002": "block",
                "P-DAT-003": "insufficient-evidence", "P-SEC-001": "block", "P-AGT-001": "block",
                "P-AI-001": "block", "P-OPS-001": "block", "P-JNK-001": "block", "P-EXP-001": "block"},
    "max_exposure": "Moderate",
    "static_leads": "block",
}


class PolicyError(ValueError):
    pass


def _validate(raw: Dict[str, Any], label: str, warnings: List[str]) -> Dict[str, Any]:
    out: Dict[str, Any] = {"require": {}, "actions": {}}
    prof = raw.get("profile")
    if prof is not None:
        if prof in PROFILES:
            out["profile"] = prof
        else:
            warnings.append("%s policy: ignored profile %r" % (label, str(prof)[:20]))
    lead = raw.get("static_leads")
    if lead is not None:
        if lead in ("review", "block"):
            out["static_leads"] = lead
        else:
            warnings.append("%s policy: ignored static_leads %r" % (label, str(lead)[:20]))
    exc = raw.get("profile_exceptions")
    if exc is not None:
        if isinstance(exc, dict) and all(_valid_exception(k, v) for k, v in exc.items()):
            out["profile_exceptions"] = dict(sorted(exc.items()))
        else:
            warnings.append("%s policy: ignored profile_exceptions (expected rule ids mapped to actions, "
                            "require.<key>: false, max_exposure, or static_leads)" % label)
    cust = raw.get("custodians")
    if cust is not None:
        if isinstance(cust, list) and all(isinstance(c, str) and c.strip() for c in cust):
            out["custodians"] = sorted({c.strip()[:80] for c in cust})[:20]
        else:
            warnings.append("%s policy: ignored custodians (expected a list of names)" % label)
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


def _tighten(eff: Dict[str, Any], rp: Dict[str, Any], warnings: List[str], who: str = "repository") -> None:
    """Apply `rp` to `eff` so that nothing gets weaker."""
    for k, v in rp.get("require", {}).items():
        if v and not eff["require"][k]:
            eff["require"][k] = True
        elif not v and eff["require"][k]:
            warnings.append("%s policy cannot relax require.%s; ignored" % (who, k))
    for k, v in rp.get("actions", {}).items():
        if ACTION_RANK[v] > ACTION_RANK[eff["actions"][k]]:
            eff["actions"][k] = v
        elif ACTION_RANK[v] < ACTION_RANK[eff["actions"][k]]:
            warnings.append("%s policy cannot weaken %s from %s to %s; ignored" % (who, k, eff["actions"][k], v))
    mx = rp.get("max_exposure")
    if mx:
        cur = eff["max_exposure"]
        if cur is None or G.EXPOSURE_RANK[mx] < G.EXPOSURE_RANK[cur]:
            eff["max_exposure"] = mx
        elif G.EXPOSURE_RANK[mx] > G.EXPOSURE_RANK[cur]:
            warnings.append("%s policy cannot raise max_exposure above %s; ignored" % (who, cur))
    if rp.get("static_leads") == "block":
        eff["static_leads"] = "block"
    elif rp.get("static_leads") == "review" and eff["static_leads"] == "block":
        warnings.append("%s policy cannot relax static_leads; ignored" % who)


def _apply_profile(eff: Dict[str, Any], profile: str, warnings: Optional[List[str]] = None,
                   operator_set: Sequence[str] = ()) -> None:
    if profile == "citizen" and eff["profile"] != "citizen":
        before = dict(eff["actions"])
        _tighten(eff, CITIZEN_PRESET, [], "profile")
        eff["profile"] = "citizen"
        for rule in sorted(operator_set):
            if warnings is not None and eff["actions"][rule] != before[rule]:
                warnings.append("citizen profile overrides the operator action for %s (%s -> %s); use "
                                "profile_exceptions to relax a citizen rule deliberately"
                                % (rule, before[rule], eff["actions"][rule]))


def _valid_exception(key: str, value: Any) -> bool:
    if key in DEFAULT_POLICY["actions"]:
        return value in ACTIONS
    if key.startswith("require."):
        return key[8:] in DEFAULT_POLICY["require"] and value is False
    if key == "max_exposure":
        return value in ("Low", "Moderate", "High", "Critical")
    if key == "static_leads":
        return value in ("review", "block")
    return False


def _apply_exception(eff: Dict[str, Any], key: str, value: Any) -> None:
    if key in DEFAULT_POLICY["actions"]:
        eff["actions"][key] = value
    elif key.startswith("require."):
        eff["require"][key[8:]] = value
    else:
        eff[key] = value


def merge(operator: Optional[Dict[str, Any]], repository: Any,
          warnings: List[str], profile: Optional[str] = None) -> Dict[str, Any]:
    """Effective policy: defaults, operator overrides, then the citizen
    profile (tighten-only, so an ordinary operator policy cannot weaken it),
    then the operator's explicit `profile_exceptions` (each one warned), then
    repository tightening. `profile` is the operator's command-line choice.
    Repository input can raise actions, add requirements, lower
    max_exposure, and opt into the citizen profile; it can never relax
    anything."""
    eff = copy.deepcopy(DEFAULT_POLICY)
    eff["custodians"] = []
    eff["profile_exceptions"] = {}
    op = _validate(operator, "operator", warnings) if operator else {"require": {}, "actions": {}}
    eff["require"].update(op["require"])
    eff["actions"].update(op["actions"])
    if "max_exposure" in op:
        eff["max_exposure"] = op["max_exposure"]
    if "static_leads" in op:
        eff["static_leads"] = op["static_leads"]
    if op.get("custodians"):
        eff["custodians"] = op["custodians"]
    if "citizen" in (profile, op.get("profile")):
        exceptions = op.get("profile_exceptions", {})
        before = {"require": dict(eff["require"]), "max_exposure": eff["max_exposure"],
                  "static_leads": eff["static_leads"]}
        _apply_profile(eff, "citizen", warnings, [k for k in op["actions"] if k not in exceptions])
        for key in sorted(op["require"]):
            if eff["require"][key] != before["require"][key] and "require." + key not in exceptions:
                warnings.append("citizen profile overrides the operator's require.%s; use profile_exceptions "
                                "to relax it deliberately" % key)
        for key in ("max_exposure", "static_leads"):
            if key in op and eff[key] != before[key] and key not in exceptions:
                warnings.append("citizen profile overrides the operator's %s (%s -> %s); use profile_exceptions "
                                "to relax it deliberately" % (key, before[key], eff[key]))
        for key, value in exceptions.items():
            _apply_exception(eff, key, value)
            eff["profile_exceptions"][key] = value
            warnings.append("operator exception under the citizen profile: %s is %s" % (key, value))
    elif op.get("profile_exceptions"):
        warnings.append("operator policy: profile_exceptions apply only under the citizen profile; ignored")
    repositories = repository if isinstance(repository, (list, tuple)) else ([repository] if repository else [])
    for raw_repo in repositories:
        rp = _validate(raw_repo, "repository", warnings)
        if rp.get("profile") == "standard" and eff["profile"] == "citizen":
            warnings.append("repository policy cannot leave the citizen profile; ignored")
        _apply_profile(eff, rp.get("profile", "standard"))
        _tighten(eff, rp, warnings)
        if rp.get("custodians"):
            warnings.append("custodians in a repository policy are declarations; use passport.custodians")
        if rp.get("profile_exceptions"):
            warnings.append("repository policy cannot grant profile_exceptions; ignored")
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
    # P-CUS-001
    named = list(policy.get("custodians") or [])
    declared = list(facts.get("declared_custodians") or [])
    if not policy["require"]["custodian"]:
        add("P-CUS-001", "pass", "custodian not required by this policy")
    elif acts["P-CUS-001"] == "off" and not named:
        add("P-CUS-001", "pass", "custodian rule turned off by the operator policy")
    elif named:
        add("P-CUS-001", "pass", "custodian(s) named by the operator policy: %s" % ", ".join(named))
    elif declared:
        # The repository's author could name anyone, including themselves:
        # the declaration is recorded, but it does not satisfy the rule.
        outcome = OUTCOMES[max(OUTCOME_RANK["insufficient-evidence"], OUTCOME_RANK[_outcome_for(acts["P-CUS-001"])])]
        add("P-CUS-001", outcome, "custodian(s) declared only in the repository: %s; a custodian must be named in "
                                  "the operator policy" % ", ".join(declared))
    else:
        outcome = OUTCOMES[max(OUTCOME_RANK["insufficient-evidence"], OUTCOME_RANK[_outcome_for(acts["P-CUS-001"])])]
        add("P-CUS-001", outcome, "no engineering custodian is named (custodians in the operator policy, or "
                                  "passport.custodians as a declaration); someone with engineering responsibility "
                                  "must answer for this software")

    nodes = {n["id"]: n for n in (graph or {}).get("nodes", [])}
    edges = [e for e in (graph or {}).get("edges", []) if e.get("verification") != "refuted"]
    # P-DAT-001
    verified_x, static_x = [], []
    for e in edges:
        t = nodes.get(e["target"], {})
        if e["kind"] == "exports" and t.get("trust_domain") == "external" and \
                (e.get("data_sensitivity") in ("confidential", "restricted") or _sensitive(nodes.get(e["source"], {}))):
            (verified_x if e["verification"] == "provider-verified" else static_x).append(e["id"])
    cap = policy.get("static_leads", "review")
    if verified_x:
        add("P-DAT-001", "block", "verified export of sensitive data to an external destination", verified_x, floor=True)
    elif static_x:
        add("P-DAT-001", _outcome_for(acts["P-DAT-001"]) if acts["P-DAT-001"] != "block" or cap == "block" else "review",
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
        # Static leads ask for grant verification; they block only where the
        # policy says unverified authority must be proven first (citizen).
        lead = "pass" if acts["P-DAT-002"] == "off" else (
            _outcome_for(acts["P-DAT-002"]) if cap == "block" else "review")
        add("P-DAT-002", lead,
            "possible mutating, destructive, or unknown authority over a production, critical, or restricted asset; "
            "verify effective grants" + ("; unverified authority blocks under this policy" if lead == "block" else ""),
            potential_a)
    else:
        add("P-DAT-002", "pass", "0 such authorities observed")
    # P-DAT-003
    unclassified = [n for n in nodes.values() if n.get("kind") in ("database", "storage", "queue")
                    and n.get("trust_domain") != "local" and n.get("sensitivity") == "unknown"]
    if policy["require"]["classification"] and unclassified:
        labels = sorted(str(n.get("display_label", n["id"])) for n in unclassified)
        add("P-DAT-003", _outcome_for(acts["P-DAT-003"]),
            "%d reachable data store(s) have no declared sensitivity: %s" % (len(labels), ", ".join(labels[:5])),
            [n["id"] for n in unclassified])
    else:
        add("P-DAT-003", "pass", "data classification not required" if not policy["require"]["classification"]
            else "every reachable data store has a declared sensitivity")
    # P-SEC-001 and P-AGT-001 (scanner leads with a public or agent blast radius)
    for rule, key, what in (("P-SEC-001", "exposure_findings", "public exposure"),
                            ("P-AGT-001", "agent_findings", "agent guardrail")):
        found = list(facts.get(key) or [])
        if found:
            add(rule, _outcome_for(acts[rule]), "%d %s lead(s): %s" % (
                len(found), what, "; ".join("%s %s:%s" % (f["rule"], f["path"], f["line"]) for f in found[:5])),
                ["finding:%s:%s:%s" % (f["rule"], f["path"], f["line"]) for f in found])
        else:
            add(rule, "pass", "0 %s leads" % what)
    # P-AI-001: co-reachability, not a data flow; it asks for the provider's
    # data handling to be checked before release.
    pairs = list(facts.get("ai_sensitive_pairs") or [])
    if pairs:
        by_service: Dict[str, List[str]] = {}
        for p in pairs:
            by_service.setdefault(p["ai_service"], [])
            if p["data"] not in by_service[p["ai_service"]]:
                by_service[p["ai_service"]].append(p["data"])
        shown = "; ".join("%s with %s" % (svc, ", ".join(stores))
                          for svc, stores in sorted(by_service.items())[:3])
        add("P-AI-001", _outcome_for(acts["P-AI-001"]),
            "%d confidential or restricted data store(s) are reachable alongside an external AI service; confirm "
            "what data reaches the provider and how it is handled (retention, training use, region) before "
            "release: %s" % (len({p["data"] for p in pairs}), shown),
            [p["data_id"] for p in pairs] + [p["ai_service_id"] for p in pairs])
    elif graph is None:
        add("P-AI-001", "pass", "not assessed: without a connectivity map, reach to AI services is unknown")
    else:
        add("P-AI-001", "pass", "no confidential or restricted data store is reachable alongside an external AI service")
    # P-OPS-001
    ops = facts.get("operations") or {}
    missing_ops = [area for area in ("tests", "ci") if policy["require"][area] and ops.get(area) != "observed"]
    if missing_ops:
        add("P-OPS-001", _outcome_for(acts["P-OPS-001"]), "%s not observed in the repository%s" % (
            " and ".join(missing_ops), "; a declaration is not enough under this policy"
            if any(ops.get(a) == "declared" for a in missing_ops) else ""))
    else:
        add("P-OPS-001", "pass", "tests and CI not required" if not (policy["require"]["tests"] or policy["require"]["ci"])
            else "required tests/CI evidence observed")
    # P-EVD-001
    sup = facts.get("supply") or {}
    missing = []
    if policy["require"]["sbom"] and not sup.get("sbom"):
        missing.append("SBOM")
    if policy["require"]["sbom_minimum"] and sup.get("sbom_minimum") != "met":
        missing.append("an SBOM meeting the NTIA minimum elements (best: %s)" % sup.get("sbom_minimum", "none"))
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
