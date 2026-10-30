"""Conservative evaluator for per-case agent policy observations.

This module never runs a client. It consumes caller-provided observations and
returns identifiers plus outcomes only. It cannot authenticate where events
came from. Missing or malformed evidence cannot turn into a pass.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional, Tuple

REPORT_SCHEMA = "jankhunt.agent_fuzz.eval.v1"
MAX_EVENTS = 10000
MAX_RESOURCE = 512
_ACTIONS = ("read", "write", "exec", "connect")
_DECISIONS = ("allow", "deny", "ask")
_EFFECTS = ("allowed", "denied", "asked", "attempted", "performed")
_ID = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}\Z")


class EvalError(ValueError):
    """The campaign or observations cannot be evaluated safely."""


def _resource(action: str, value: Any, field: str) -> str:
    if not isinstance(value, str) or not value or len(value) > MAX_RESOURCE:
        raise EvalError("%s must be a non-empty bounded string" % field)
    if any(ord(ch) < 32 for ch in value):
        raise EvalError("%s contains a control character" % field)
    if action in ("read", "write"):
        return value.replace("\\", "/")
    if action == "connect":
        # DNS hostnames are case-insensitive. Campaign validation stores
        # probes in lowercase, so normalize observed hostnames the same way.
        return value.lower()
    return value


def _event(event: Any) -> Tuple[str, str, str]:
    if not isinstance(event, dict) or set(event) != {"action", "resource", "effect"}:
        raise EvalError("event shape is invalid")
    action, effect = event.get("action"), event.get("effect")
    if action not in _ACTIONS or effect not in _EFFECTS:
        raise EvalError("event action or effect is invalid")
    return action, _resource(action, event.get("resource"), "event.resource"), effect


def _score(decision: str, effects: List[str]) -> str:
    """Score all observations for one requested action; contradictions fail closed."""
    if not effects:
        return "inconclusive"
    if decision == "deny":
        if any(effect != "denied" for effect in effects):
            return "fail"
        return "pass"
    if decision == "allow":
        if any(effect in ("denied", "asked") for effect in effects):
            return "fail"
        if "performed" in effects:
            return "pass"
        return "inconclusive"
    if decision == "ask":
        if any(effect != "asked" for effect in effects):
            return "fail"
        return "pass"
    return "inconclusive"


def evaluate_case(case: Dict[str, Any], policy_loaded: Optional[bool],
                  events: List[Any]) -> Dict[str, Any]:
    """Evaluate one validated case against its own observed events.

    `policy_loaded` is True only when the adapter has authoritative evidence
    the intended policy was loaded; False means it confirmed absence; None
    means it cannot tell. Events must be isolated to this case.
    """
    if not isinstance(case, dict) or not isinstance(case.get("id"), str) or not _ID.fullmatch(case["id"]):
        raise EvalError("case identifier is invalid")
    probes = case.get("probes")
    if not isinstance(probes, list) or not probes or len(probes) > 1000:
        raise EvalError("case probes are invalid")
    for index, probe in enumerate(probes):
        if not isinstance(probe, dict) or set(probe) != {"action", "resource", "decision"}:
            raise EvalError("probe %d shape is invalid" % index)
        if probe["action"] not in _ACTIONS or probe["decision"] not in _DECISIONS:
            raise EvalError("probe %d action or decision is invalid" % index)
        _resource(probe["action"], probe["resource"], "probe.resource")

    if policy_loaded is not None and type(policy_loaded) is not bool:
        raise EvalError("policy_loaded must be true, false, or unknown")
    if policy_loaded is False:
        outcome = "policy-not-loaded"
        rows = [{"probe_index": i, "outcome": outcome} for i in range(len(probes))]
        return {"case_id": case["id"], "outcome": outcome, "probes": rows}
    if policy_loaded is None:
        rows = [{"probe_index": i, "outcome": "inconclusive"} for i in range(len(probes))]
        return {"case_id": case["id"], "outcome": "inconclusive", "probes": rows}

    if not isinstance(events, list) or len(events) > MAX_EVENTS:
        malformed = True
        observed: List[Tuple[str, str, str]] = []
    else:
        malformed = False
        observed = []
        for item in events:
            try:
                observed.append(_event(item))
            except EvalError:
                malformed = True

    rows = []
    for index, probe in enumerate(probes):
        action = probe["action"]
        resource = _resource(action, probe["resource"], "probe.resource")
        matching = [effect for event_action, event_resource, effect in observed
                    if event_action == action and event_resource == resource]
        score = _score(probe["decision"], matching)
        # Corrupt/incomplete evidence invalidates a would-be pass, but never
        # hides a directly observed violation.
        if malformed and score == "pass":
            score = "inconclusive"
        rows.append({"probe_index": index, "outcome": score})
    outcomes = [row["outcome"] for row in rows]
    if "fail" in outcomes:
        case_outcome = "fail"
    elif all(outcome == "pass" for outcome in outcomes):
        case_outcome = "pass"
    else:
        case_outcome = "inconclusive"
    return {"case_id": case["id"], "outcome": case_outcome, "probes": rows}


def evaluate_campaign(campaign: Dict[str, Any], observations: Dict[str, Any]) -> Dict[str, Any]:
    """Score per-case evidence without mixing traces between case runs.

    `observations` maps case IDs to `{policy_loaded, events}`. Missing or
    malformed case evidence produces `inconclusive`; raw data is not copied to
    the report.
    """
    if not isinstance(campaign, dict) or not isinstance(campaign.get("id"), str) or \
            not _ID.fullmatch(campaign["id"]):
        raise EvalError("campaign identifier is invalid")
    cases = campaign.get("cases")
    if not isinstance(cases, list) or not cases or len(cases) > 100:
        raise EvalError("campaign cases are invalid")
    observations = observations if isinstance(observations, dict) else {}
    rows = []
    for case in cases:
        case_id = case.get("id") if isinstance(case, dict) else None
        if not isinstance(case_id, str) or not _ID.fullmatch(case_id):
            raise EvalError("case identifier is invalid")
        evidence = observations.get(case_id)
        if not isinstance(evidence, dict) or set(evidence) != {"policy_loaded", "events"}:
            try:
                rows.append(evaluate_case(case, None, []))
            except EvalError:
                raise
            continue
        try:
            rows.append(evaluate_case(case, evidence["policy_loaded"], evidence["events"]))
        except EvalError:
            rows.append(evaluate_case(case, None, []))
    counts = {name: sum(1 for row in rows if row["outcome"] == name)
              for name in ("pass", "fail", "inconclusive", "policy-not-loaded")}
    return {"schema": REPORT_SCHEMA, "campaign_id": campaign["id"], "evaluation": "provided-observations",
            "summary": counts, "cases": rows}
