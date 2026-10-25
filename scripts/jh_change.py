#!/usr/bin/env python3
"""Change-control (merge-gate) evidence for the passport: can code reach the
default branch without an independent human review?

Sources, strongest first:
  * an operator export of the repository's rulesets or branch protection,
    as the GitHub REST API returns them, passed from outside the
    repository: provider-verified (inside the repository it is only
    declared, whatever it says);
  * Terraform github_repository_ruleset / github_branch_protection in the
    repository: declared intent, not proof of what is applied;
  * nothing: unknown, never "absent".

The default branch's checks: a pull-request rule with at least one
approval, code-owner review, approval of the last push, required status
checks, deletion and force-push protection, no bypass for GitHub Apps
(Integration) or deploy keys, and a CODEOWNERS file covering the tree.
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import jh_hcl

CHECKS = ("pull_request_review", "code_owner_review", "last_push_approval", "status_checks",
          "deletion_protected", "force_push_protected", "no_app_bypass", "codeowners_coverage")
# Without these an unreviewed change can land (P-CHG-001 at its full action).
SEVERE = ("pull_request_review", "no_app_bypass")
APP_ACTORS = ("Integration", "DeployKey")
_CODEOWNERS = ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS")
_CATCH_ALL = {"*", "/*", "**", "/**", "/", "**/*"}


def _targets_default(conditions: Any, default_branch: str) -> bool:
    """Whether a ruleset's ref_name conditions include the default branch."""
    ref = (conditions or {}).get("ref_name") if isinstance(conditions, dict) else None
    if not isinstance(ref, dict):
        return True                     # no condition: the ruleset applies to every branch
    include = [str(x) for x in ref.get("include") or []]
    exclude = [str(x) for x in ref.get("exclude") or []]
    names = {"~DEFAULT_BRANCH", "~ALL", "refs/heads/%s" % default_branch, default_branch}

    def hit(patterns: Sequence[str]) -> bool:
        return any(p in names or re.fullmatch(re.escape(p).replace(r"\*\*", ".*").replace(r"\*", "[^/]*"),
                                               "refs/heads/%s" % default_branch) for p in patterns)
    return hit(include) and not hit(exclude)


class _Gate:
    """The strongest combination of every rule that applies to the branch."""

    def __init__(self) -> None:
        self.approvals: Optional[int] = None
        self.code_owner: Optional[bool] = None
        self.last_push: Optional[bool] = None
        self.checks: Optional[List[str]] = None
        self.deletion: Optional[bool] = None
        self.force_push: Optional[bool] = None
        self.bypass: Optional[List[Dict[str, str]]] = None   # None: bypass actors not visible in the source
        self.rule_seen = False

    def pr(self, approvals: Optional[int], code_owner: Optional[bool], last_push: Optional[bool]) -> None:
        self.rule_seen = True
        if approvals is not None:
            self.approvals = max(self.approvals or 0, approvals)
        if code_owner is not None:
            self.code_owner = bool(self.code_owner) or code_owner
        if last_push is not None:
            self.last_push = bool(self.last_push) or last_push

    def add_bypass(self, actors: Sequence[Dict[str, Any]]) -> None:
        self.bypass = (self.bypass or []) + [
            {"actor_type": str(a.get("actor_type", "")), "bypass_mode": str(a.get("bypass_mode", "always")),
             "actor_id": str(a.get("actor_id", ""))} for a in actors if isinstance(a, dict)]


def _ruleset_rules(gate: _Gate, rules: Sequence[Any]) -> None:
    for rule in rules:
        if not isinstance(rule, dict):
            continue
        kind = rule.get("type")
        p = rule.get("parameters") if isinstance(rule.get("parameters"), dict) else {}
        if kind == "pull_request":
            gate.pr(int(p.get("required_approving_review_count") or 0), bool(p.get("require_code_owner_review")),
                    bool(p.get("require_last_push_approval")))
        elif kind == "required_status_checks":
            gate.rule_seen = True
            ctx = [str(c.get("context")) for c in p.get("required_status_checks") or [] if isinstance(c, dict)]
            gate.checks = sorted(set((gate.checks or []) + ctx))
        elif kind == "deletion":
            gate.rule_seen = True
            gate.deletion = True
        elif kind == "non_fast_forward":
            gate.rule_seen = True
            gate.force_push = True


def from_export(data: Any, default_branch: str = "main") -> Tuple[_Gate, List[str]]:
    """Read a GitHub REST API export: a ruleset object, a list of rulesets, the
    `rules/branches/{branch}` list, classic branch protection, or a wrapper
    {"default_branch", "rulesets", "branch_protection", "branch_rules"}."""
    notes: List[str] = []
    gate = _Gate()
    if isinstance(data, dict) and any(k in data for k in ("rulesets", "branch_protection", "branch_rules")):
        default_branch = str(data.get("default_branch") or default_branch)
        parts: List[Any] = list(data.get("rulesets") or [])
        if data.get("branch_protection"):
            parts.append(data["branch_protection"])
        if data.get("branch_rules"):
            parts.append(list(data["branch_rules"]))
    else:
        parts = data if isinstance(data, list) and all(isinstance(x, dict) and "rules" in x for x in data) else [data]
    bypass_known = False
    for part in parts:
        if isinstance(part, list):                      # rules/branches: flat rules, no bypass actors
            _ruleset_rules(gate, part)
            notes.append("branch rules list: bypass actors are not included in this export")
        elif isinstance(part, dict) and "rules" in part:   # a ruleset
            if part.get("enforcement", "active") != "active":
                notes.append("ruleset %r is %s, not enforced" % (str(part.get("name", "?"))[:40], part.get("enforcement")))
                continue
            if part.get("target", "branch") != "branch" or not _targets_default(part.get("conditions"), default_branch):
                continue
            _ruleset_rules(gate, part.get("rules") or [])
            if "bypass_actors" in part:
                bypass_known = True
                gate.add_bypass(part.get("bypass_actors") or [])
            else:
                notes.append("ruleset %r: bypass actors not included (they need admin read access)"
                             % str(part.get("name", "?"))[:40])
        elif isinstance(part, dict) and ("required_pull_request_reviews" in part or "required_status_checks" in part
                                         or "allow_force_pushes" in part):   # classic protection
            rpr = part.get("required_pull_request_reviews")
            if isinstance(rpr, dict):
                gate.pr(int(rpr.get("required_approving_review_count") or 0), bool(rpr.get("require_code_owner_reviews")),
                        bool(rpr.get("require_last_push_approval")))
                allow = rpr.get("bypass_pull_request_allowances") or {}
                bypass_known = True
                gate.add_bypass([{"actor_type": "Integration", "bypass_mode": "pull_request", "actor_id": str(a.get("slug", a.get("id", "")))}
                                 for a in allow.get("apps") or [] if isinstance(a, dict)])
            else:
                gate.rule_seen = True
            rsc = part.get("required_status_checks")
            if isinstance(rsc, dict):
                ctx = list(rsc.get("contexts") or []) + [c.get("context") for c in rsc.get("checks") or [] if isinstance(c, dict)]
                gate.checks = sorted(set((gate.checks or []) + [str(c) for c in ctx if c]))
            gate.deletion = gate.deletion or not _enabled(part.get("allow_deletions"))
            gate.force_push = gate.force_push or not _enabled(part.get("allow_force_pushes"))
    if bypass_known and gate.bypass is None:
        gate.bypass = []
    return gate, notes


def _enabled(value: Any) -> bool:
    return bool(value.get("enabled")) if isinstance(value, dict) else bool(value)


def from_iac(items: Sequence[Any], default_branch: str = "main") -> Tuple[Optional[_Gate], List[Tuple[str, int]]]:
    """Terraform GitHub provider declarations; (gate or None, receipts)."""
    gate = _Gate()
    receipts: List[Tuple[str, int]] = []
    for item in items:
        if not item.rel.lower().endswith(".tf") or "github_" not in item.text:
            continue
        for r in jh_hcl.resources(item.text, "github_"):
            b = r["body"]
            if r["type"] == "github_repository_ruleset":
                if jh_hcl.as_str(b.get("enforcement")) not in ("active", "") or jh_hcl.as_str(b.get("target")) not in ("branch", ""):
                    continue
                ref = jh_hcl.first(jh_hcl.first(b, "conditions"), "ref_name")
                cond = {"ref_name": {"include": jh_hcl.as_list(ref.get("include")),
                                     "exclude": jh_hcl.as_list(ref.get("exclude"))}} if ref else None
                if not _targets_default(cond, default_branch):
                    continue
                rules = jh_hcl.first(b, "rules")
                pr = jh_hcl.first(rules, "pull_request")
                if pr:
                    gate.pr(jh_hcl.as_int(pr.get("required_approving_review_count")) or 0,
                            jh_hcl.as_bool(pr.get("require_code_owner_review")) or False,
                            jh_hcl.as_bool(pr.get("require_last_push_approval")) or False)
                rsc = jh_hcl.first(rules, "required_status_checks")
                if rsc:
                    gate.rule_seen = True
                    gate.checks = sorted(set((gate.checks or []) + [jh_hcl.as_str(c.get("context"))
                                                                    for c in rsc.get("required_check", [])]))
                if jh_hcl.as_bool(rules.get("deletion")):
                    gate.deletion, gate.rule_seen = True, True
                if jh_hcl.as_bool(rules.get("non_fast_forward")):
                    gate.force_push, gate.rule_seen = True, True
                gate.add_bypass([{"actor_type": jh_hcl.as_str(a.get("actor_type")),
                                  "bypass_mode": jh_hcl.as_str(a.get("bypass_mode")) or "always",
                                  "actor_id": str(a.get("actor_id", ""))} for a in b.get("bypass_actors", [])])
                receipts.append((item.rel, r["line"]))
            elif r["type"] == "github_branch_protection":
                pattern = jh_hcl.as_str(b.get("pattern"))
                if pattern and not re.fullmatch(re.escape(pattern).replace(r"\*", ".*"), default_branch):
                    continue
                rpr = jh_hcl.first(b, "required_pull_request_reviews")
                if rpr:
                    gate.pr(jh_hcl.as_int(rpr.get("required_approving_review_count")) or 0,
                            jh_hcl.as_bool(rpr.get("require_code_owner_reviews")) or False,
                            jh_hcl.as_bool(rpr.get("require_last_push_approval")) or False)
                    gate.add_bypass([{"actor_type": "Integration", "bypass_mode": "pull_request", "actor_id": x}
                                     for x in jh_hcl.as_list(rpr.get("pull_request_bypassers")) if "/" not in x])
                else:
                    gate.rule_seen = True
                    gate.bypass = gate.bypass or []
                rsc = jh_hcl.first(b, "required_status_checks")
                if rsc:
                    gate.checks = sorted(set((gate.checks or []) + jh_hcl.as_list(rsc.get("contexts"))))
                gate.deletion = gate.deletion or not jh_hcl.as_bool(b.get("allows_deletions"))
                gate.force_push = gate.force_push or not jh_hcl.as_bool(b.get("allows_force_pushes"))
                receipts.append((item.rel, r["line"]))
    if not receipts:
        return None, []
    if gate.bypass is None:
        gate.bypass = []
    return gate, receipts


def codeowners(items: Sequence[Any]) -> Dict[str, Any]:
    by_rel = {i.rel: i for i in items}
    for rel in _CODEOWNERS:
        item = by_rel.get(rel)
        if not item:
            continue
        catch_all, patterns = None, 0
        for idx, line in enumerate(item.text.split("\n"), 1):
            parts = line.split("#", 1)[0].split()
            if not parts:
                continue
            patterns += 1
            if parts[0] in _CATCH_ALL:
                catch_all = idx if len(parts) > 1 else None      # last match wins: an owner-less * un-owns the tree
        return {"state": "covers-tree" if catch_all else ("partial" if patterns else "empty"), "path": rel,
                "line": catch_all or 1}
    return {"state": "none", "path": None, "line": 0}


def assess(gate: Optional[_Gate], source: str, owners: Dict[str, Any], notes: Sequence[str] = ()) -> Dict[str, Any]:
    """Per-check states (met | not-met | unknown) and the overall evidence state."""
    if gate is None or not (gate.rule_seen or gate.approvals is not None):
        state = "unknown" if gate is None else source
        checks = {c: {"state": "unknown", "detail": "no change-control evidence"} for c in CHECKS}
        if gate is not None:
            checks = {c: {"state": "not-met", "detail": "no rule applies to the default branch"} for c in CHECKS}
        checks["codeowners_coverage"] = _owners_check(owners)
        return {"state": state, "checks": checks, "bypass": [], "notes": list(notes)}

    def check(ok: Optional[bool], yes: str, no: str) -> Dict[str, str]:
        return {"state": "unknown" if ok is None else ("met" if ok else "not-met"), "detail": yes if ok else no}

    apps = [b for b in gate.bypass or [] if b["actor_type"] in APP_ACTORS]
    checks = {
        "pull_request_review": check((gate.approvals or 0) >= 1,
                                     "a pull request with %s approval(s) is required" % gate.approvals,
                                     "no pull-request rule with at least one approval"),
        "code_owner_review": check(bool(gate.code_owner), "code-owner review required", "code-owner review not required"),
        "last_push_approval": check(bool(gate.last_push), "the last push must be approved by someone else",
                                    "the last pusher's own approval can count; an agent can push after approval"),
        "status_checks": check(bool(gate.checks), "required checks: %s" % ", ".join((gate.checks or [])[:5]),
                               "no required status checks"),
        "deletion_protected": check(bool(gate.deletion), "branch deletion blocked", "the branch can be deleted"),
        "force_push_protected": check(bool(gate.force_push), "force pushes blocked", "force pushes allowed"),
        "no_app_bypass": (check(not apps, "no GitHub App or deploy key can bypass the rules",
                                "can bypass: %s" % ", ".join("%s %s (%s)" % (b["actor_type"], b["actor_id"], b["bypass_mode"])
                                                             for b in apps[:3]))
                          if gate.bypass is not None else {"state": "unknown", "detail": "bypass actors not in the evidence"}),
        "codeowners_coverage": _owners_check(owners),
    }
    return {"state": source, "checks": checks, "bypass": gate.bypass or [], "notes": list(notes),
            "approvals": gate.approvals or 0}


def _owners_check(owners: Dict[str, Any]) -> Dict[str, str]:
    st = owners.get("state")
    if st == "covers-tree":
        return {"state": "met", "detail": "CODEOWNERS covers the whole tree (%s)" % owners["path"]}
    if st == "none":
        return {"state": "not-met", "detail": "no CODEOWNERS file"}
    return {"state": "not-met", "detail": "CODEOWNERS (%s) does not cover the whole tree" % owners.get("path")}


def violations(cc: Dict[str, Any]) -> Tuple[List[str], List[str], List[str]]:
    """(severe, weak, unknown) check names."""
    severe = [c for c in SEVERE if cc["checks"][c]["state"] == "not-met"]
    weak = [c for c in CHECKS if c not in SEVERE and cc["checks"][c]["state"] == "not-met"]
    unknown = [c for c in SEVERE if cc["checks"][c]["state"] == "unknown"]
    return severe, weak, unknown


def build(items: Sequence[Any], export: Any = None, export_trusted: bool = False, export_label: str = "",
          default_branch: str = "main") -> Dict[str, Any]:
    owners = codeowners(items)
    if export is not None:
        gate, notes = from_export(export, default_branch)
        source = "provider-verified" if export_trusted else "declared"
        cc = assess(gate, source, owners, notes)
        cc["source"] = {"kind": "operator export" if export_trusted else "repository file", "label": export_label}
        return cc
    gate, receipts = from_iac(items, default_branch)
    cc = assess(gate, "declared" if gate else "unknown", owners)
    cc["source"] = ({"kind": "terraform", "receipts": [{"path": p, "line": l} for p, l in receipts[:10]]}
                    if gate else {"kind": "none"})
    return cc
