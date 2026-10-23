#!/usr/bin/env python3
"""Software Passport for `jankhunt42 passport` (Can we responsibly ship it?).

A passport links the evidence jankhunt42 already produces (scan findings
and Jank Score 2.0, supply-chain files, the connectivity map) with
ownership and operations evidence, then applies the explainable policy in
jh_policy. It is a *local assessment*, not a certificate:

  * lifecycle is `draft` or `assessed`; `accepted` needs separately
    supplied, trusted acceptance evidence, which this tool does not create;
  * signatures are never claimed verified: attestation states are what the
    exporter recorded;
  * missing evidence is `not-observed` (unknown), never "absent".
"""
from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Optional, Sequence, Tuple

import jh_graph as G
import jh_map
import jh_policy
from jh_core import TOOL, VERSION, is_test_path, safe_text

PASSPORT_SCHEMA = "jankhunt.passport.v1"

_CI_FILES = re.compile(r"(^|/)(\.github/workflows/[^/]+\.ya?ml|\.gitlab-ci\.ya?ml|azure-pipelines\.ya?ml|"
                       r"jenkinsfile|\.circleci/config\.ya?ml|bitbucket-pipelines\.ya?ml)$", re.I)
_OBS_RE = re.compile(r"\b(sentry_sdk|@sentry/|opentelemetry|prometheus_client|prom-client|ddtrace|dd-trace|"
                     r"newrelic|applicationinsights|ApplicationInsights|micrometer|OpenTelemetry)\b")
_HEALTH_RE = re.compile(r"\b(livenessProbe|readinessProbe|startupProbe|HEALTHCHECK|healthcheck:)|[\"'](/healthz?|/ready|/readyz|/livez)[\"']")
_RUNBOOK_RE = re.compile(r"(^|/)(runbook|playbook|oncall|on-call|operations)[^/]*\.(md|rst|txt|adoc)$", re.I)
_CODEOWNERS = ("CODEOWNERS", ".github/CODEOWNERS", "docs/CODEOWNERS", ".gitlab/CODEOWNERS")
_OWNER_TOKEN = re.compile(r"^@[\w.\-]+(/[\w.\-]+)?$")

AREAS = ("ownership", "provenance", "data_inventory", "ci", "tests", "observability",
         "health_checks", "runbook", "security_policy")


def _ev(evidence: List[Dict[str, Any]], area: str, state: str, path: str, line: int, detail: str) -> str:
    eid = "pv:" + G.sha(G.canonical_json([area, path, line, detail]))
    if not any(e["id"] == eid for e in evidence):
        evidence.append({"id": eid, "area": area, "state": state, "path": safe_text(path), "line": line,
                         "detail": G.sanitize_text(detail, 160)})
    return eid


def ownership(items: Sequence[jh_map.Item], declared: Sequence[str], evidence: List[Dict[str, Any]],
              config_path: Optional[str]) -> Dict[str, Any]:
    owners: List[str] = []
    refs: List[str] = []
    by_rel = {i.rel: i for i in items}
    for rel in _CODEOWNERS:
        item = by_rel.get(rel)
        if not item:
            continue
        for idx, line in enumerate(item.text.split("\n"), 1):
            parts = line.split("#", 1)[0].split()
            if len(parts) < 2:
                continue
            found = []
            for tok in parts[1:]:
                if _OWNER_TOKEN.match(tok):
                    found.append(tok)
                elif "@" in tok:
                    found.append("<redacted-email>")
            if found:
                owners.extend(found)
                refs.append(_ev(evidence, "ownership", "observed", rel, idx, "%s %s" % (parts[0], " ".join(found))))
    state = "observed" if owners else "unknown"
    decl = [G.sanitize_text(str(o), 80) for o in declared if str(o).strip()]
    if decl:
        refs.append(_ev(evidence, "ownership", "declared", config_path or "config", 0, "owners: %s" % ", ".join(decl)))
        if state == "unknown":
            state = "declared"
    return {"state": state, "owners": sorted(set(owners))[:20], "declared_owners": decl[:20],
            "evidence_refs": sorted(set(refs)),
            "note": "CODEOWNERS is observed repository text; it does not prove the owners accept accountability"}


def operations(items: Sequence[jh_map.Item], declared: Dict[str, Any], evidence: List[Dict[str, Any]],
               config_path: Optional[str]) -> Dict[str, Dict[str, Any]]:
    found: Dict[str, Tuple[str, str, int, str]] = {}
    tests = 0
    for item in sorted(items, key=lambda i: i.rel):
        rel = item.rel
        if is_test_path(rel):
            tests += 1
            found.setdefault("tests", ("observed", rel, 1, "test file"))
            continue
        if _CI_FILES.search(rel):
            found.setdefault("ci", ("observed", rel, 1, "CI configuration"))
        if _RUNBOOK_RE.search(rel):
            found.setdefault("runbook", ("observed", rel, 1, "runbook/operations document"))
        if os.path.basename(rel).upper() in ("SECURITY.MD", "SECURITY.RST", "SECURITY.TXT"):
            found.setdefault("security_policy", ("observed", rel, 1, "security policy"))
        if len(item.text) > 2_000_000:
            continue
        if "observability" not in found or "health_checks" not in found:
            for idx, line in enumerate(item.text.split("\n"), 1):
                if len(line) > 4000:
                    continue
                if "observability" not in found and _OBS_RE.search(line):
                    found["observability"] = ("inferred", rel, idx, line)
                if "health_checks" not in found and _HEALTH_RE.search(line):
                    found["health_checks"] = ("observed", rel, idx, line)
    out: Dict[str, Dict[str, Any]] = {}
    notes = {"observability": "an SDK reference suggests telemetry; whether it is configured and alerting is not verified",
             "health_checks": "a declared probe or endpoint; its behaviour is not tested",
             "tests": "test files exist; what they cover is not assessed here",
             "ci": "CI configuration exists; that it runs and gates releases is not verified"}
    for area in ("ci", "tests", "observability", "health_checks", "runbook", "security_policy"):
        if area in found:
            state, rel, idx, detail = found[area]
            ref = _ev(evidence, area, state, rel, idx, detail)
            out[area] = {"state": state, "evidence_refs": [ref], "note": notes.get(area, "")}
            if area == "tests":
                out[area]["count"] = tests
        elif declared.get(area):
            ref = _ev(evidence, area, "declared", config_path or "config", 0, "%s declared in repository config" % area)
            out[area] = {"state": "declared", "evidence_refs": [ref], "note": "declared, not observed"}
        else:
            out[area] = {"state": "not-observed", "evidence_refs": [],
                         "note": "not observed in the repository; this is unknown, not proof of absence"}
    return out


def provenance(supply: Optional[Dict[str, Any]], evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    if supply is None:
        return {"state": "not assessed", "sboms": 0, "attestations": [], "artifact_digests": []}
    s = supply.get("summary", {})
    atts = []
    digests = []
    for a in supply.get("attestations", [])[:50]:
        rel = a.get("rel") or a.get("path") or "attestation"
        ref = _ev(evidence, "provenance", "declared", os.path.basename(str(rel)) if os.path.isabs(str(rel)) else str(rel),
                  0, "attestation %s" % a.get("kind", "unknown"))
        atts.append({"kind": a.get("kind", "unknown"), "exporter_verification": a.get("verification", "unknown"),
                     "evidence_ref": ref})
        for sub in a.get("subjects", [])[:5]:
            for algo, val in sorted((sub.get("digest") or {}).items()):
                digests.append({"digest": "%s:%s" % (algo, str(val)[:128]), "source": "attestation subject",
                                "verification": "exporter-reported (%s); not verified by %s" % (a.get("verification", "unknown"), TOOL)})
    for sb in supply.get("sboms", [])[:50]:
        rel = sb.get("rel") or sb.get("path") or "sbom"
        _ev(evidence, "provenance", "observed", os.path.basename(str(rel)) if os.path.isabs(str(rel)) else str(rel),
            0, "SBOM %s with %s packages" % (sb.get("format", "?"), sb.get("package_count", 0)))
    state = "observed" if (s.get("sboms") or s.get("attestations")) else "not-observed"
    return {"state": state, "sboms": s.get("sboms", 0), "packages": s.get("packages", 0),
            "attestations": atts, "verified_attestations_reported": s.get("verified_attestations", 0),
            "artifact_digests": sorted(digests, key=lambda d: d["digest"])[:20],
            "note": "%s parses provenance files; it does not verify signatures or signer identity" % TOOL}


def data_inventory(map_report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if map_report is None:
        return {"state": "not assessed", "sources": []}
    out = []
    for n in map_report["graph"]["nodes"]:
        if n["kind"] in ("database", "storage", "queue", "api", "external", "unknown"):
            out.append({"node": n["id"], "kind": n["kind"], "label": n["display_label"],
                        "sensitivity": n["sensitivity"], "criticality": n["criticality"],
                        "environment": n["environment"], "trust_domain": n["trust_domain"],
                        "classification_source": n["classification_source"]})
    return {"state": "assessed" if map_report["coverage"]["files_inspected"] else "not assessed",
            "graph_ref": map_report["scan_id"], "sources": out}


def remediation(decision: Dict[str, Any], ops: Dict[str, Dict[str, Any]], owner_state: str,
                prov: Dict[str, Any], map_report: Optional[Dict[str, Any]]) -> List[str]:
    steps: List[str] = []
    for r in decision["reasons"]:
        rule = r["rule"]
        if rule == "P-COV-001":
            steps.append("Restore assessment coverage (%s) and re-run; partial results are never a pass." % r["message"])
        elif rule == "P-OWN-001":
            steps.append("Declare an accountable owner in CODEOWNERS or `passport.owners` in .jankhunt42.json.")
        elif rule == "P-DAT-001":
            steps.append("Confirm or remove the sensitive external export; route it through an approved, narrow interface.")
        elif rule == "P-DAT-002":
            steps.append("Verify effective grants for the flagged connections and scope them to least privilege; "
                         "record the result in an operator inventory to turn leads into verified evidence.")
        elif rule == "P-EVD-001":
            steps.append("Produce the required supply-chain evidence (%s); see `jankhunt42 supply-chain`." % r["message"])
        elif rule == "P-JNK-001":
            steps.append("Work down the weakest Jank Score dimension first (`jankhunt42 score`), then the "
                         "highest-severity leads (`jankhunt42 scan --min-severity critical`).")
        elif rule == "P-EXP-001":
            steps.append("Reduce exposure below the policy maximum: remove unneeded write/delete paths shown by `jankhunt42 map`.")
    if owner_state == "unknown" and not any("owner" in s for s in steps):
        steps.append("Declare an accountable owner (CODEOWNERS or `passport.owners`).")
    for area in ("observability", "health_checks", "runbook"):
        if ops.get(area, {}).get("state") == "not-observed":
            steps.append("Add or declare %s evidence (currently not observed)." % area.replace("_", " "))
    if prov.get("state") == "not-observed":
        steps.append("Generate an SBOM and build provenance for released artifacts.")
    return steps[:8]


def build(*, name: str, source_revision: Optional[str], dirty: Optional[bool], items: Sequence[jh_map.Item],
          scan_files: int, scan_loc: int, jank: Dict[str, Any], findings_counts: Dict[str, int],
          supply: Optional[Dict[str, Any]], map_report: Optional[Dict[str, Any]],
          passport_cfg: Dict[str, Any], config_path: Optional[str], operator_policy: Optional[Dict[str, Any]],
          operator_policy_label: str, repo_policy_paths: Sequence[str], fail_on: Optional[str],
          warnings: Sequence[str] = (), extra_repo_policies: Sequence[Dict[str, Any]] = ()) -> Dict[str, Any]:
    evidence: List[Dict[str, Any]] = []
    warns = list(warnings)
    own = ownership(items, passport_cfg.get("owners") or [], evidence, config_path)
    ops = operations(items, passport_cfg.get("operations") or {}, evidence, config_path)
    prov = provenance(supply, evidence)
    data = data_inventory(map_report)
    repo_policies = [passport_cfg["policy"]] if isinstance(passport_cfg.get("policy"), dict) else []
    repo_policies += list(extra_repo_policies)
    eff = jh_policy.merge(operator_policy, repo_policies[0] if repo_policies else None, warns)
    for extra in repo_policies[1:]:
        eff = jh_policy.merge(eff, extra, warns)  # still tighten-only for the repository input
    exposure = map_report["assessment"]["exposure"]["class"] if map_report else "Unknown"
    if map_report:
        warns.extend(map_report.get("warnings", []))
    facts = {
        "files_scanned": scan_files,
        "map_files_inspected": map_report["coverage"]["files_inspected"] if map_report else 0,
        "map_status": map_report["coverage"]["status"] if map_report else "none",
        "map_partial_reasons": map_report["coverage"]["partial_reasons"] if map_report else [],
        "truncated": bool(map_report and map_report["truncation"]["truncated"]),
        "truncation_reasons": map_report["truncation"]["reasons"] if map_report else [],
        "exposure": exposure,
        "owner_state": own["state"],
        "jank_policy": jank.get("policy", "pass"),
        "blocker_leads": findings_counts.get("blocker", 0),
        "supply": {"sbom": prov.get("sboms", 0), "attestations": len(prov.get("attestations", [])),
                   "verified_attestations": prov.get("verified_attestations_reported", 0)},
    }
    decision = jh_policy.evaluate(eff, facts, map_report["graph"] if map_report else None)
    sources = [{"kind": "default"}]
    if operator_policy is not None:
        sources.append({"kind": "operator-supplied", "label": safe_text(operator_policy_label),
                        "note": "a local file path is operator input, not proof of organizational authority"})
    for p in repo_policy_paths:
        sources.append({"kind": "repository", "label": safe_text(p), "note": "tighten-only"})
    completeness = {}
    area_states = {"ownership": own["state"], "provenance": prov["state"], "data_inventory": data["state"],
                   **{k: v["state"] for k, v in ops.items()}}
    for area in AREAS:
        completeness[area] = area_states.get(area, "not-observed")
    present = sum(1 for v in completeness.values() if v in ("observed", "declared", "inferred", "assessed"))
    lifecycle_state = "assessed" if decision["result"] != "insufficient-evidence" else "draft"
    graph_unknowns = map_report["unknowns"] if map_report else [{"id": "connectivity", "detail": "map not assessed"}]
    report: Dict[str, Any] = {
        "schema_version": PASSPORT_SCHEMA,
        "tool": TOOL,
        "tool_version": VERSION,
        "source_revision": source_revision,
        "scan_id": "",
        "generated_at": "",
        "subject": {"name": safe_text(name), "revision": source_revision, "working_tree_dirty": dirty,
                    "artifact_digests": prov.get("artifact_digests", []),
                    "environment": passport_cfg.get("environment") if passport_cfg.get("environment") in G.ENVIRONMENTS else "unknown"},
        "scope": {"root": ".", "files_scanned": scan_files, "loc": scan_loc, "redaction": "none"},
        "coverage": {
            "evidence_areas": completeness,
            "evidence_areas_present": present,
            "evidence_areas_total": len(AREAS),
            "map": {"status": facts["map_status"], "files_inspected": facts["map_files_inspected"]},
        },
        "warnings": sorted(set(warns)),
        "evidence": sorted(evidence, key=lambda e: e["id"]),
        "assessment": {
            "jank": jank,
            "findings": findings_counts,
            "exposure": {"class": exposure, "model": G.EXPOSURE_MODEL,
                         "note": "qualitative exposure from the connectivity map; separate from the Jank Score"},
            "decision": {
                "result": decision["result"],
                "reasons": decision["reasons"],
                "rules": decision["rules"],
                "mode": "enforced (--fail-on %s)" % fail_on if fail_on else "advisory",
                "policy": {"hash": jh_policy.policy_hash(eff), "effective": eff, "sources": sources},
                "note": "explainable rule outcomes, not a weighted score and not a compliance certificate",
            },
        },
        "ownership": own,
        "provenance": prov,
        "data": data,
        "operations": ops,
        "lifecycle": {"state": lifecycle_state, "acceptance": {"state": "not-supplied",
                      "note": "acceptance is a separate, externally authorized act; a passing assessment is not approval"}},
        "remediation": remediation(decision, ops, own["state"], prov, map_report),
        "unknowns": graph_unknowns,
        "limitations": [
            "static repository evidence only; runtime behaviour, effective privileges and data movement are not verified",
            "signatures and attestations are not cryptographically verified by %s" % TOOL,
            "scanner findings are leads, not confirmed defects",
            "self-assessment cannot certify production readiness",
        ],
        "truncation": map_report["truncation"] if map_report else {"truncated": False, "reasons": []},
        "graph_ref": map_report["scan_id"] if map_report else None,
    }
    return jh_map.finalize_report(report)


def redact(report: Dict[str, Any]) -> Dict[str, Any]:
    """Shareable passport: no hostnames, labels, owners, or snippets."""
    import json
    rep = json.loads(json.dumps(report))
    for i, src in enumerate(rep["data"].get("sources", []), 1):
        src["label"] = "%s-%d" % (src["kind"], i)
        src["node"] = "%s-%d" % (src["kind"], i)
    rep["ownership"]["owners"] = ["owner-%d" % i for i, _ in enumerate(rep["ownership"]["owners"], 1)]
    rep["ownership"]["declared_owners"] = ["owner-%d" % i for i, _ in enumerate(rep["ownership"]["declared_owners"], 1)]
    for ev in rep["evidence"]:
        ev["detail"] = ev["area"]
    for r in rep["assessment"]["decision"]["rules"] + rep["assessment"]["decision"]["reasons"]:
        r["evidence_refs"] = ["ref-%d" % i for i, _ in enumerate(r["evidence_refs"], 1)]
    rep["subject"]["name"] = "application"
    rep["scope"]["redaction"] = "share"
    rep["unknowns"] = [{"id": u["id"], "count": u.get("count"), "detail": u["detail"]} for u in rep["unknowns"]]
    return rep


# ---------------------------------------------------------------------------
# Views
# ---------------------------------------------------------------------------

def markdown(p: Dict[str, Any]) -> str:
    a = p["assessment"]
    d = a["decision"]
    cov = p["coverage"]
    lines = ["# Software passport: %s" % p["subject"]["name"], "",
             "- Release assessment: **%s** (%s; %s)" % (d["result"], d["mode"], d["note"]),
             "- Technical Jank Score: **%s/100** grade %s (%s)" % (a["jank"].get("score"), a["jank"].get("grade"), a["jank"].get("policy")),
             "- Exposure: **%s** (%s)" % (a["exposure"]["class"], a["exposure"]["note"]),
             "- Evidence coverage: %d of %d areas observed, declared, or inferred" % (cov["evidence_areas_present"], cov["evidence_areas_total"]),
             "- Lifecycle: %s; acceptance: %s" % (p["lifecycle"]["state"], p["lifecycle"]["acceptance"]["state"]),
             "- Revision: %s%s" % (p["subject"]["revision"] or "unknown (not a git checkout)",
                                   " (working tree dirty)" if p["subject"].get("working_tree_dirty") else ""),
             "", "## Why this decision", ""]
    if d["reasons"]:
        for r in d["reasons"]:
            lines.append("- **%s** `%s`%s: %s" % (r["outcome"], r["rule"], " (hard floor)" if r["hard_floor"] else "", r["message"]))
    else:
        lines.append("- No rule triggered. This is an assessment, not an approval.")
    lines += ["", "## Evidence", "", "| area | state |", "|---|---|"]
    for area, state in cov["evidence_areas"].items():
        lines.append("| %s | %s |" % (area.replace("_", " "), state))
    own = p["ownership"]
    lines += ["", "- Owners: %s" % (", ".join(own["owners"] + own["declared_owners"]) or "unknown")]
    prov = p["provenance"]
    lines.append("- Provenance: %s SBOM(s), %d attestation(s); %s" % (prov.get("sboms", 0), len(prov.get("attestations", [])), prov.get("note", "")))
    lines.append("- Data sources: %d (%s)" % (len(p["data"].get("sources", [])), p["data"]["state"]))
    if p["remediation"]:
        lines += ["", "## Top remediation steps", ""] + ["%d. %s" % (i, s) for i, s in enumerate(p["remediation"], 1)]
    lines += ["", "## Unknowns", ""] + ["- %s: %s" % (u["id"], u["detail"]) for u in p["unknowns"]]
    if p["warnings"]:
        lines += ["", "## Warnings", ""] + ["- %s" % w for w in p["warnings"]]
    lines += ["", "_Export: `jankhunt42 passport . --json` or `--html > passport.html`; "
                  "`--redact` for a shareable copy._"]
    return "\n".join(safe_text(l) for l in lines)
