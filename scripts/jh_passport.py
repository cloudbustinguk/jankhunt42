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

import jh_change
import jh_capabilities
import jh_n8n
import jh_capability_approval
import jh_detonate
import jh_graph as G
import jh_map
import jh_frameworks
import jh_policy
import jh_registry
import jh_supply
from jh_core import SEV_RANK, TOOL, VERSION, is_agent_context, is_mcp_config, is_test_path, safe_text

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
         "health_checks", "runbook", "security_policy", "change_control")

# Scanner leads that put credentials or data in front of the public.
EXPOSURE_RULES = {"JH132", "JH133", "JH134"}
SECRET_RULES = {"JH101", "JH401", "JH415"}
# agent guardrails, sandboxes and dev containers, and CI that runs agent branches with secrets
AGENT_RULES = {"JH70%d" % i for i in range(1, 10)} | {"JH710", "JH711", "JH432"}
GOVERNANCE_RULES = EXPOSURE_RULES | SECRET_RULES | AGENT_RULES | {"JH131"}


def _lead(f: Any) -> Dict[str, Any]:
    return {"rule": f.rule, "path": safe_text(f.path), "line": f.line, "severity": f.severity, "title": f.title}


def _lead_key(d: Dict[str, Any]) -> Tuple[str, int, str]:
    return (d["path"], d["line"], d["rule"])


def governance_leads(findings: Sequence[Any]) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    """(public-exposure leads, agent-guardrail leads) at major severity or
    above, deduplicated and sorted; callers truncate for display."""
    serious = [f for f in findings if SEV_RANK.get(f.severity, 99) <= SEV_RANK["major"]]
    exposure = {_lead_key(d): d for d in (_lead(f) for f in serious if f.rule in EXPOSURE_RULES
                or (f.rule in SECRET_RULES and f.severity in ("blocker", "critical")))}
    agent = {_lead_key(d): d for d in (_lead(f) for f in serious if f.category == "agent" or f.rule in AGENT_RULES
             or (f.rule == "JH131" and (is_agent_context(f.path) or is_mcp_config(f.path))))}
    return [exposure[k] for k in sorted(exposure)], [agent[k] for k in sorted(agent)]


def agent_tooling(map_report: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """What the repository's AI agent configuration wires an agent to."""
    if map_report is None:
        return {"configs": [], "servers": []}
    nodes = {n["id"]: n for n in map_report["graph"]["nodes"]}
    edges = map_report["graph"]["edges"]
    agents = sorted(n["id"] for n in nodes.values() if n["attributes"].get("platform") == "ai-agent")
    servers = []
    for a in agents:
        for e in sorted((e for e in edges if e["source"] == a), key=lambda e: e["target"]):
            t = nodes[e["target"]]
            creds = sorted(ref.split(" ", 1)[-1] for x in edges
                           if x["source"] == t["id"] and x["kind"] == "authenticates-as"
                           for ref in nodes[x["target"]]["attributes"].get("credential_refs", []))
            reach = sorted(nodes[x["target"]]["display_label"] for x in edges
                           if x["source"] == t["id"] and x["kind"] == "connects")
            servers.append({"name": str(t["attributes"].get("mcp_server", t["display_label"]))[:60],
                            "transport": t["attributes"].get("transport", "remote"),
                            "pinned": t["attributes"].get("pinned"),
                            "credentials": creds[:10], "reaches": reach[:10]})
    return {"configs": sorted({str(nodes[a]["attributes"].get("config", "")) for a in agents}), "servers": servers[:50]}


# Map engines that are external AI model services.
AI_ENGINES = {"openai", "anthropic", "google-ai", "groq", "mistral", "cohere", "replicate", "huggingface",
              "together", "deepseek", "openrouter", "perplexity", "xai", "bedrock", "azure-openai", "vertex-ai",
              "vercel-ai-gateway"}
_TIER = {3: "verified", 2: "supported", 1: "inferred", 0: "unknown"}


def ai_inventory(map_report: Optional[Dict[str, Any]], items: Sequence[jh_map.Item],
                 agent_leads: Sequence[Dict[str, Any]], agent: Dict[str, Any]) -> Dict[str, Any]:
    """What the repository shows about AI use: the model services the software
    can reach, the agent tooling and instructions it carries, whether agent
    approvals are weakened, and sensitive data reachable alongside an AI
    service. A static inventory (NIST AI RMF GOVERN 1.6), not proof of use."""
    files = sorted(i.rel for i in items if is_agent_context(i.rel))[:20]
    servers = len(agent.get("servers", []))
    if any(l["rule"] in ("JH702", "JH703", "JH704") for l in agent_leads):
        oversight = "approval bypass observed"
    elif files or servers or agent_leads:
        oversight = "no approval bypass observed"
    else:
        oversight = "no agent tooling observed"
    base = {"instruction_files": files, "agent_tool_servers": servers, "human_oversight": oversight,
            "note": "a static inventory of what the repository shows; not proof of what runs or of what data moves"}
    in_use = bool(files or servers or agent_leads)
    if map_report is None:
        return dict(base, state="not assessed", observed=in_use, model_services=[], sensitive_data_with_ai=[])
    nodes = {n["id"]: n for n in map_report["graph"]["nodes"]}
    label = {nid: n["display_label"] for nid, n in nodes.items()}
    radii = map_report["assessment"].get("blast_radius", {})
    services = []
    for nid in sorted(n for n in nodes if nodes[n]["attributes"].get("engine") in AI_ENGINES):
        tiers = [info["tier"] for br in radii.values() for impact in br["impacts"].values()
                 for target, info in impact.items() if target == nid]
        services.append({"label": label[nid], "engine": nodes[nid]["attributes"]["engine"],
                         "evidence": _TIER[max(tiers)] if tiers else "unknown",
                         "reached_by": sorted({label[p] for p, br in radii.items()
                                               if any(nid in impact for impact in br["impacts"].values())})})
    # One entry per (store, AI service), with every principal that reaches
    # both. The full list feeds P-AI-001; the passport section shows a cap.
    pairs: Dict[Tuple[str, str], Dict[str, Any]] = {}
    for p, br in sorted(radii.items()):
        conf = br["impacts"].get("confidentiality", {})
        ai = [n for n in conf if nodes.get(n, {}).get("attributes", {}).get("engine") in AI_ENGINES]
        sensitive = [n for n in conf if nodes.get(n, {}).get("sensitivity") in ("confidential", "restricted")
                     and nodes[n]["kind"] in ("database", "storage", "queue", "api")]
        for a in ai:
            for d in sensitive:
                pair = pairs.setdefault((d, a), {"data": label[d], "data_id": d, "sensitivity": nodes[d]["sensitivity"],
                                                 "ai_service": label[a], "ai_service_id": a, "reached_by": []})
                pair["reached_by"].append(label[p])
    ordered = [dict(v, reached_by=sorted(set(v["reached_by"]))) for _, v in sorted(pairs.items())]
    return dict(base, state="assessed", observed=in_use or bool(services), model_services=services[:20],
                sensitive_data_with_ai=ordered)


_PLAIN = {
    "P-CAP-001": "Its requested access changed or remains unresolved. An engineer must review the comparison.",
    "P-COV-001": "We could not see enough of the project to judge it.",
    "P-OWN-001": "Nobody is named as the owner.",
    "P-CUS-001": "No engineer is named as its custodian, so nobody with engineering responsibility answers for it.",
    "P-DAT-001": "It may send sensitive data to an outside service.",
    "P-DAT-002": "It can change or delete data in a production or sensitive system, and nobody has confirmed "
                 "that this access is limited.",
    "P-DAT-003": "Nobody has said how sensitive the data it touches is.",
    "P-SEC-001": "Secret keys or data are exposed to the public.",
    "P-AGT-001": "The AI agent set-up can act without asking, or pulls tools that can change without notice.",
    "P-AI-001": "It may send sensitive data to an outside AI service; nobody has checked how that service handles it.",
    "P-OPS-001": "There are no automated tests or CI to catch mistakes before they ship.",
    "P-EVD-001": "Required build records are missing.",
    "P-JNK-001": "The code has serious quality or security problems.",
    "P-EXP-001": "It can reach more than this policy allows.",
    "P-CHG-001": "Changes can reach the main branch without another person approving them.",
    "P-SUP-001": "It may download packages from places your organization has not allowed.",
}
_VERDICT = {
    "block": "Not ready to ship. Fix every blocking item below; then an engineering custodian must review and sign off.",
    "insufficient-evidence": "Cannot be judged yet: evidence is missing. Supply what is listed below and re-run. "
                             "The citizen pull-request gate stops the merge until then.",
    "review": "Needs an engineer's review before it ships.",
    "pass": "No blocking issue found. This is an automated check, not approval: the custodian still signs off.",
}


def plain_brief(p: Dict[str, Any]) -> List[str]:
    """The decision in plain language, for the person who built the software
    and the custodian who answers for it."""
    d = p["assessment"]["decision"]
    gov = p["governance"]
    lines = [_VERDICT[d["result"]]]
    for r in d["reasons"]:
        lines.append("- %s" % _PLAIN.get(r["rule"], r["title"]))
    services = (p.get("ai") or {}).get("model_services", [])
    servers = gov.get("agent", {}).get("servers", [])
    agent_only = {label for sv in servers for label in sv.get("reaches", [])}
    sources = p["data"].get("sources", [])
    stores = [s for s in sources if s["kind"] in ("database", "storage", "queue") and s["label"] not in agent_only]
    if stores:
        lines.append("The software can reach: %s." % "; ".join(
            "%s (%s%s)" % (s["label"], s["environment"] if s["environment"] != "unknown" else "environment unknown",
                           ", %s data" % s["sensitivity"] if s["sensitivity"] != "unknown" else "")
            for s in stores[:5]))
    if services:
        lines.append("It uses AI services: %s." % "; ".join(
            "%s (%s)" % (sv["label"], sv["evidence"]) for sv in services[:5]))
    if servers:
        lines.append("Its AI agent set-up connects to %d tool server(s): %s." % (len(servers), "; ".join(
            "%s%s%s%s" % (sv["name"], " (unpinned)" if sv.get("pinned") is False else "",
                          " with %s" % ", ".join(sv["credentials"]) if sv.get("credentials") else "",
                          ", reaching %s" % ", ".join(sv["reaches"]) if sv.get("reaches") else "")
            for sv in servers[:5])))
    lines.append("Custodian: %s." % (", ".join(gov["custodians"]) if gov["custodians"] else "not named"))
    return lines


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


def _digest_verification(a: Dict[str, Any]) -> str:
    state = a.get("verification", "unknown")
    if state == "tool-verified":
        return "verified by %s (signature and signer identity)" % (a.get("verified_by") or "a native verifier")
    if state == "signature-only":
        return "signature checked by %s; signer identity not checked" % (a.get("verified_by") or "a verifier")
    return "exporter-reported (%s); not verified by %s" % (state, TOOL)


def provenance(supply: Optional[Dict[str, Any]], evidence: List[Dict[str, Any]]) -> Dict[str, Any]:
    if supply is None:
        return {"state": "not assessed", "sboms": 0, "attestations": [], "artifact_digests": []}
    s = supply.get("summary", {})
    atts = []
    digests = []
    for a in supply.get("attestations", [])[:50]:
        rel = a.get("rel") or a.get("path") or "attestation"
        kind = a.get("predicate_kind") or a.get("kind") or "unknown"
        ref = _ev(evidence, "provenance", "declared", os.path.basename(str(rel)) if os.path.isabs(str(rel)) else str(rel),
                  0, "attestation %s" % kind)
        entry = {"kind": kind, "exporter_verification": a.get("exporter_verification", a.get("verification", "unknown")),
                 "evidence_ref": ref}
        if a.get("verified_by"):
            entry["verification"] = a.get("verification")
            entry["verified_by"] = safe_text(a["verified_by"])
        if a.get("origin"):
            entry["origin"] = a["origin"]
        atts.append(entry)
        for sub in a.get("subjects", [])[:5]:
            for algo, val in sorted((sub.get("digest") or {}).items()):
                digests.append({"digest": "%s:%s" % (algo, str(val)[:128]), "source": "attestation subject",
                                "verification": _digest_verification(a)})
    for sb in supply.get("sboms", [])[:50]:
        rel = sb.get("rel") or sb.get("path") or "sbom"
        _ev(evidence, "provenance", "observed", os.path.basename(str(rel)) if os.path.isabs(str(rel)) else str(rel),
            0, "SBOM %s with %s packages" % (sb.get("format", "?"), sb.get("package_count", 0)))
    state = "observed" if (s.get("sboms") or s.get("attestations")) else "not-observed"
    best = jh_supply.best_sbom_quality(supply.get("sboms", []))
    out = {"state": state, "sboms": s.get("sboms", 0), "packages": s.get("packages", 0),
           "sbom_minimum_elements": best["minimum_elements"],
           "sbom_missing": best["missing"][:6] if best["minimum_elements"] != "none" else [],
           "attestations": atts, "verified_attestations_reported": s.get("verified_attestations", 0),
           "artifact_digests": sorted(digests, key=lambda d: d["digest"])[:20],
           "note": "%s parses provenance files; it does not verify signatures or signer identity" % TOOL}
    ver = supply.get("verification")
    if ver:
        # No timestamps here: verification ran when the passport was generated
        # (generated_at), and scan_id must depend only on content.
        out["verification"] = {
            "plan": ver.get("plan"), "mode": ver.get("mode"),
            "results": [{k: r.get(k) for k in ("subject", "verifier", "tool_version", "outcome", "reason")}
                        for r in ver.get("results", [])[:50]],
            "problems": [r for r in (supply.get("gate") or {}).get("reasons", []) if r.startswith("verification ")],
        }
        out["note"] = ("%s performs no cryptographic verification itself; `tool-verified` results come from "
                       "the native verifiers named in the plan" % TOOL)
    return out


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
            steps.append("Work down the weakest Jank Score dimension first (`jankhunt42 scan --score`), then the "
                         "highest-severity leads (`jankhunt42 scan --min-severity critical`).")
        elif rule == "P-EXP-001":
            steps.append("Reduce exposure below the policy maximum: remove unneeded write/delete paths shown by `jankhunt42 map`.")
        elif rule == "P-CUS-001":
            steps.append("Name an engineering custodian who reviews and answers for this software (`passport.custodians`, "
                         "or `custodians` in the operator policy); the custodian signs the acceptance record.")
        elif rule == "P-SEC-001":
            steps.append("Rotate exposed keys, move secrets to server-side code, and close public data access "
                         "(`jankhunt42 scan . --rule JH132 --rule JH133 --rule JH134`).")
        elif rule == "P-AGT-001":
            steps.append("Remove agent approval bypasses, auto-run hooks, and credential literals from the repository, "
                         "and pin every MCP server (`jankhunt42 scan . --category agent`).")
        elif rule == "P-OPS-001":
            steps.append("Add automated tests and a CI workflow that runs them on every change.")
        elif rule == "P-AI-001":
            steps.append("Check what data reaches the AI provider and its terms (retention, training use, region), "
                         "record the decision, or keep restricted data away from AI calls.")
        elif rule == "P-DAT-003":
            steps.append("Declare the sensitivity of every data store in `passport.assets` "
                         "(public, internal, confidential, or restricted).")
        elif rule == "P-CHG-001":
            steps.append("Protect the default branch: require a pull request with at least one approval from someone "
                         "other than the last pusher, code-owner review and status checks, and remove GitHub App and "
                         "deploy-key bypasses; pass the exported rulesets with --branch-rules.")
        elif rule == "P-SUP-001":
            steps.append("Point every package manager at an allowed registry in committed config (.npmrc, pip.conf "
                         "or index-url, Maven mirror, nuget.config) and regenerate lockfiles from it.")
    if owner_state == "unknown" and not any("owner" in s for s in steps):
        steps.append("Declare an accountable owner (CODEOWNERS or `passport.owners`).")
    for area in ("observability", "health_checks", "runbook"):
        if ops.get(area, {}).get("state") == "not-observed":
            steps.append("Add or declare %s evidence (currently not observed)." % area.replace("_", " "))
    if prov.get("state") == "not-observed":
        steps.append("Generate an SBOM and build provenance for released artifacts.")
    return steps[:8]


def _declared_custodians(passport_cfg: Dict[str, Any], warnings: List[str]) -> List[str]:
    raw = passport_cfg.get("custodians")
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(c, str) and c.strip() for c in raw):
        warnings.append("passport.custodians: expected a list of names; ignored")
        return []
    return sorted({G.sanitize_text(c.strip(), 80) for c in raw})[:20]


def build(*, name: str, source_revision: Optional[str], dirty: Optional[bool], items: Sequence[jh_map.Item],
          scan_files: int, scan_loc: int, jank: Dict[str, Any], findings_counts: Dict[str, int],
          supply: Optional[Dict[str, Any]], map_report: Optional[Dict[str, Any]],
          passport_cfg: Dict[str, Any], config_path: Optional[str], operator_policy: Optional[Dict[str, Any]],
          operator_policy_label: str, repo_policy_paths: Sequence[str], fail_on: Optional[str],
          warnings: Sequence[str] = (), extra_repo_policies: Sequence[Dict[str, Any]] = (),
          findings: Sequence[Any] = (), governance_findings: Optional[Sequence[Any]] = None,
          governance_tuned: Optional[Sequence[Any]] = None, governance_truncated: bool = False,
          profile: Optional[str] = None, change_control: Optional[Dict[str, Any]] = None,
          package_sources: Optional[Dict[str, Any]] = None,
          capability_delta: Optional[Dict[str, Any]] = None,
          capability_approval_record: Optional[Dict[str, Any]] = None,
          capability_approval_label: str = "",
          sandbox: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    evidence: List[Dict[str, Any]] = []
    warns = list(warnings)
    own = ownership(items, passport_cfg.get("owners") or [], evidence, config_path)
    ops = operations(items, passport_cfg.get("operations") or {}, evidence, config_path)
    prov = provenance(supply, evidence)
    data = data_inventory(map_report)
    repo_policies = [passport_cfg["policy"]] if isinstance(passport_cfg.get("policy"), dict) else []
    if passport_cfg.get("profile") is not None:
        # `passport.profile` is the repository opting into stricter governance.
        repo_policies.insert(0, {"profile": passport_cfg.get("profile")})
    repo_policies += list(extra_repo_policies)
    # One merge for every repository input, so operator exceptions are applied
    # once and repository tightening really comes last.
    eff = jh_policy.merge(operator_policy, repo_policies, warns, profile)
    declared_custodians = _declared_custodians(passport_cfg, warns)
    exposure_leads, agent_leads = governance_leads(governance_tuned if governance_tuned is not None else findings)
    suppressed = 0
    if governance_findings is not None:
        raw_exposure, raw_agent = governance_leads(governance_findings)
        seen = {_lead_key(d) for d in exposure_leads + agent_leads}
        suppressed = len({_lead_key(d) for d in raw_exposure + raw_agent} - seen)
        if eff["profile"] == "citizen":
            # Union: the repository can add or raise leads, never remove them
            # (the tuned lead comes last, so a raised severity is kept).
            exposure_leads = sorted({_lead_key(d): d for d in raw_exposure + exposure_leads}.values(), key=_lead_key)
            agent_leads = sorted({_lead_key(d): d for d in raw_agent + agent_leads}.values(), key=_lead_key)
        if suppressed:
            warns.append("%d public-exposure or agent lead(s) are suppressed or re-rated by repository scan config or "
                         "inline pragmas%s" % (suppressed, "; the citizen profile does not honour them"
                                               if eff["profile"] == "citizen" else ""))
    exposure = map_report["assessment"]["exposure"]["class"] if map_report else "Unknown"
    if map_report:
        warns.extend(map_report.get("warnings", []))
    agent = agent_tooling(map_report)
    ai = ai_inventory(map_report, items, agent_leads, agent)
    cc = change_control if change_control is not None else jh_change.build(items)
    cc_ref = None
    if cc["state"] != "unknown":
        rec = (cc.get("source") or {}).get("receipts") or [{"path": (cc.get("source") or {}).get("label") or "branch rules",
                                                            "line": 0}]
        cc_ref = _ev(evidence, "change_control", "observed" if cc["state"] == "provider-verified" else "declared",
                     rec[0]["path"], rec[0]["line"], "change control: %s" % ", ".join(
                         "%s %s" % (k.replace("_", " "), v["state"]) for k, v in cc["checks"].items()))
    severe, weak, unknown = jh_change.violations(cc)
    pkg = package_sources if package_sources is not None else jh_registry.collect(items)
    reg = jh_registry.assess(pkg, eff.get("allowed_registries") or [])
    approval = jh_capability_approval.evaluate(capability_approval_record,
        capability_delta or jh_capabilities.not_requested(), eff, jh_policy.policy_hash(eff), capability_approval_label)
    sandbox = sandbox or {"state": "not-supplied"}
    if sandbox["state"] == "stale":
        warns.append("the sandbox run (--detonation) was made on a different tree and was not used")
    facts = {
        "sandbox": sandbox,
        "capability_approval": approval,
        "capability_delta": capability_delta or jh_capabilities.not_requested(),
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
        "supply": {"sbom": prov.get("sboms", 0), "sbom_minimum": prov.get("sbom_minimum_elements", "none"),
                   "attestations": len(prov.get("attestations", [])),
                   "verified_attestations": prov.get("verified_attestations_reported", 0),
                   "verification_problems": (prov.get("verification") or {}).get("problems", [])},
        "declared_custodians": declared_custodians,
        "exposure_findings": exposure_leads,
        "agent_findings": agent_leads,
        "ai_sensitive_pairs": ai["sensitive_data_with_ai"],
        "operations": {k: v["state"] for k, v in ops.items()},
        "change_control": {"state": cc["state"], "severe": severe, "weak": weak, "unknown": unknown,
                           "details": [cc["checks"][c]["detail"] for c in severe]},
        "registry": reg,
    }
    if governance_truncated:
        reason = "the governance scan (without repository ignore globs) reached --max-files; raise the limit"
        warns.append(reason)
        if eff["profile"] == "citizen":
            facts["truncated"] = True
            facts["truncation_reasons"] = list(facts["truncation_reasons"]) + [reason]
    decision = jh_policy.evaluate(eff, facts, map_report["graph"] if map_report else None)
    sources = [{"kind": "default"}]
    if operator_policy is not None:
        sources.append({"kind": "operator-supplied", "label": safe_text(operator_policy_label),
                        "note": "a local file path is operator input, not proof of organizational authority"})
    for p in repo_policy_paths:
        sources.append({"kind": "repository", "label": safe_text(p), "note": "tighten-only"})
    completeness = {}
    area_states = {"ownership": own["state"], "provenance": prov["state"], "data_inventory": data["state"],
                   "change_control": {"provider-verified": "provider-verified", "declared": "declared"}.get(
                       cc["state"], "not-observed"),
                   **{k: v["state"] for k, v in ops.items()}}
    for area in AREAS:
        completeness[area] = area_states.get(area, "not-observed")
    present = sum(1 for v in completeness.values() if v in ("observed", "declared", "inferred", "assessed",
                                                             "provider-verified"))
    lifecycle_state = "assessed" if decision["result"] != "insufficient-evidence" else "draft"
    graph_unknowns = map_report["unknowns"] if map_report else [{"id": "connectivity", "detail": "map not assessed"}]
    report: Dict[str, Any] = {
        "schema_version": PASSPORT_SCHEMA,
        "capability_delta": capability_delta or jh_capabilities.not_requested(),
        "capability_approval": approval,
        "sandbox_run": sandbox,
        "triggers": jh_n8n.trigger_counts((map_report or {}).get('triggers') or jh_n8n.trigger_summary([])),
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
        "governance": {
            "profile": eff["profile"],
            "custodians": eff.get("custodians") or declared_custodians,
            "custodian_source": ("operator-policy" if eff.get("custodians") else
                                 "repository" if declared_custodians else "none"),
            "public_exposure_leads": exposure_leads[:50],
            "agent_leads": agent_leads[:50],
            "repository_suppressed_leads": suppressed,
            "agent": agent,
            "brief": [],
            "note": ("the citizen profile governs software built by people who are not software engineers: "
                     "it requires a named engineering custodian and blocks on unverified authority"
                     if eff["profile"] == "citizen" else "standard profile"),
        },
        "ai": dict({k: v for k, v in ai.items() if k != "sensitive_data_with_ai"},
                   sensitive_data_with_ai=[{k: v for k, v in p.items() if not k.endswith("_id")}
                                           for p in ai["sensitive_data_with_ai"][:20]],
                   sensitive_data_with_ai_total=len(ai["sensitive_data_with_ai"])),
        "alignment": jh_frameworks.alignment(r["rule"] for r in decision["reasons"]),
        "provenance": prov,
        "data": data,
        "operations": ops,
        "egress": (map_report or {}).get("egress") or {"state": "unknown", "note": "connectivity map not assessed"},
        "change_control": dict(cc, evidence_refs=[cc_ref] if cc_ref else [],
                               note="whether code can reach the default branch without an independent human review; "
                                    "provider-verified only from an operator export outside the repository"),
        "package_sources": dict(pkg, assessment=dict(reg, allowed_registries=eff.get("allowed_registries") or [])),
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
    report["governance"]["brief"] = plain_brief(report)
    return jh_map.finalize_report(report)


_DETAILED_RULES = ("P-COV-001", "P-CUS-001", "P-DAT-003", "P-SEC-001", "P-AGT-001", "P-AI-001", "P-CHG-001",
                   "P-SUP-001")


def redact(report: Dict[str, Any]) -> Dict[str, Any]:
    """Shareable passport: no hostnames, labels, owners, or snippets."""
    import json
    rep = json.loads(json.dumps(report))
    if rep.get('triggers'):
        rep['triggers'] = jh_n8n.trigger_counts(rep['triggers'])
    for i, alert in enumerate((rep.get("sandbox_run") or {}).get("alerts", []), 1):
        alert["detail"] = "redacted"            # paths and hosts from the run
        alert["step"] = "step-%d" % i           # step names carry task labels and server names
    run = rep.get("sandbox_run") or {}
    for i, attempt in enumerate(run.get("attempts", []), 1):
        attempt["target"] = "destination-%d" % i
    if run.get("undeclared"):
        run["undeclared"] = ["destination" for _ in run["undeclared"]]
    decision = rep.get("assessment", {}).get("decision", {})
    for rule in decision.get("rules", []) + decision.get("reasons", []):       # reasons repeat the triggered rules
        if rule.get("rule") == "P-RUN-002" and run.get("undeclared"):
            rule["message"] = "the sandbox run tried %d destination(s) the repository does not declare" % max(
                len(run["undeclared"]), (run.get("counts") or {}).get("UNDECLARED") or 0)
    approval = rep.get("capability_approval") or {}
    for key in ("approved_by", "subject_id", "rationale", "record"):
        if key in approval:
            approval[key] = "redacted"
    delta = rep.get("capability_delta")
    if delta:
        for i, row in enumerate(delta["requests"], 1):
            row.update(principal="principal", target={"logical_name": "target-%d" % i}, evidence=[], witness=[])
        delta["unknowns"] = [{"id": u["id"], "detail": "unresolved access"} for u in delta["unknowns"]]
        delta["unchanged_unknowns"] = [{"id": u["id"], "detail": "unresolved access, unchanged"}
                                       for u in delta.get("unchanged_unknowns", [])]
        delta["truncation"]["reasons"] = ["comparison incomplete"] if delta["truncation"]["reasons"] else []
    for i, src in enumerate(rep["data"].get("sources", []), 1):
        src["label"] = "%s-%d" % (src["kind"], i)
        src["node"] = "%s-%d" % (src["kind"], i)
    rep["ownership"]["owners"] = ["owner-%d" % i for i, _ in enumerate(rep["ownership"]["owners"], 1)]
    rep["ownership"]["declared_owners"] = ["owner-%d" % i for i, _ in enumerate(rep["ownership"]["declared_owners"], 1)]
    for ev in rep["evidence"]:
        ev["detail"] = ev["area"]
        if ev["area"] == "change_control":
            ev["path"] = "branch rules"         # an operator export's file name can name the organization
    eff = rep["assessment"]["decision"].get("policy", {}).get("effective") or {}
    # the embedded policy names people and internal registries (its hash still identifies it)
    if eff.get("custodians"):
        eff["custodians"] = ["custodian-%d" % i for i, _ in enumerate(eff["custodians"], 1)]
    if eff.get("allowed_registries"):
        eff["allowed_registries"] = ["allowed-%d" % i for i, _ in enumerate(eff["allowed_registries"], 1)]
    if eff.get("capability_approvals"):
        eff["capability_approvals"] = {"subject_id": "redacted", "approvers": ["approver"],
                                      "max_lifetime_seconds": eff["capability_approvals"].get("max_lifetime_seconds", 0)}
    for r in rep["assessment"]["decision"]["rules"] + rep["assessment"]["decision"]["reasons"]:
        r["evidence_refs"] = ["ref-%d" % i for i, _ in enumerate(r["evidence_refs"], 1)]
        if r["rule"] in _DETAILED_RULES and ":" in r["message"]:
            # These messages quote hostnames, file paths, or people.
            r["message"] = r["message"].split(":", 1)[0] + " (details redacted)"
    rep["remediation"] = ["Restore assessment coverage and re-run; partial results are never a pass."
                          if step.startswith("Restore assessment coverage (") else step for step in rep["remediation"]]
    rep["subject"]["name"] = "application"
    acc = rep["lifecycle"]["acceptance"]
    if acc.get("accepted_by"):
        acc["accepted_by"] = "acceptor"
        acc["record"] = "acceptance record"
    ver = rep.get("provenance", {}).get("verification")
    if ver:
        # Subjects can be registry URIs or repository paths, and verifier
        # messages can quote hosts: keep only the outcome.
        for i, r in enumerate(ver.get("results", []), 1):
            r["subject"] = "subject-%d" % i
            r["reason"] = r["outcome"]
        ver["problems"] = ["verification problem %d" % i for i, _ in enumerate(ver.get("problems", []), 1)]
    ai = rep.get("ai")
    if ai:
        for i, sv in enumerate(ai.get("model_services", []), 1):
            sv["label"] = "ai-service-%d" % i
            sv["reached_by"] = ["principal-%d" % j for j, _ in enumerate(sv["reached_by"], 1)]
        ai["sensitive_data_with_ai"] = [{"data": "data-store-%d" % i, "sensitivity": p["sensitivity"],
                                         "ai_service": "ai-service",
                                         "reached_by": ["principal-%d" % j for j, _ in enumerate(p["reached_by"], 1)]}
                                        for i, p in enumerate(ai.get("sensitive_data_with_ai", []), 1)]
        ai["instruction_files"] = ["instruction-file-%d" % i for i, _ in enumerate(ai.get("instruction_files", []), 1)]
    pkg = rep.get("package_sources")
    if isinstance(pkg, dict):
        # registry URLs, scopes and file paths reveal internal hosts and organization names
        urls: Dict[str, str] = {}

        def alias(url: str) -> str:
            return urls.setdefault(url, "registry-%d" % (len(urls) + 1))
        for eco in (pkg.get("ecosystems") or {}).values():
            eco["manifests"] = ["manifest-%d" % i for i, _ in enumerate(eco.get("manifests", []), 1)]
            eco["sources"] = [{"url": alias(s["url"]), "kind": s["kind"], "scope": "scope" if s.get("scope") else "",
                               "path": "file", "line": 0} for s in eco.get("sources", [])]
        a = pkg.get("assessment") or {}
        a["disallowed"] = [{"ecosystem": d["ecosystem"], "url": alias(d["url"]), "path": "file", "line": 0, "kind": d["kind"]}
                           for d in a.get("disallowed", [])]
        a["allowed_registries"] = ["allowed-%d" % i for i, _ in enumerate(a.get("allowed_registries", []), 1)]
    eg = rep.get("egress")
    if isinstance(eg, dict) and isinstance(eg.get("boundaries"), list):
        rep["egress"] = {"state": eg.get("state", "unknown"), "boundaries": len(eg["boundaries"]), "outside": len(eg["outside"]),
                         "unused": len(eg["unused"]), "wildcards": len(eg["wildcards"]),
                         "contexts": len(eg.get("contexts", [])), "unassessed": len(eg.get("unassessed", [])),
                         "note": "counts only in the shareable copy"}
    cc = rep.get("change_control")
    if isinstance(cc, dict):
        for name, chk in (cc.get("checks") or {}).items():
            chk["detail"] = "%s: %s" % (name.replace("_", " "), chk["state"])
        cc["bypass"] = [{"actor_type": b.get("actor_type", ""), "bypass_mode": b.get("bypass_mode", ""),
                         "actor_id": "actor-%d" % i} for i, b in enumerate(cc.get("bypass", []), 1)]
        cc["notes"] = ["note %d withheld" % i for i, _ in enumerate(cc.get("notes", []), 1)]
        src = cc.get("source") or {}
        cc["source"] = {"kind": src.get("kind", "none")}
        cc["evidence_refs"] = ["ref-%d" % i for i, _ in enumerate(cc.get("evidence_refs", []), 1)]
    gov = rep.get("governance")
    if gov:
        gov["custodians"] = ["custodian-%d" % i for i, _ in enumerate(gov["custodians"], 1)]
        for i, sv in enumerate(gov["agent"]["servers"], 1):
            sv["name"] = "server-%d" % i
            sv["credentials"] = ["credential-%d" % j for j, _ in enumerate(sv["credentials"], 1)]
            sv["reaches"] = ["endpoint-%d" % j for j, _ in enumerate(sv["reaches"], 1)]
        gov["agent"]["configs"] = ["config-%d" % i for i, _ in enumerate(gov["agent"]["configs"], 1)]
        for lead in gov["public_exposure_leads"] + gov["agent_leads"]:
            lead["path"] = "file"
        gov["brief"] = plain_brief(rep)
    rep["scope"]["redaction"] = "share"
    rep["unknowns"] = [{"id": u["id"], "count": u.get("count"), "detail": u["detail"]} for u in rep["unknowns"]]
    if rep["warnings"]:
        # Warnings quote patterns, object names, and paths from the repository.
        rep["warnings"] = ["%d warning(s) withheld from the shareable copy; see the full local passport"
                           % len(rep["warnings"])]
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
             ""]
    gov = p.get("governance") or {}
    trigger_text = jh_n8n.trigger_line(p.get('triggers'))
    if trigger_text:
        lines += ['## Declared triggers', '', trigger_text, jh_n8n.TRIGGER_NOTE, '']
    if p.get("capability_delta", {}).get("state", "not-requested") != "not-requested":
        lines += ["## Requested access changes", ""] + ["- " + jh_capabilities.markdown_line(line) for line in
                  jh_capabilities.approver_lines(p["capability_delta"])] + [""]
        approval_line = jh_capability_approval.approver_line(p.get("capability_approval") or {})
        if approval_line:
            lines += [jh_capabilities.markdown_line(approval_line), ""]
    sandbox_line = jh_detonate.passport_line(p.get("sandbox_run") or {})
    if sandbox_line:
        lines += ["## Sandbox run", "", jh_capabilities.markdown_line(sandbox_line), ""]
        for a in (p.get("sandbox_run") or {}).get("alerts", [])[:20]:
            lines.append("- " + jh_capabilities.markdown_line("ALERT %s: %s (%s)" % (a["kind"], a["detail"], a["step"])))
        for target in (p.get("sandbox_run") or {}).get("undeclared", [])[:20]:
            lines.append("- " + jh_capabilities.markdown_line("Undeclared destination tried: %s" % target))
        lines += [""] if (p.get("sandbox_run") or {}).get("alerts") else []
    if gov.get("profile") == "citizen":
        lines += ["## In plain terms (citizen-developer profile)", ""] + gov.get("brief", []) + [""]
    lines += ["## Why this decision", ""]
    if d["reasons"]:
        for r in d["reasons"]:
            lines.append("- **%s** `%s`%s: %s" % (r["outcome"], r["rule"], " (hard floor)" if r["hard_floor"] else "", r["message"]))
    else:
        lines.append("- No rule triggered. This is an assessment, not an approval.")
    acc = p["lifecycle"]["acceptance"]
    if acc["state"] != "not-supplied":
        lines.insert(7, "- Acceptance record: %s%s (%s)" % (acc["state"], (" by " + acc["accepted_by"]) if acc.get("accepted_by") else "",
                                                          "; ".join(acc.get("reasons") or []) or acc["note"]))
    lines += ["", "## Evidence", "", "| area | state |", "|---|---|"]
    for area, state in cov["evidence_areas"].items():
        lines.append("| %s | %s |" % (area.replace("_", " "), state))
    own = p["ownership"]
    lines += ["", "- Owners: %s" % (", ".join(own["owners"] + own["declared_owners"]) or "unknown")]
    prov = p["provenance"]
    lines.append("- Provenance: %s SBOM(s), %d attestation(s); %s" % (prov.get("sboms", 0), len(prov.get("attestations", [])), prov.get("note", "")))
    for r in (prov.get("verification") or {}).get("results", []):
        lines.append("  - verification `%s` (%s): **%s**: %s" % (r.get("subject"), r.get("verifier"), r.get("outcome"), r.get("reason")))
    lines.append("- Data sources: %d (%s)" % (len(p["data"].get("sources", [])), p["data"]["state"]))
    cc = p.get("change_control") or {}
    if cc:
        lines += ["", "## Change control (default branch)", "", "- Evidence: %s%s" % (
            cc["state"], " (%s)" % cc["source"].get("label") if (cc.get("source") or {}).get("label") else "")]
        for name, chk in cc["checks"].items():
            lines.append("- %s: **%s**: %s" % (name.replace("_", " "), chk["state"], chk["detail"]))
        for n in cc.get("notes", [])[:3]:
            lines.append("- _%s_" % n)
    pkg = p.get("package_sources") or {}
    if pkg.get("ecosystems"):
        lines += ["", "## Package sources", ""]
        for eco, info in pkg["ecosystems"].items():
            urls = sorted({s["url"] for s in info["sources"]})
            lines.append("- %s: %s%s" % (eco, info["state"], ": " + ", ".join(urls[:4]) if urls else
                                          " (not configured in the repository; default %s)" % info["default_if_unconfigured"]))
        bad = (pkg.get("assessment") or {}).get("disallowed") or []
        if (pkg.get("assessment") or {}).get("allowed_registries"):
            lines.append("- Outside the allowed registries: %s" % (", ".join(sorted({b["url"] for b in bad})[:5]) or "none"))
    ai = p.get("ai") or {}
    if ai.get("observed"):
        lines += ["", "## AI use", ""]
        for sv in ai.get("model_services", []):
            lines.append("- AI service: %s (%s; reached by %s)" % (sv["label"], sv["evidence"],
                                                                  ", ".join(sv["reached_by"]) or "nothing"))
        if ai.get("agent_tool_servers"):
            lines.append("- AI agent tool servers: %d" % ai["agent_tool_servers"])
        if ai.get("instruction_files"):
            lines.append("- Agent instruction files: %s" % ", ".join("`%s`" % f for f in ai["instruction_files"][:8]))
        lines.append("- Human oversight of agents: %s" % ai.get("human_oversight", "unknown"))
        for pair in ai.get("sensitive_data_with_ai", [])[:5]:
            lines.append("- Reachable together: %s (%s) and %s, from %s" % (
                pair["data"], pair["sensitivity"], pair["ai_service"], ", ".join(pair["reached_by"])))
        lines.append("- _%s_" % ai.get("note", ""))
    al = p.get("alignment") or {}
    if ai.get("observed") and al.get("triggered"):
        lines += ["", "## Framework orientation (NIST AI RMF, AIGP)", "", "_%s._" % al["note"], ""]
        for rule, ref in al["triggered"].items():
            lines.append("- `%s`: NIST AI RMF %s; AIGP domain %s" % (rule, ", ".join(ref["nist_ai_rmf"]),
                                                                   "; ".join(ref["aigp"])))
    if p["remediation"]:
        lines += ["", "## Top remediation steps", ""] + ["%d. %s" % (i, s) for i, s in enumerate(p["remediation"], 1)]
    lines += ["", "## Unknowns", ""] + ["- %s: %s" % (u["id"], u["detail"]) for u in p["unknowns"]]
    if p["warnings"]:
        lines += ["", "## Warnings", ""] + ["- %s" % w for w in p["warnings"]]
    lines += ["", "_Export: `jankhunt42 passport . --json` or `--html > passport.html`; "
                  "`--redact` for a shareable copy._"]
    return "\n".join(safe_text(l) for l in lines)


# ---------------------------------------------------------------------------
# Acceptance (operator-declared, never inferred) and passport comparison
# ---------------------------------------------------------------------------

DELTA_SCHEMA = "jankhunt.passport-delta.v1"
_AREA_RANK = {"observed": 3, "assessed": 3, "declared": 2, "inferred": 1,
              "not-observed": 0, "not assessed": 0, "unknown": 0}


def _parse_time(value: Any):
    from datetime import datetime, timezone
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        dt = datetime.fromisoformat(value.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def _now():
    from datetime import datetime, timezone
    epoch = os.environ.get("SOURCE_DATE_EPOCH")
    if epoch and epoch.isdigit():
        return datetime.fromtimestamp(int(epoch), timezone.utc)
    return datetime.now(timezone.utc)


def apply_acceptance(p: Dict[str, Any], record: Dict[str, Any], trusted: bool, label: str) -> Dict[str, Any]:
    """Record an operator's acceptance of exactly this assessment.

    Acceptance is valid only when the record lives outside the repository and
    is bound to the current revision, policy hash, decision, and (when given)
    artifact digest and environment, and has not expired. It is an unsigned,
    operator-declared statement: `declared-by-operator`, never `verified`.
    Any mismatch invalidates it with named reasons; a block or
    insufficient-evidence decision can never be accepted.
    """
    decision = p["assessment"]["decision"]["result"]
    reasons: List[str] = []
    if not trusted:
        reasons.append("acceptance record is inside the scanned repository (repository-controlled)")
    accepted_at = _parse_time(record.get("accepted_at"))
    expires = _parse_time(record.get("expires"))
    if not str(record.get("accepted_by", "")).strip():
        reasons.append("accepted_by missing")
    if accepted_at is None:
        reasons.append("accepted_at missing or not ISO-8601")
    if record.get("expires") is not None and expires is None:
        reasons.append("expires is not ISO-8601")
    gov = p.get("governance") or {}
    if gov.get("profile") == "citizen":
        acceptor = str(record.get("accepted_by", "")).strip().lower()
        named = {c.lower() for c in gov.get("custodians", [])} if gov.get("custodian_source") == "operator-policy" else set()
        if acceptor not in named:
            reasons.append("accepted_by is not a custodian named by the operator policy (citizen profile)")
    rejected = bool(reasons)
    if decision in ("block", "insufficient-evidence"):
        reasons.append("a %s decision cannot be accepted" % decision)
        rejected = True
    invalid: List[str] = []
    if not rejected:
        if record.get("decision_accepted") != decision:
            invalid.append("decision-changed (%s accepted, now %s)" % (record.get("decision_accepted"), decision))
        if not p.get("source_revision") or record.get("subject_revision") != p.get("source_revision"):
            invalid.append("revision-changed")
        if record.get("policy_hash") != p["assessment"]["decision"]["policy"]["hash"]:
            invalid.append("policy-changed")
        digest = record.get("artifact_digest")
        if digest and digest not in {d["digest"] for d in p["subject"].get("artifact_digests", [])}:
            invalid.append("digest-changed")
        env = record.get("environment")
        if env and env != p["subject"].get("environment"):
            invalid.append("environment-changed")
        if p["subject"].get("working_tree_dirty"):
            invalid.append("working-tree-dirty")
        if expires is not None and expires <= _now():
            invalid.append("expired")
    if rejected:
        acc = {"state": "rejected", "reasons": reasons}
    elif invalid:
        acc = {"state": "invalidated", "reasons": invalid}
    else:
        acc = {"state": "declared-by-operator", "reasons": []}
        p["lifecycle"]["state"] = "accepted"
    acc.update({
        "record": safe_text(label),
        "accepted_by": G.sanitize_text(str(record.get("accepted_by", "")), 80),
        "accepted_at": record.get("accepted_at") if accepted_at else None,
        "expires": record.get("expires") if expires else None,
        "bound_to": {"revision": record.get("subject_revision"), "policy_hash": record.get("policy_hash"),
                     "decision": record.get("decision_accepted"), "artifact_digest": record.get("artifact_digest"),
                     "environment": record.get("environment")},
        "note": "an unsigned operator statement recorded by jankhunt42; it is not verified and confers no authority",
    })
    p["lifecycle"]["acceptance"] = acc
    return p


def _integrity(doc: Dict[str, Any]) -> str:
    body = {k: v for k, v in doc.items() if k not in ("scan_id", "generated_at")}
    return "consistent" if G.sha(G.canonical_json(body), 32) == doc.get("scan_id") else "mismatch"


def compare(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Field-level comparison of two passports. Pure: reads only the two
    documents. `integrity` is a self-consistency check of each document's
    scan_id (was it edited after generation?), not a signature check."""
    for doc, which in ((old, "old"), (new, "new")):
        if doc.get("schema_version") != PASSPORT_SCHEMA:
            raise ValueError("%s document is not %s" % (which, PASSPORT_SCHEMA))

    def owners(d: Dict[str, Any]) -> set:
        return set(d["ownership"].get("owners", [])) | set(d["ownership"].get("declared_owners", []))

    def triggered(d: Dict[str, Any]) -> set:
        return {r["rule"] for r in d["assessment"]["decision"]["reasons"]}

    def digests(d: Dict[str, Any]) -> set:
        return {x["digest"] for x in d["subject"].get("artifact_digests", [])}

    def sources(d: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
        return {s["node"]: s for s in d["data"].get("sources", [])}

    od, nd = old["assessment"]["decision"]["result"], new["assessment"]["decision"]["result"]
    oe, ne = old["assessment"]["exposure"]["class"], new["assessment"]["exposure"]["class"]
    areas = {}
    regressions: List[str] = []
    for area in AREAS:
        a = old["coverage"]["evidence_areas"].get(area, "not-observed")
        b = new["coverage"]["evidence_areas"].get(area, "not-observed")
        if a != b:
            areas[area] = {"old": a, "new": b}
            if _AREA_RANK.get(b, 0) < _AREA_RANK.get(a, 0):
                regressions.append("evidence area %s: %s -> %s" % (area, a, b))
    if jh_policy.OUTCOME_RANK[nd] > jh_policy.OUTCOME_RANK[od]:
        regressions.append("decision %s -> %s" % (od, nd))
    if G.EXPOSURE_RANK.get(ne, 0) > G.EXPOSURE_RANK.get(oe, 0) or (ne == "Unknown" and oe != "Unknown"):
        regressions.append("exposure %s -> %s" % (oe, ne))
    lost_owners = sorted(owners(old) - owners(new))
    if lost_owners:
        regressions.append("owner(s) no longer present: %s" % ", ".join(lost_owners))
    os_, ns_ = sources(old), sources(new)
    reclassified = []
    for nid in sorted(set(os_) & set(ns_)):
        changes = {k: {"old": os_[nid][k], "new": ns_[nid][k]}
                   for k in ("sensitivity", "criticality", "environment", "trust_domain") if os_[nid][k] != ns_[nid][k]}
        if changes:
            reclassified.append({"node": nid, "label": ns_[nid]["label"], "changes": changes})
    oj, nj = old["assessment"]["jank"], new["assessment"]["jank"]
    report = {
        "schema_version": DELTA_SCHEMA,
        "tool": TOOL,
        "tool_version": VERSION,
        "old": {"scan_id": old.get("scan_id"), "revision": old.get("source_revision"), "generated_at": old.get("generated_at"),
                "integrity": _integrity(old)},
        "new": {"scan_id": new.get("scan_id"), "revision": new.get("source_revision"), "generated_at": new.get("generated_at"),
                "integrity": _integrity(new)},
        "decision": {"old": od, "new": nd, "rules_added": sorted(triggered(new) - triggered(old)),
                     "rules_removed": sorted(triggered(old) - triggered(new))},
        "exposure": {"old": oe, "new": ne},
        "jank": {"old": {"score": oj.get("score"), "grade": oj.get("grade")},
                 "new": {"score": nj.get("score"), "grade": nj.get("grade")}},
        "evidence_areas": areas,
        "owners": {"added": sorted(owners(new) - owners(old)), "removed": lost_owners},
        "artifact_digests": {"added": sorted(digests(new) - digests(old)), "removed": sorted(digests(old) - digests(new))},
        "data_sources": {"added": sorted(set(ns_) - set(os_)), "removed": sorted(set(os_) - set(ns_)),
                         "reclassified": reclassified},
        "policy_changed": old["assessment"]["decision"]["policy"]["hash"] != new["assessment"]["decision"]["policy"]["hash"],
        "graph_changed": old.get("graph_ref") != new.get("graph_ref"),
        "lifecycle": {"old": old["lifecycle"]["state"], "new": new["lifecycle"]["state"]},
        "regressions": regressions,
        "regressed": bool(regressions),
        "note": "a comparison of two local documents; integrity is a self-consistency check, not a signature",
    }
    return report


def compare_markdown(d: Dict[str, Any]) -> str:
    lines = ["# Passport comparison", "",
             "- Decision: **%s -> %s** (rules added: %s; removed: %s)" % (
                 d["decision"]["old"], d["decision"]["new"], ", ".join(d["decision"]["rules_added"]) or "none",
                 ", ".join(d["decision"]["rules_removed"]) or "none"),
             "- Exposure: %s -> %s; Jank Score: %s (%s) -> %s (%s)" % (
                 d["exposure"]["old"], d["exposure"]["new"], d["jank"]["old"]["score"], d["jank"]["old"]["grade"],
                 d["jank"]["new"]["score"], d["jank"]["new"]["grade"]),
             "- Revisions: %s -> %s; policy changed: %s; graph changed: %s" % (
                 (d["old"]["revision"] or "unknown")[:12], (d["new"]["revision"] or "unknown")[:12],
                 "yes" if d["policy_changed"] else "no", "yes" if d["graph_changed"] else "no"),
             "- Integrity (self-consistency, not a signature): old %s, new %s" % (d["old"]["integrity"], d["new"]["integrity"]),
             "- Lifecycle: %s -> %s" % (d["lifecycle"]["old"], d["lifecycle"]["new"]), ""]
    lines += ["## Regressions", ""] + (["- %s" % r for r in d["regressions"]] or ["- none"])
    if d["evidence_areas"]:
        lines += ["", "## Evidence areas", ""] + ["- %s: %s -> %s" % (k, v["old"], v["new"]) for k, v in d["evidence_areas"].items()]
    lines += ["", "## Changes", "",
              "- Owners: +%s / -%s" % (", ".join(d["owners"]["added"]) or "none", ", ".join(d["owners"]["removed"]) or "none"),
              "- Artifact digests: +%d / -%d" % (len(d["artifact_digests"]["added"]), len(d["artifact_digests"]["removed"])),
              "- Data sources: +%d / -%d / reclassified %d" % (len(d["data_sources"]["added"]), len(d["data_sources"]["removed"]),
                                                              len(d["data_sources"]["reclassified"]))]
    for r in d["data_sources"]["reclassified"][:20]:
        lines.append("  - %s: %s" % (r["label"], "; ".join("%s %s -> %s" % (k, v["old"], v["new"]) for k, v in r["changes"].items())))
    return "\n".join(safe_text(l) for l in lines)
