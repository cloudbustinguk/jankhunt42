#!/usr/bin/env python3
"""`jankhunt42 selftest`: self-assurance that does not grade its own homework.

A scanner that scans itself can award itself a perfect score, so the
dogfood steps here are reported but never decide the gate on their own.
The gate rests on independent evidence: an oracle-checked test suite,
a hand-maintained ground truth for the self-map, seeded fixtures,
mutation testing (deliberately broken copies must make tests fail), and a
privacy scan of shipped files and generated artifacts.

Each check reports pass | fail | skip | insufficient-evidence with the
exact command, exit code, and timing. Nothing is installed, fetched, or
sent anywhere; optional checks that need tools which are not present are
reported as `skip` and never counted as passes.
"""
from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional, Sequence, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
ROOT = os.path.dirname(HERE)
TESTS = os.path.join(ROOT, "tests")
CLI = os.path.join(HERE, "jankhunt42")

# (id, description, file, old, new, test pattern). Each mutant must be
# "killed": the named tests must fail against the mutated copy.
MUTANTS = [
    ("M1-permission-comparison", "integrity admits read instead of write/delete/admin", "jh_graph.py",
     'return base if cap in ("write", "delete", "admin") else None',
     'return base if cap in ("read",) else None', "test_graph.py"),
    ("M2-edge-type-filter", "depends-on edges propagate authority", "jh_graph.py",
     'if kind == "depends-on":\n        return None', 'if kind == "depends-on":\n        return base', "test_graph.py"),
    ("M3-redaction-branch", "key=value credential redaction disabled", "jh_graph.py",
     'out = _KV_SECRET_RE.sub(lambda m: m.group(1) + m.group(2) + "<redacted>", out)', 'out = out',
     "test_graph.py"),
    ("M4-unknown-as-safe", "unknown capability treated as no access", "jh_graph.py",
     'if kind in ("connects", "calls"):\n            return min(base, 1)',
     'if kind in ("connects", "calls"):\n            return None', "test_graph.py"),
    ("M5-policy-precedence", "repository config may weaken the effective policy", "jh_policy.py",
     'if ACTION_RANK[v] > ACTION_RANK[eff["actions"][k]]:', 'if True:', "test_passport.py"),
    ("M6-unverified-to-verified", "repository inventory claims become provider-verified", "jh_map.py",
     'verification = "provider-verified" if trusted else "declared"', 'verification = "provider-verified"',
     "test_map.py"),
    ("M7-coverage-floor", "partial coverage no longer forces insufficient-evidence", "jh_policy.py",
     'add("P-COV-001", "insufficient-evidence" if cov_reasons else "pass",',
     'add("P-COV-001", "pass",', "test_passport.py"),
    ("M8-accept-revision-mismatch", "an acceptance record survives a revision change", "jh_passport.py",
     'invalid.append("revision-changed")', 'pass', "test_extensions.py"),
    ("M9-csv-formula-injection", "CSV cells starting with = are no longer neutralized", "jh_map.py",
     'if text[:1] in ("=", "+", "-", "@", "\\t", "\\r"):', 'if False:', "test_extensions.py"),
    ("M10-not-run-counts-as-verified", "a verifier that did not run satisfies the verified-attestation gate",
     "jh_supply.py", 'tool_verified = any(r.get("outcome") == "tool-verified" for r in results)',
     'tool_verified = bool(results)', "test_verify.py"),
    ("M11-token-on-redirect", "the GitHub token is sent to redirect targets", "jh_verify.py",
     'if parts.hostname == API_HOST:', 'if parts.hostname:', "test_verify.py"),
    ("M12-in-repo-verify-plan", "a verification plan inside the repository is trusted", "jh_verify.py",
     'if _inside(path, root):\n        raise PlanError', 'if False:\n        raise PlanError', "test_verify.py"),
    ("M13-citizen-leads-only-review", "unverified production authority no longer blocks under the citizen profile",
     "jh_policy.py", '_outcome_for(acts["P-DAT-002"]) if cap == "block" else "review")', '"review")',
     "test_citizen.py"),
    ("M14-hidden-tags-ignored", "invisible Unicode tag characters are not reported", "jh_checks.py",
     'if not flag:\n                hit("tag", run, i)', 'if False:\n                hit("tag", run, i)',
     "test_agents.py"),
    ("M15-mcp-unpinned-as-pinned", "an MCP server fetched by npx without a version counts as pinned", "jh_agent.py",
     '"pinned": bool(_EXACT_VERSION.match(version))}', '"pinned": True}', "test_citizen.py"),
    ("M16-any-acceptor", "a citizen-profile acceptance by someone the operator did not name as custodian is accepted",
     "jh_passport.py", 'reasons.append("accepted_by is not a custodian named by the operator policy (citizen profile)")',
     'pass',
     "test_citizen.py"),
    ("M17-ai-pairs-ignored", "sensitive data reachable alongside an external AI service never reaches P-AI-001",
     "jh_policy.py", 'pairs = list(facts.get("ai_sensitive_pairs") or [])', 'pairs = []', "test_ai_governance.py"),
    ("M18-sbom-always-met", "every SBOM counts as meeting the NTIA minimum elements", "jh_supply.py",
     'status = "not-met" if not total else ("met" if not missing else "partial")', 'status = "met"',
     "test_sbom.py"),
    ("M19-every-secret-a-placeholder", "the placeholder filter hides real credentials", "jh_rules.py",
     'def secret_placeholder(match_text: str) -> bool:\n    """True when',
     'def secret_placeholder(match_text: str) -> bool:\n    return True\n    """True when', "test_precision.py"),
    ("M20-tls-context-ignored", "verify=False on an HTTP client is no longer reported", "jh_checks.py",
     "                elif not _HTTP_CALLEE_RE.search(callee):\n                    break",
     "                elif True:\n                    break", "test_precision.py"),
    ("M21-bypass-actors-ignored", "a GitHub App or deploy key that can bypass the branch rules is not reported",
     "jh_change.py", 'apps = [b for b in gate.bypass or [] if b["actor_type"] in APP_ACTORS]', "apps = []",
     "test_containment.py"),
    ("M22-repo-branch-rules-trusted", "a branch-rules export inside the repository counts as provider-verified",
     "jh_change.py", 'source = "provider-verified" if export_trusted else "declared"', 'source = "provider-verified"',
     "test_containment.py"),
    ("M23-safeloader-always", "every yaml.load counts as using a safe loader", "jh_checks.py",
     'if re.search(r"\\b(?:Safe|CSafe|Base)Loader\\b", text) or (alias and re.search(',
     'if True or (alias and re.search(', "test_precision.py"),
    ("M24-disallowed-registries-ignored", "a package source outside allowed_registries passes P-SUP-001",
     "jh_policy.py", '    elif reg.get("disallowed"):', "    elif False:", "test_containment.py"),
    ("M25-egress-outside-hidden", "a host reached outside the declared egress boundary is not reported",
     "jh_egress.py", '            if denied or (not allowed and not boundary["open"]):', "            if False:", "test_containment.py"),
    ("M26-branch-ci-write-ignored", "a write-scoped token on an any-branch push workflow is ignored",
     "jh_checks.py", "        write = _grants_write_explicit(perms)", "        write = False", "test_containment.py"),
    ("M27-shared-tenant-wildcards", "a sandbox wildcard on a shared cloud domain is not reported", "jh_checks.py",
     "    if any(base == s or base.endswith(s) for s in _SHARED_TENANT):", "    if False:", "test_containment.py"),
    ("M28-citizen-declared-change-control", "repository-declared change control satisfies P-CHG-001 under the "
     "citizen profile", "jh_policy.py", '    elif citizen and cc["state"] == "declared":', "    elif False:",
     "test_containment.py"),
    ("M29-fence-host-unchecked", "a host name from the repository goes into an emitted sandbox policy unchecked",
     "jh_fence.py", '    if _HOST_RE.match(h) and "." in h.lstrip("*.") or re.fullmatch(r"[a-z0-9][a-z0-9-]{0,62}", h):',
     "    if True:", "test_fence.py"),
    ("M30-fence-production-included", "a production asset goes into the agent's sandbox fence", "jh_fence.py",
     '        if n.get("environment") == "production":', "        if False:", "test_fence.py"),
    ("M31-git-config-not-overridden", "git runs the repository's own fsmonitor hook, hooks and signature program",
     "jh_core.py", '    opts = [a for kv in _GIT_SAFE_CONFIG for a in ("-c", kv)]', "    opts = []",
     "test_git_safety.py"),
    ("M32-git-filters-not-blanked", "git runs a filter program named by the repository", "jh_core.py",
     "    filters = [] if command in _GIT_NO_FILTER_COMMANDS else _git_filter_overrides(root)", "    filters = []",
     "test_git_safety.py"),
    ("M33-git-textconv-allowed", "git diff runs a text converter named by the repository", "jh_core.py",
     '        rest = rest[:pos + 1] + flags + rest[pos + 1:]', "        rest = rest",
     "test_git_safety.py"),
    ("M34-fence-credential-deny-unchecked", "a sandbox policy missing a credential read-deny passes its own gate",
     "jh_fence.py", "        elif not set(CREDENTIAL_PATHS).issubset(read_denies):", "        elif False:",
     "test_fence.py"),
    ("M35-egress-disabled-credited", "disabled declarations contribute coverage", "jh_egress.py",
     '        if boundary.get("selected") is not True or boundary.get("enabled") is not True:',
     '        if boundary.get("selected") is not True:', "test_egress_context.py"),
    ("M36-egress-scopes-merged", "two settings scopes of one tool are assessed as if their merge were known",
     "jh_egress.py", "    one_each = len(tools) == len(set(tools))", "    one_each = True", "test_egress_context.py"),
    ("M37-egress-unknown-not-redacted", "unknown egress retains topology in a shareable map", "jh_graph.py",
     '    if isinstance(eg, dict) and isinstance(eg.get("boundaries"), list):',
     '    if isinstance(eg, dict) and eg.get("state") == "declared":', "test_egress_context.py"),
    ("M38-egress-control-decoys", "unmodeled declaration syntax can establish coverage", "jh_egress.py",
     '        if not supported or inherited or global_rules and len(records) > 1:',
     '        if inherited or global_rules and len(records) > 1:', "test_egress_context.py"),

    ("M39-network-ceiling-not-intersected", "discovered destinations bypass the operator ceiling",
     "jh_ceiling.py", "        if (host, port) in ceiling:", "        if True:", "test_network_ceiling.py"),
    ("M40-network-ceiling-boolean-port", "a Boolean is accepted as an approved port",
     "jh_ceiling.py", "    if type(port) is not int or not 1 <= port <= 65535:",
     "    if not isinstance(port, int) or not 1 <= port <= 65535:", "test_network_ceiling.py"),
    ("M41-network-ceiling-repository-input", "a repository file becomes the operator ceiling",
     "jh_ceiling.py", "    if inside_repository(path, root):", "    if False:", "test_network_ceiling.py"),
    ("M42-network-ceiling-directory-alias", "a symlinked directory can select operator input",
     "jh_ceiling.py", "    if absolute != resolved:", "    if False:", "test_network_ceiling.py"),
    ("M43-network-ceiling-port-loss", "an exporter discards mandatory ceiling ports",
     "jh_fence.py", '        if fmt not in ("openshell", "claude-code"):', "        if False:", "test_network_ceiling.py"),
    ("M44-network-ceiling-duplicate-fields", "ambiguous duplicate JSON fields are accepted",
     "jh_ceiling.py", "        if key in result:", "        if False:", "test_network_ceiling.py"),
    ("M45-network-ceiling-parent-repository", "scanning a subdirectory promotes a containing-repository file",
     "jh_ceiling.py", '            if os.path.lexists(os.path.join(ancestor, ".git")):',
     "            if False:", "test_network_ceiling.py"),
    ("M46-network-ceiling-empty-path", "an explicitly empty ceiling path silently disables the limit",
     "jankhunt42", "if args.sandbox_network_ceiling is not None else None",
     "if args.sandbox_network_ceiling else None", "test_network_ceiling.py"),
    ("M47-claude-ceiling-ports-lost", "Claude export discards mandatory ceiling ports", "jh_fence.py",
     'port_qualified=fmt == "claude-code" and network_ceiling is not None',
     'port_qualified=False', "test_claude_ports.py"),
    ("M48-claude-reader-ports-ignored", "a grant for one port admits every port", "jh_egress.py",
     '    return True if target_port is None else None if port is None else port == target_port',
     '    return True', "test_claude_ports.py"),
    ("M49-egress-host-only-aggregation", "different destination ports collapse into one host", "jh_egress.py",
     '    return row["host"], row.get("port") or 0', '    return row["host"], 0', "test_claude_ports.py"),
    ("M50-claude-unknown-port-credited", "an unresolved destination port is admitted", "jh_egress.py",
     '    return True if target_port is None else None if port is None else port == target_port',
     '    return True if target_port is None or port is None else port == target_port', "test_claude_ports.py"),
    ("M51-claude-portless-narrowed", "a port-less entry is incorrectly limited to HTTPS", "jh_egress.py",
     '    return True if target_port is None else None if port is None else port == target_port',
     '    return port == 443 if target_port is None else None if port is None else port == target_port',
     "test_claude_ports.py"),
    ("M52-claude-port-range-unchecked", "an invalid port suffix is treated as a native grant", "jh_fence.py",
     '    if not re.fullmatch(r":[1-9][0-9]{0,4}", suffix) or int(suffix[1:]) > 65535:',
     '    if not re.fullmatch(r":[1-9][0-9]{0,4}", suffix):', "test_claude_ports.py"),
    ("M53-claude-version-note-missing", "port-qualified output omits its compatibility requirement", "jh_fence.py",
     '            notes.append(CLAUDE_PORT_NOTE)', '            notes.append("review compatibility")',
     "test_claude_ports.py"),
    ("M54-claude-default-ports-changed", "default export silently gains a version requirement", "jh_fence.py",
     'for r in p["allow"]}) if port_qualified else _hosts(p)',
     'for r in p["allow"]}) if True else _hosts(p)', "test_claude_ports.py"),

    ("M55-jh702-any-json-key-descriptive", "the bypass flag under any JSON key (a devcontainer's postCreateCommand) "
     "drops to minor", "jh_rules.py", "            return bool(_DESCRIPTIVE_KEY_RE.match(m.group(1)))",
     "            return True", "test_precision.py"),
    ("M56-tokenizer-quotes-skipped", "ordinary-span skipping overlooks string openers", "jh_core.py",
     '        starts = {token[0] for token in self.quotes}', '        starts = set()', "test_tokenizer.py"),
    ("M57-tokenizer-line-comments-skipped", "ordinary-span skipping overlooks unconditional comments", "jh_core.py",
     '        starts.update(token[0] for token in _ANY_LINE_COMMENTS.get(lang, ()))', '        pass',
     "test_tokenizer.py"),
    ("M58-tokenizer-space-comments-skipped", "ordinary-span skipping overlooks whitespace-sensitive comments",
     "jh_core.py", '        starts.update(token[0] for token in _WS_LINE_COMMENTS.get(lang, ()))',
     '        pass', "test_tokenizer.py"),
    ("M59-tokenizer-block-comments-skipped", "ordinary-span skipping overlooks block openers", "jh_core.py",
     '        starts.update(start[0] for start, _ in self.blocks)', '        pass', "test_tokenizer.py"),
    ("M60-tokenizer-regex-skipped", "a regex opener is missed in an embedded language", "jh_core.py",
     '        if self.regex:\n            starts.add("/")', '        if False:\n            starts.add("/")',
     "test_tokenizer.py"),
    ("M61-tokenizer-active-block-lost", "active block state is ignored before ordinary-span skipping", "jh_core.py",
     '            if self.block_end is not None:', '            if False:', "test_tokenizer.py"),
    ("M62-tokenizer-active-string-lost", "active string state is ignored before ordinary-span skipping", "jh_core.py",
     '            if self.str_end is not None:', '            if False:', "test_tokenizer.py"),

    ("M63-tokenizer-real-opener-overrun", "a skipped span consumes a real lexical opener", "jh_core.py",
     '                i = opener.start()', '                i = opener.end()', "test_tokenizer.py"),

    ("M64-capability-review-disabled", "new access no longer requires review", "jh_policy.py",
     'needs_review = bool((delta.get("counts") or {}).get("total") or (delta.get("counts") or {}).get("unknown"))',
     'needs_review = False', "test_capabilities.py"),
    ("M65-capability-policy-after-display", "display limits erase policy counts", "jh_capabilities.py",
     'counts.update(total=len(requests),', 'counts.update(total=len(requests[:DISPLAY_LIMIT]),', "test_capabilities.py"),
    ("M66-capability-production-ranked-last", "production requests are buried behind a host flood", "jh_capabilities.py",
     'not r["production"], r["kind"] not in ("credential", "agent"), r["id"]))',
     'not r["production"], r["kind"] not in ("credential", "agent"), r["id"]), reverse=True)', "test_capabilities.py"),
    ("M67-capability-unknown-port-as-443", "an unknown port counts as a known approved port", "jh_capabilities.py",
     'port = a.get("port") or G.DEFAULT_PORTS.get(a.get("engine"))',
     'port = a.get("port") or G.DEFAULT_PORTS.get(a.get("engine"), 443)', "test_capabilities.py"),
    ("M68-capability-read-inherits-write", "a read path inherits mutating authority", "jh_capabilities.py",
     'if impact == "integrity":', 'if impact == "confidentiality":', "test_capabilities.py"),
    ("M69-capability-path-is-identity", "moving evidence creates new requested access", "jh_capabilities.py",
     'semantic = dict(kind=kind, principal=principal, target=target, action=action)',
     'semantic = dict(kind=kind, principal=principal, target=target, action=action, location=sorted(refs))', "test_capabilities.py"),
    ("M70-capability-base-uncertainty-erased", "a resolved head erases unresolved base authority", "jh_capabilities.py",
     'unknowns = sorted([u for k, u in {**bu, **hu}.items() if not (k in bu and k in hu)], key=lambda u: u["id"])',
     'unknowns = sorted([u for k, u in hu.items() if k not in bu], key=lambda u: u["id"])', "test_capabilities.py"),
    ("M71-capability-repo-ignore-hides-access", "repository ignore globs erase the security view", "jh_capabilities.py",
     'declarations = cfg.passport',
     'declarations = cfg.passport\n        col.items = [i for i in col.items if not any(__import__("fnmatch").fnmatch(i.rel, p) for p in cfg.ignore_globs)]',
     "test_capabilities.py"),
    ("M72-detonate-network-on", "the sandbox runs with a network", "jh_sandbox.py",
     '"--network=none", "--read-only"', '"--read-only"', "test_sandbox.py"),
    ("M73-detonate-canary-read-ignored", "reading a canary credential is not reported", "jh_sandbox.py",
     "            if f and f.group(1) in paths and not re.search", "            if False and re.search",
     "test_sandbox.py"),
    ("M74-capability-opaque-change-unchanged", "a changed hook or MCP definition passes as an unchanged unknown",
     "jh_capabilities.py", "        if old is None or old != new:", "        if old is None:", "test_capabilities.py"),
    ("M75-capability-unchanged-not-redacted", "a shareable passport keeps unchanged unknowns' labels", "jh_passport.py",
     '        delta["unchanged_unknowns"] = [{"id": u["id"], "detail": "unresolved access, unchanged"}\n'
     '                                       for u in delta.get("unchanged_unknowns", [])]',
     '        pass', "test_capabilities.py"),
    ("M76-approval-stale-context", "an approval accepts a different analysis context", "jh_capability_approval.py",
     '        if record[key] != expected[key]:', '        if key != "context_hash" and record[key] != expected[key]:',
     "test_capability_approval.py"),
    ("M77-approval-only-displayed-rows", "an approval can cover only the displayed subset", "jh_capability_approval.py",
     '    if trunc.get("truncated") or any(counts.get(key, 0) != len(delta.get(field) or []) for key, field in',
     '    if False and any(counts.get(key, 0) != len(delta.get(field) or []) for key, field in', "test_capability_approval.py"),
    ("M78-approval-template-incomplete", "an incomplete comparison can emit an approval template", "jh_capability_approval.py",
     '    if problems:\n        raise ValueError("cannot emit capability approval: "',
     '    if False:\n        raise ValueError("cannot emit capability approval: "', "test_capability_approval.py"),
    ("M79-approval-unknowns-accepted", "active unknowns can be approved", "jh_capability_approval.py",
     '    if counts.get("unknown") or delta.get("unknowns"):', '    if False:', "test_capability_approval.py"),
    ("M80-approval-repo-adds-approver", "repository policy adds an allowed approver", "jh_policy.py",
     'set(cur.get("approvers", [])) & set(caps["approvers"])',
     'set(cur.get("approvers", [])) | set(caps["approvers"])', "test_capability_approval.py"),
    ("M81-approval-expiry-ignored", "an expired approval remains accepted", "jh_capability_approval.py",
     '        if not issued <= clock < expires:', '        if not issued <= clock:', "test_capability_approval.py"),
    ("M82-capability-unmapped-file-window", "an edit far from line 1 of an unmapped file passes as unchanged",
     "jh_capabilities.py", '        if row["action"] == "resolve-analysis":', '        if False:', "test_capabilities.py"),
    ("M83-n8n-discovery-disabled", "workflow exports disappear", "jh_n8n.py",
     "    if not candidate(path, text):", "    if True:", "test_n8n.py"),
    ("M84-n8n-unknown-version-trusted", "future versions reuse known operation tables", "jh_n8n.py",
     "version not in VERSIONS.get(typ, ())", "False", "test_n8n.py"),
    ("M85-n8n-header-secret-hidden", "literal authorization headers escape detection", "jh_n8n.py",
     "            name = pair_name if k == 'value' and _secret_name(pair_name) else k",
     "            name = k", "test_n8n.py"),
    ("M86-n8n-definition-erased", "late execution edits inherit unchanged uncertainty", "jh_capabilities.py",
     "        return n8n.get(row['principal'])", "        return row['principal']", "test_n8n.py"),
    ("M87-n8n-masked-executable-unchanged", "a secret-named executable parameter evades review", "jh_n8n.py",
     "if comparable else None", "if True else None", "test_n8n.py"),
    ("M88-n8n-unknown-http-method-trusted", "a known host hides opaque HTTP behavior", "jh_map.py",
     "cap == 'unknown' or jh_n8n.dynamic(raw['parameters'])", "False", "test_n8n.py"),
    ("M89-n8n-field-bound-disabled", "workflow parameter floods bypass their bound", "jh_n8n.py",
     "fields > MAX_FIELDS or depth > MAX_DEPTH", "False or depth > MAX_DEPTH", "test_n8n.py"),
    ("M90-n8n-principal-label-identity", "display labels become capability identity", "jh_capabilities.py",
     "        return a['n8n_key']", "        return node['display_label']", "test_n8n.py"),
    ("M91-detonate-command-in-runner", "a repository's hook command is pasted into the sandbox runner script",
     "jh_sandbox.py", '        runner = "sh /jh/step.%d.sh" % i', '        runner = step["script"]', "test_sandbox.py"),
    ("M92-detonate-follows-links", "settings behind a link (the user's own ~/.claude) are read and run",
     "jh_sandbox.py", "        if os.path.islink(path):\n            return False", "        if False:\n            return False",
     "test_sandbox.py"),
    ("M93-detonate-open-surface-off", "the commands that run when a repository is opened are never planned",
     "jh_sandbox.py", '    if "open" in surfaces:\n        _plan_open', '    if False:\n        _plan_open', "test_sandbox.py"),
    ("M94-detonate-raw-step-names", "a task label or server name with a newline forges a line in the report",
     "jh_sandbox.py", '    name = jh_graph.sanitize_text(name, 80).replace("*", "").replace("`", "\'")', "    name = name",
     "test_sandbox.py"),
    ("M95-detonate-vscode-quotes-everything", "every VS Code task argument is quoted, so $(...) that runs in the "
     "editor stays inert in the sandbox", "jh_sandbox.py",
     "    return \"'\" + value + \"'\" if _unquoted_space(value) and not already else value",
     "    return shlex.quote(value)", "test_sandbox.py"),
    ("M96-detonate-follows-output-links", "a link the sandbox leaves in its output makes the host read a file it "
     "points to", "jh_sandbox.py", "os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK |", "os.O_RDONLY | os.O_NONBLOCK |",
     "test_sandbox.py"),
    ("M97-detonate-empty-trace-observed", "an empty or forged trace counts as observation", "jh_sandbox.py",
     '            traced = trace is not None and problem != "unusable" and _started(trace_text, i)',
     "            traced = trace is not None", "test_sandbox.py"),
    ("M98-detonate-dns-lines-unchecked", "any line in the sandbox's DNS log becomes a report entry", "jh_sandbox.py",
     "    names = sorted(n for n in lines if _HOSTNAME.match(n))", "    names = sorted(lines)", "test_sandbox.py"),
    ("M99-detonate-vscode-dependencies-skipped", "a payload in a folder-open task's dependency never runs",
     "jh_sandbox.py", "            out.extend(_vscode_chain(by_label[dep], by_label, gaps, stack + (label,)))",
     "            pass", "test_sandbox.py"),
    ("M100-trigger-projection-disabled", "declared triggers disappear from access review", "jh_capabilities.py",
     "        if trigger:\n            add('trigger'", "        if False:\n            add('trigger'", "test_n8n_triggers.py"),
    ("M101-trigger-disabled-exemption", "a disabled trigger is not mapped", "jh_map.py",
     "            if principal and trigger:", "            if principal and trigger and not raw.get('disabled'):", "test_n8n_triggers.py"),
    ("M102-trigger-binding-assumed", "route and activation are assumed verified", "jh_capabilities.py",
     "                principal['evidence_refs'], uncertain=True)", "                principal['evidence_refs'], uncertain=False)", "test_n8n_triggers.py"),
    ("M103-trigger-share-details", "shareable map keeps trigger node receipts", "jh_graph.py",
     "        rep['triggers'] = trigger_counts(rep['triggers'])", "        pass", "test_n8n_triggers.py"),
    ("M104-trigger-count-after-display", "summary counts only displayed trigger declarations", "jh_n8n.py",
     "        counts['total'] += 1", "        counts['total'] += len(entries) < TRIGGER_LIMIT", "test_n8n_triggers.py"),
    ("M105-trigger-path-disclosed", "a webhook path leaks into reports", "jh_n8n.py",
     "else 'literal-withheld' if isinstance(path, str) and path else 'missing'",
     "else path if isinstance(path, str) and path else 'missing'", "test_n8n_triggers.py"),
    ("M110-detonate-digest-ignores-content", "a run on one tree matches a passport of an edited tree", "jh_sandbox.py",
     '                entries.append(["file", rel, 1 if st.st_mode & 0o100 else 0, content.hexdigest()])',
     '                entries.append(["file", rel, 1 if st.st_mode & 0o100 else 0])', "test_sandbox.py"),
    ("M111-passport-stale-sandbox-used", "a sandbox run made on a different tree is used", "jh_sandbox.py",
     '    if doc["tree"]["digest"] != digest["digest"]:', "    if False:", "test_sandbox.py"),
    ("M112-p-run-alerts-ignored", "sandbox ALERTs never reach the decision", "jh_policy.py",
     '    alerts = (sandbox.get("counts") or {}).get("ALERT", 0) if sandbox.get("state") == "matched" else 0',
     "    alerts = 0", "test_sandbox.py"),
    ("M113-detonate-digest-unreadable-empty", "an unreadable folder counts as empty, so another tree matches",
     "jh_sandbox.py", "        for name in sorted(os.listdir(base)):",
     "        for name in (sorted(os.listdir(base)) if os.access(base, os.R_OK) else []):", "test_sandbox.py"),
    ("M114-passport-base-working-tree-digest", "with --base, a run is matched against the working tree, not the commit",
     "jankhunt42", "            if snapshot:\n                # --base assesses the commit",
     "            if False:\n                # --base assesses the commit", "test_sandbox.py"),
    ("M115-passport-redact-keeps-step-names", "a shared passport keeps the sandbox steps' task and server names",
     "jh_passport.py", '        alert["step"] = "step-%d" % i           # step names carry task labels and server names',
     "        pass", "test_sandbox.py"),
    ("M116-detonate-cache-copy-follows-links", "a link in the operator's cache makes the copy read the file it points "
     "to", "jh_sandbox.py", "            st = os.stat(name, dir_fd=dfd, follow_symlinks=False)",
     "            st = os.stat(name, dir_fd=dfd, follow_symlinks=True)", "test_sandbox.py"),
    ("M117-detonate-pip-not-isolated", "a pip.py in the repository stands in for the installer", "jh_sandbox.py",
     'PIP_OFFLINE = "python3 -I -m pip install', 'PIP_OFFLINE = "python3 -m pip install', "test_sandbox.py"),
    ("M118-detonate-npm-omits-dev", "a repository .npmrc can leave dev dependencies (and their hooks) out",
     "jh_sandbox.py", '"--include=dev --include=optional --include=peer")', '"--include=optional --include=peer")',
     "test_sandbox.py"),
    ("M119-detonate-cache-copy-unbudgeted", "a cache that grows while it is copied is copied whole", "jh_sandbox.py",
     '                            if counts["bytes"] > budget:', "                            if False:", "test_sandbox.py"),
    ("M120-detonate-cache-in-repository", "a repository's own folder is accepted as the dependency cache",
     "jh_sandbox.py", "    if jh_ceiling.inside_repository(path, root):", "    if False:", "test_sandbox.py"),
    ("M121-detonate-npm-ci-never-planned", "with a cache and a lockfile, dependencies still never install",
     "jh_sandbox.py", '        if "npm" in caches and lock:', "        if False:", "test_sandbox.py"),
    ('M122-n8n-code-repository-principal', 'embedded results are attributed to repository code', 'jh_map.py',
     '        self.app = principal or graph.add_node("application",',
     '        self.app = graph.add_node("application",', "test_n8n_code.py"),
    ('M123-n8n-code-evidence-collision', 'two embedded sources share one receipt', 'jh_graph.py',
     ' + ([location] if location else [])',
     '', "test_n8n_code.py"),
    ('M124-n8n-code-inherits-repo-config', 'repository config resolves a workflow runtime variable', 'jh_map.py',
     '    _resolve_env(child)',
     '    child.defs = ctx.defs\n    _resolve_env(child)', "test_n8n_code.py"),
    ('M125-n8n-code-residual-unknown-removed', 'mapping a call hides arbitrary code uncertainty', 'jh_map.py',
     "                g.add_edge(principal, target, 'calls', 'unknown', 'declared', 'high', evidence=ev)\n                _adapt_n8n_code",
     '                _adapt_n8n_code', "test_n8n_code.py"),
    ('M126-n8n-code-limits-silent', 'omitted embedded source counts as complete coverage', 'jh_map.py',
     '        if capped or any(len(line) > MAX_LINE for line in nocomment):',
     '        if False:', "test_n8n_code.py"),
    ('M127-n8n-code-interpolation-literal', 'an interpolated template becomes a literal target', 'jh_n8n_code.py',
     " or '${' in body",
     '', "test_n8n_code.py"),
    ('M128-n8n-code-spread-assumed', 'dynamic option spreads cannot override the assumed method', 'jh_n8n_code.py',
     '            return None  # spreads, computed keys, shorthand, methods',
     '            continue', "test_n8n_code.py"),

    ('M129-n8n-code-operation-source-unscoped', 'unrelated declarations become code operation targets', "jh_map.py",
     '            if ev and (ctx.source_pointer is None or ev.get("json_pointer") == ctx.source_pointer):',
     '            if ev:', "test_n8n_code.py"),

    ("M130-acquire-unapproved-origin", "a URL outside the approved origins is downloaded", "jh_acquire.py",
     '    if not approved(artifact["url"], origins):', "    if False:", "test_acquire.py"),
    ("M131-acquire-private-address", "a registry name resolving to a private or metadata address is fetched",
     "jh_acquire.py", "    if not addr.is_global or addr.is_multicast:", "    if False:", "test_acquire.py"),
    ("M132-acquire-hash-unchecked", "bytes that differ from the lockfile's sha512 are kept", "jh_acquire.py",
     '            if digest.hexdigest() != artifact["sha512"]:', "            if False:", "test_acquire.py"),
    ("M133-acquire-dot-segments", "a ../ path escapes the approved origin's prefix", "jh_acquire.py",
     '            any(seg in (".", "..") for seg in u.path.split("/")):', "            False:", "test_acquire.py"),
    ("M134-acquire-output-in-repository", "the acquired cache lands inside the repository", "jh_acquire.py",
     "    if jh_ceiling.inside_repository(out, root):", "    if False:", "test_acquire.py"),
    ("M135-p-run-undeclared-ignored", "destinations the repository does not declare never reach the decision",
     "jh_policy.py", '    undeclared = sandbox.get("undeclared") or [] if sandbox.get("state") == "matched" else []',
     "    undeclared = []", "test_sandbox.py"),
    ("M136-declared-port-ignored", "a host declared on 443 also declares a connection to port 22", "jh_sandbox.py",
     "        return ports[host] is None or port is None or port in ports[host]", "        return True",
     "test_sandbox.py"),
    ("M137-declared-after-the-cap", "only the first 100 attempts are compared, so a later one hides",
     "jh_sandbox.py", "    for a in attempts:", "    for a in attempts[:MAX_ATTEMPTS]:", "test_sandbox.py"),
    ("M138-acquire-rejected-bytes-free", "downloads that fail verification spend none of the budget", "jh_acquire.py",
     '                received += getattr(exc, "received", 0)', "                pass", "test_acquire.py"),
    ("M139-acquire-lockfile-link-followed", "a lockfile link is followed out of the repository", "jh_acquire.py",
     "        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)",
     "        fd = os.open(path, os.O_RDONLY | os.O_NONBLOCK)", "test_acquire.py"),
    ("M140-acquire-conflicting-pins", "one URL pinned to two hashes is fetched under both", "jh_acquire.py",
     "        if pins[url] > 1:", "        if False:", "test_acquire.py"),
    ("M141-acquire-cut-short-free", "bytes a cut-short response consumed spend none of the budget",
     "jh_acquire.py", '        usage["received"] = max(usage.get("received", 0), received)',
     "        pass", "test_acquire.py"),
    ("M142-acquire-header-bytes-free", "bytes read while parsing headers that then fail are charged nothing",
     "jh_acquire.py", "        self.metered = _MeteredResponse(sock, *args, limit=self.limit, **kwargs)",
     "        return _MeteredResponse(sock, *args, limit=self.limit, **kwargs)", "test_acquire.py"),
    ("M143-acquire-response-left-open", "a refused response keeps its socket open until it is collected",
     "jh_acquire.py", "                handed_off.close()                    # with Connection: close, the response owns the socket",
     "                pass", "test_acquire.py"),
    ("M144-acquire-connection-cycle", "the connection's bound response factory keeps it alive until a cycle collection",
     "jh_acquire.py", '            conn.__dict__.pop("response_class", None)     # break the cycle with its bound response factory',
     "            pass", "test_acquire.py"),
    ("M145-acquire-read-past-limit", "a response keeps reading past the byte limit (trailers, framing)",
     "jh_acquire.py", "        if self.limit is not None:", "        if False:", "test_acquire.py"),
    ('M146-tls-cert-none-missed', 'ssl.CERT_NONE turns TLS checks off unnoticed', 'jh_rules.py',
     '          r"\\bverify_mode\\s*=\\s*(?:ssl\\.)?CERT_NONE\\b",',
     '', "test_trial_recall.py"),
    ('M147-npm-scripts-unscoped', 'curl|sh anywhere in a JSON file is reported, not only in npm scripts', 'jh_rules.py',
     '                for line_no, script in scripts:',
     '                for line_no, script in enumerate(sf.raw, 1):', "test_trial_recall.py"),
    ('M148-npm-scripts-unread', 'a postinstall that pipes curl to sh goes unreported', 'jh_rules.py',
     '      confidence="high", target="nocomment", langs=SCRIPT + ("yaml", "docker", "json"),',
     '      confidence="high", target="nocomment", langs=SCRIPT + ("yaml", "docker"),', "test_trial_recall.py"),
    ('M149-connection-string-password', 'a password inside a connection string is not a secret', 'jh_rules.py',
     '          r"(?i)\\b(?:server|host|data\\s+source)\\s*=[^\\"\'\\n]*?\\b(?:password|pwd)\\s*[:=]\\s*[\'\\"]?[^;\\"\'\\s${%<]{6,}",',
     '', "test_trial_recall.py"),
    ("M150-anon-jwt-flagged", "any JWT is a secret, the public anon key included", "jh_rules.py",
     "                            while m and _jwt_role(m.group(0)) not in _PRIVILEGED_JWT_ROLES:",
     "                            while False:", "test_trial_recall.py"),
    ('M151-hidden-no-ask-missed', 'a hidden comment telling the agent not to ask the user goes unreported', 'jh_checks.py',
     '        elif _HIDDEN_NO_ASK_RE.search(body):',
     '        elif False:', "test_trial_recall.py"),
    ("M152-connection-password-shown", "a connection-string password is printed in the evidence", "jh_core.py",
     '    return _value_spans(text, _CONN_PASSWORD_RE, (\'\\\\"\', \'""\', "\'\'", \'"\', "\'"), True, 1, False)',
     "    return []", "test_trial_recall.py"),
    ('M153-brief-names-nothing', 'the citizen brief never names the problems', 'jh_passport.py',
     '            "top_problems": top_problems(findings),',
     '            "top_problems": [],', "test_trial_recall.py"),
    ("M154-local-db-password-critical", "a password for a localhost database is reported as critical",
     "jh_rules.py", "                            if host and _local_db_host(host.group(1)):",
     "                            if False:", "test_trial_recall.py"),
    ('M155-tls-server-context-flagged', 'a TLS server that does not ask for client certificates is reported', 'jh_checks.py',
     '            return bool(_SERVER_TLS_RE.search(expr))',
     '            return False', "test_trial_recall.py"),
    ('M156-npm-scripts-by-line', 'a compact or unusually spaced package.json hides its postinstall from JH111', 'jh_rules.py',
     '    if "scripts" not in top_members or text[top_members["scripts"][0]] != "{":',
     '    if True:', "test_trial_recall.py"),
    ("M157-attempt-flag-lost", "the shareable passport marks an undeclared attempt as declared", "jh_sandbox.py",
     "        a[\"declared\"] = declared(a)                 # kept by --redact, which renames the targets",
     "        pass", "test_sandbox.py"),
    ("M158-deep-json-crashes", "JSON nested past the decoder's limit stops the passport with a traceback",
     "jh_supply.py", "    except (ValueError, TypeError, RecursionError):\n        return None\n\n\ndef _as_list",
     "    except (ValueError, TypeError):\n        return None\n\n\ndef _as_list", "test_fuzz.py"),
    ("M159-escaped-quote-ends-value", "a password with a backslash-escaped quote is shown after the quote",
     "jh_core.py", '        if len(quote) == 1 and end > start and text[end - 1] == "\\\\":',
     "        if False:", "test_trial_recall.py"),
    ("M160-later-secret-skipped", "a secret whose key lies inside a value read too far is shown", "jh_core.py",
     "        start = m.end()\n        quote = next((q for q in quotes if text.startswith(q, start)), \"\")",
     "        if spans and m.start() < spans[-1][1]:\n            continue\n        start = m.end()\n"
     "        quote = next((q for q in quotes if text.startswith(q, start)), \"\")", "test_trial_recall.py"),
    ('M161-import-surface-skipped', 'dependencies are never loaded after the install', 'jh_sandbox.py',
     '        _plan_import(root, steps, gaps)',
     '        pass', 'test_sandbox.py'),
    ('M162-dependency-name-unchecked', 'a dependency name that is not a package name reaches a step', 'jh_sandbox.py',
     '                if not _NPM_NAME.match(name):',
     '                if False:', 'test_sandbox.py'),
    ('M163-loader-record-unread', 'a wheel without top_level.txt loads none of its modules', 'jh_sandbox_load.py',
     '        elif os.path.isfile(record):',
     '        elif False:', 'test_sandbox.py'),
    ('M164-loads-uncapped', 'every direct dependency loads, however many there are', 'jh_sandbox.py',
     '    for name, script, source, dep in loads[:MAX_IMPORT_STEPS]:',
     '    for name, script, source, dep in loads:', 'test_sandbox.py'),
    ('M165-ignore-rule-unapplied', '--ignore-rule is recorded but the rule still reports', 'jankhunt42',
     '        ignore_rule_ids=ignored_rules(args) or None,',
     '        ignore_rule_ids=None,', 'test_ignore_rule.py'),
    ('M166-governance-ignore-unapplied', "the passport's governance scans ignore --ignore-rule", 'jankhunt42',
     '    ignored = set(getattr(args, "governance_ignore_ids", None) or ()) or None',
     '    ignored = None', 'test_ignore_rule.py'),
    ('M167-ruleset-examples-unchecked', 'a site rule that misses its own example is accepted', 'jh_ruleset.py',
     '        if not hits(line):',
     '        if False:', 'test_rulesets.py'),
    ('M168-in-repo-ruleset-trusted', 'a ruleset inside the repository switches off citizen governance leads', 'jh_ruleset.py',
     '                 trusted=not jh_ceiling.inside_repository(path, root))',
     '                 trusted=True)', 'test_rulesets.py'),
    ('M169-unknown-ignore-accepted', '--ignore-rule takes an id no rule has', 'jankhunt42',
     '        return "--ignore-rule: no such rule: %s" % ", ".join(unknown)',
     '        pass', 'test_rulesets.py'),
    ('M170-python-download-hash-unchecked', 'Python bytes are retained without checking their sha256 pin', 'jh_acquire.py',
     '            if digest.hexdigest() != artifact["sha256"]:',
     '            if False:', 'test_pyfetch.py'),
    ('M171-python-unhashed-pin-accepted', 'a Python requirement without a sha256 hash authorizes fetching', 'jh_pyfetch.py',
     '            elif not hashes or _HASH.sub("", options).strip():',
     '            elif _HASH.sub("", options).strip():', 'test_pyfetch.py'),
    ('M172-python-wildcard-pin-accepted', 'a nonexact Python version authorizes fetching', 'jh_pyfetch.py',
     '            if _version_key(version) is None:',
     '            if False:', 'test_pyfetch.py'),
    ('M173-python-index-hash-ignored', 'the index chooses files whose hashes are not pinned in requirements', 'jh_pyfetch.py',
     '        if not isinstance(digest, str) or digest.lower() not in pin["hashes"]:',
     '        if not isinstance(digest, str):', 'test_pyfetch.py'),
    ('M174-python-source-before-wheel', 'a source build is chosen even though a wheel hash is pinned', 'jh_pyfetch.py',
     '            wheels = [a for a in matches if a["kind"] == "wheel"]',
     '            wheels = []', 'test_pyfetch.py'),
    ('M175-python-index-origin-unchecked', 'a simple API request leaves the approved origins', 'jh_pyfetch.py',
     '        if not A.approved(url, origins):',
     '        if False:', 'test_pyfetch.py'),
    ('M176-python-filename-path-unchecked', 'a distribution filename can contain a path', 'jh_pyfetch.py',
     '    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._+!-]{0,239}", filename):',
     '    if False:', 'test_pyfetch.py'),
    ('M177-python-failed-index-bytes-free', 'a failed index consumes none of the shared budget', 'jh_pyfetch.py',
     '        err.received = max(size, usage["received"])',
     '        err.received = 0', 'test_pyfetch.py'),
    ('M178-python-npm-budget-not-shared', 'Python gets the whole allowance after npm has already spent it', 'jh_acquire.py',
     '                                                MAX_TOTAL_BYTES - received, stream,',
     '                                                MAX_TOTAL_BYTES, stream,', 'test_pyfetch.py'),
    ('M179-python-wheelhouse-not-handed-on', 'the sandbox ignores the acquired Python wheelhouse', 'jankhunt42',
     '            npm_cache, wheelhouse = fetched["cache"], fetched.get("wheelhouse")',
     '            npm_cache, wheelhouse = fetched["cache"], None', 'test_pyfetch.py'),
    ('M180-python-source-build-unmarked', 'a downloaded source archive is reported as running no build code', 'jh_pyfetch.py',
     '                                 {"bytes": size, "build_runs_code": a["kind"] == "sdist"})',
     '                                 {"bytes": size, "build_runs_code": False})', 'test_pyfetch.py'),
    ('M181-python-filename-hash-conflict-ignored', 'different pinned hashes can overwrite the same wheelhouse filename', 'jh_pyfetch.py',
     '        if len(names[a["filename"]]) != 1:',
     '        if False:', 'test_pyfetch.py'),
    ('M182-python-distribution-count-unbounded', 'an index can choose more distribution files than the run allows', 'jh_pyfetch.py',
     '        if len(selected) > A.MAX_ARTIFACTS:',
     '        if False:', 'test_pyfetch.py'),
    ('M183-python-index-wire-cap-ignored', 'a simple API response can read past its own wire-byte cap', 'jh_pyfetch.py',
     '        chunks = stream(url, min(limit, MAX_INDEX_BYTES), usage)',
     '        chunks = stream(url, limit, usage)', 'test_pyfetch.py'),
    ('M184-gh-canary-missing', "the GitHub CLI's hosts.yml is not a canary, so reading it goes unseen", 'jh_sandbox.py',
     '    ("gh", ".config/gh/hosts.yml", "github.com:\\n    oauth_token: gho_JH42CANARY{h26}\\n    user: canary\\n"),',
     '', 'test_sandbox.py'),
    ('M185-pyproject-dependencies-uninstalled', 'dependencies declared only in pyproject.toml never install', 'jh_sandbox.py',
     '    if declared and "wheels" in caches:',
     '    if False:', 'test_sandbox.py'),
    ('M186-pyproject-option-passed', 'a pyproject entry shaped like a pip option reaches pip', 'jh_sandbox.py',
     '    return [d.strip() for d in deps if isinstance(d, str) and _PY_REQUIREMENT.match(d.strip())',
     '    return [d.strip() for d in deps if isinstance(d, str)', 'test_sandbox.py'),
    ('M187-pth-step-missing', '.pth files installed by a dependency never run', 'jh_sandbox.py',
     '        loads.insert(0, ("python startup (.pth files)", "python3 -I /jh/load.py --pth", "site-packages", ""))',
     '        pass', 'test_sandbox.py'),
    ('M188-node-load-no-settle', 'a timer a dependency defers at load time never runs where it is seen', 'jh_sandbox.py',
     'SETTLE_SECONDS = 2        # after a load, time for what it deferred (a timer, a thread) to run where it is seen',
     'SETTLE_SECONDS = 0', 'test_sandbox.py'),
    ('M189-python-load-no-settle', 'a thread a Python package starts at import never runs where it is seen', 'jh_sandbox_load.py',
     'SETTLE_SECONDS = 2        # after loading, time for what it deferred (a timer, a thread) to run where it is seen',
     'SETTLE_SECONDS = 0', 'test_sandbox.py'),
    ('M190-ruleset-secret-printed', "a credential in a site rule's title is printed in every report", 'jh_ruleset.py',
     '    if _secret_in(value):\n        # this text is printed in every report: it must not carry a credential',
     '    if False:\n        # this text is printed in every report: it must not carry a credential', 'test_rulesets.py'),
    ('M191-site-overrun-silent', 'a site rule switched off for running away leaves no warning', 'jh_rules.py',
     '        result.site_overrun.add(rule.id)',
     '        pass', 'test_rulesets.py'),
    ('M192-ruleset-fifo-read', 'a ruleset that is not a regular file is read anyway', 'jh_ruleset.py',
     '        if not stat.S_ISREG(os.fstat(fd).st_mode):',
     '        if False:', 'test_rulesets.py'),
    ('M193-pyproject-array-overread', 'the 3.9/3.10 reading runs past the dependencies array', 'jh_sandbox.py',
     '                if q.group(3):\n                    break',
     '                if False:\n                    break', 'test_sandbox.py'),
    ('M194-review-overrun-silent', 'review drops the warning for a site rule switched off for running away', 'jh_review.py',
     '            + overrun\n',
     '            + []\n', 'test_rulesets.py'),
    ('M195-url-credentials-printed', "a URL user:password in a site rule's text is printed in every report", 'jh_ruleset.py',
     '    return redact_secrets(value) != value or bool(_URL_CREDENTIALS.search(value))',
     '    return redact_secrets(value) != value', 'test_rulesets.py'),
    ('M200-nuget-unlocked-fetched', 'a project not in locked mode authorizes NuGet downloads', 'jh_nuget.py',
     "            if not _locked(root, project, tree['files']):",
     '            if False:', 'test_nuget.py'),
    ('M201-nuget-hash-unchecked', 'NuGet bytes are retained without verifying contentHash', 'jh_acquire.py',
     '            if digest.hexdigest() != artifact["sha512"]:',
     '            if False:', 'test_nuget.py'),
    ('M202-nuget-package-path-accepted', 'a lock package id can become a path', 'jh_nuget.py',
     "                if not _ID.fullmatch(name) or not re.search('[A-Za-z0-9]', name) or not v or len(digest) != 64 or \\",
     "                if False or not re.search('[A-Za-z0-9]', name) or not v or len(digest) != 64 or \\", 'test_nuget.py'),
    ('M203-nuget-conflicts-ignored', 'conflicting pins for one package and version are accepted', 'jh_nuget.py',
     '        if len(hashes[key]) != 1:',
     '        if False:', 'test_nuget.py'),
    ('M204-nuget-lock-version-unchecked', 'unsupported NuGet lock formats are accepted', 'jh_nuget.py',
     "doc['version'] not in (1, 2)",
     'False', 'test_nuget.py'),
    ('M205-nuget-rejected-bytes-free', 'failed NuGet downloads spend none of their allowance', 'jh_nuget.py',
     "                result['downloaded'] += getattr(exc, 'received', 0)",
     '                pass', 'test_nuget.py'),
    ('M206-nuget-shared-budget-ignored', 'NuGet receives a new budget after Python has spent it', 'jh_acquire.py',
     '            nuget_result = jh_nuget.acquire(nuget_plan, approved_origins, os.path.join(stage, "out", "nuget"),\n                                            MAX_TOTAL_BYTES - received, stream)',
     '            nuget_result = jh_nuget.acquire(nuget_plan, approved_origins, os.path.join(stage, "out", "nuget"),\n                                            MAX_TOTAL_BYTES, stream)', 'test_nuget.py'),
    ('M207-dotnet-restore-unlocked', 'dotnet restore can change its lock file', 'jh_sandbox.py',
     'dotnet restore --locked-mode --source /cache/nuget',
     'dotnet restore --source /cache/nuget', 'test_nuget.py'),
    ('M208-dotnet-build-restores', 'dotnet build performs another restore', 'jh_sandbox.py',
     'dotnet build --no-restore --disable-build-servers',
     'dotnet build --disable-build-servers', 'test_nuget.py'),
    ('M209-nuget-feed-writable', 'package code can modify the verified feed', 'jh_sandbox.py',
     '"nuget": ("/cache/nuget", "ro")',
     '"nuget": ("/cache/nuget", "rw")', 'test_nuget.py'),
    ('M210-dotnet-image-for-all-repos', 'the SDK image is selected for non-.NET repositories', 'jh_sandbox.py',
     '        if jh_nuget.is_dotnet(root) and present(DOTNET_IMAGE):',
     '        if present(DOTNET_IMAGE):', 'test_nuget.py'),
    ('M211-dotnet-sdk-gap-ignored', 'dotnet commands are planned despite the missing SDK image', 'jh_sandbox.py',
     '    if not ready:',
     '    if False:', 'test_nuget.py'),
    ('M212-dotnet-telemetry-on', 'the guest does not opt out of dotnet telemetry', 'jh_sandbox.py',
     '"DOTNET_CLI_TELEMETRY_OPTOUT=1"',
     '"DOTNET_CLI_TELEMETRY_OPTOUT=0"', 'test_nuget.py'),
    ('M213-dotnet-missing-engine-aborts', 'a .NET run without its runner stops without a coverage report', 'jh_sandbox.py',
     '    if not engine and not dotnet:',
     '    if not engine:', 'test_nuget.py'),
    ('M214-nuget-lock-link-followed', 'a lock file link is read outside the repository', 'jh_nuget.py',
     '        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)',
     '        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NONBLOCK, dir_fd=fd)', 'test_nuget.py'),

    ('M215-dotnet-data-route-skipped', 'minimal API data endpoints are never checked', 'jh_dotnet.py', '        if _sensitive(m[2], route, body):', '        if False:', 'test_dotnet.py'),
    ('M216-dotnet-anonymous-override-ignored', 'AllowAnonymous is ignored on a protected route group', 'jh_dotnet.py', "        anonymous = bool(re.search(r'\\.AllowAnonymous\\s*\\(', tail)) or m[1] in anonymous_vars or (assigned and assigned[1] in anonymous_vars)", '        anonymous = False', 'test_dotnet.py'),
    ('M217-dotnet-public-cors-flagged', 'anonymous public CORS is called credentialed', 'jh_dotnet.py', "        if re.search(r'\\.AllowCredentials\\s*\\(', code[begin:finish]):", '        if True:', 'test_dotnet.py'),
    ('M218-dotnet-dev-guard-global', 'a closed development guard hides later developer errors', 'jh_dotnet.py', '            if not any(a <= m.start() < b for a,b in guarded)]', '            if not guarded]', 'test_dotnet.py'),
    ('M219-dotnet-https-middleware-ignored', 'HTTPS redirection does not qualify a public listener lead', 'jh_dotnet.py', "    if ctx.get('https') or sf.rel.lower().endswith('launchsettings.json') or '.development.' in sf.rel.lower():", "    if sf.rel.lower().endswith('launchsettings.json') or '.development.' in sf.rel.lower():", 'test_dotnet.py'),
    ('M220-dotnet-parameterized-ef-flagged', 'EF parameterized interpolation is treated as raw SQL', 'jh_dotnet.py', 'FromSqlRaw|ExecuteSqlRaw', 'FromSql(?:Raw|Interpolated)|ExecuteSqlRaw', 'test_dotnet.py'),
    ('M221-dotnet-safe-type-handling-flagged', 'TypeNameHandling.None is reported as unsafe', 'jh_dotnet.py', '(?:All|Auto|Objects|Arrays)', '(?:All|Auto|Objects|Arrays|None)', 'test_dotnet.py'),
    ('M222-dotnet-redaction-ignored', 'redacted personal fields still produce an AI disclosure lead', 'jh_dotnet.py', '            return any(not any(a <= p.start() < b for a,b in spans) for p in re.finditer(field,fragment,re.I))', '            return any(True for p in re.finditer(field,fragment,re.I))', 'test_dotnet.py'),
    ('M223-nuget-fixed-version-flagged', 'fixed package references are reported as floating', 'jh_dotnet.py', "            if '*' in v:", '            if v:', 'test_dotnet.py'),
    ('M224-msbuild-local-command-flagged', 'any local MSBuild command is called a download', 'jh_dotnet.py', "            if re.search(r'\\b(?:curl|wget|Invoke-WebRequest|Invoke-RestMethod|DownloadString|DownloadFile)\\b', command, re.I) and \\\n                    re.search(r'https?://', command, re.I):", '            if command:', 'test_dotnet.py'),
    ('M225-dotnet-url-credential-printed', 'MSBuild download evidence leaks URL credentials', 'jh_dotnet.py', "    evidence = sanitize_text(sf.raw[line - 1] if line <= len(sf.raw) else '', 200)", "    evidence = sf.raw[line - 1] if line <= len(sf.raw) else ''", 'test_dotnet.py'),
    ('M226-dotnet-citizen-exposure-ignored', 'citizen governance ignores exposed ASP.NET data endpoints', 'jh_passport.py', 'EXPOSURE_RULES = {"JH132", "JH133", "JH134", "JH135", "JH136"}', 'EXPOSURE_RULES = {"JH132", "JH133", "JH134", "JH136"}', 'test_dotnet.py'),

    ('M227-dotnet-delimiters-rescanned', 'malformed C# calls repeatedly scan the file and exhaust the scan budget', 'jh_dotnet.py', '@lru_cache(maxsize=2)', '# delimiter caching disabled', 'test_dotnet.py'),
    ('M228-dotnet-sanitizing-hides-pii', 'ordinary text sanitizing is treated as personal-data redaction', 'jh_dotnet.py', 'Redact|Anonymi[sz]e|Saniti[sz]e(?:Pii|PersonalData)|RemovePii', 'Redact|Anonymi[sz]e|Saniti[sz]e|RemovePii', 'test_dotnet.py'),

    ('M229-dotnet-false-guard-trusted', 'a development check compared with false is treated as a safe development guard', 'jh_dotnet.py', "            literal = comparison[1 if reverse else 3] == 'true'", '            literal = True', 'test_dotnet.py'),
    ('M230-dotnet-dev-only-https-trusted', 'development-only HTTPS redirection hides a public production HTTP listener', 'jh_dotnet.py', "            item['https'] |= any(_unconditional_in_production(m.start(), branches)", "            item['https'] |= any(True", 'test_dotnet.py'),
    ('M231-dotnet-reassigned-group-inherited', 'a child route inherits authorization from a reassigned parent', 'jh_dotnet.py', '        if assignments.get(m[1], 0) <= 1 and _unconditional_in_production(m.start(), branches) and \\', '        if True and _unconditional_in_production(m.start(), branches) and \\', 'test_dotnet.py'),
    ('M232-dotnet-dev-only-auth-trusted', 'authorization applied only in development protects production routes in the scan', 'jh_dotnet.py', '        elif assignments.get(m[1], 0) <= 1 and _unconditional_in_production(m.start(), branches):', '        elif assignments.get(m[1], 0) <= 1:', 'test_dotnet.py'),

    ('M233-python-docstring-called-hook', 'a literal Python docstring is called an executable install hook', 'jh_rules.py',
     'while m and _in_python_docstring(sf, idx, m, python_docstrings):',
     'while False and _in_python_docstring(sf, idx, m, python_docstrings):', 'test_report_precision.py'),
    ('M234-regex-called-agent-launch', 'a JavaScript flag detector is called an agent launch', 'jh_rules.py',
     'while m and _in_regex_spans(agent_regexes, m.end() - 1):',
     'while False and _in_regex_spans(agent_regexes, m.end() - 1):', 'test_report_precision.py'),
    ('M235-listing-citation-called-imperative', 'a quoted listing example is called a direct instruction', 'jh_checks.py',
     '|(?:description|listing|message|input|document|text)\\s+contains?', '', 'test_report_precision.py'),
    ('M236-citation-hides-stronger-instruction', 'a citation hides a later imperative on the same line', 'jh_checks.py',
     'if old is None or SEV_RANK[severity] < SEV_RANK[old[0]]:',
     'if old is None or severity == "critical":', 'test_report_precision.py'),

]

_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+@([A-Za-z0-9\-]+\.)+[A-Za-z]{2,}")
_ALLOWED_EMAIL_DOMAINS = ("example.com", "example.org", "example.net", "example.invalid", "users.noreply.github.com")
_SECRET_PATTERNS = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----\s*\n\s*[A-Za-z0-9+/=]{40,}")),
    ("aws-key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
]
_PASCAL_RE = re.compile("Jank" + "Hunt")


class Check:
    def __init__(self, cid: str, title: str, mandatory: bool = True):
        self.id = cid
        self.title = title
        self.mandatory = mandatory
        self.status = "insufficient-evidence"
        self.detail = ""
        self.commands: List[Dict[str, Any]] = []
        self.data: Dict[str, Any] = {}
        self.seconds = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"id": self.id, "title": self.title, "mandatory": self.mandatory, "status": self.status,
                "detail": self.detail, "seconds": round(self.seconds, 2), "commands": self.commands,
                "data": self.data}


def _rel_cmd(cmd: Sequence[str]) -> str:
    out = []
    for c in cmd:
        c = str(c)
        if c.startswith(ROOT):
            c = os.path.relpath(c, ROOT)
        elif c == sys.executable:
            c = "python3"
        elif c.startswith(tempfile.gettempdir()):
            c = "$TMP/" + os.path.basename(c)
        out.append(c)
    return " ".join(out)


def _run(check: Check, cmd: Sequence[str], timeout: int = 900, cwd: Optional[str] = None,
         env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    e = dict(os.environ, PYTHONDONTWRITEBYTECODE="1")
    e.pop("FORCE_COLOR", None)
    if env:
        e.update(env)
    t0 = time.time()
    try:
        proc = subprocess.run(list(cmd), capture_output=True, text=True, timeout=timeout, cwd=cwd or ROOT, env=e)
    except subprocess.TimeoutExpired:
        proc = subprocess.CompletedProcess(list(cmd), 124, "", "timeout after %ds" % timeout)
    check.commands.append({"command": _rel_cmd(cmd), "exit_code": proc.returncode,
                           "seconds": round(time.time() - t0, 2)})
    return proc


def _tail(text: str, n: int = 6) -> str:
    lines = [l for l in (text or "").strip().splitlines() if l.strip()]
    return "\n".join(lines[-n:])


def check_unit_tests() -> Check:
    c = Check("unit-tests", "unittest suite: oracle, metamorphic, adapters, policy, diff, fuzz, snapshots, compat")
    if not os.path.isdir(TESTS):
        c.detail = "tests/ directory not present in this installation"
        return c
    proc = _run(c, [sys.executable, "-m", "unittest", "discover", "-s", TESTS])
    summary = _tail(proc.stderr, 3)
    m = re.search(r"Ran (\d+) tests?", proc.stderr or "")
    skipped = re.search(r"skipped=(\d+)", proc.stderr or "")
    c.data = {"tests": int(m.group(1)) if m else None, "skipped": int(skipped.group(1)) if skipped else 0}
    c.status = "pass" if proc.returncode == 0 else "fail"
    c.detail = summary
    return c


def check_shell_suite() -> Check:
    c = Check("shell-regression", "scripts/selftest.sh end-to-end CLI regression suite")
    bash = shutil.which("bash")
    if not bash:
        c.status, c.detail = "skip", "bash not available on this system"
        c.mandatory = False
        return c
    proc = _run(c, [bash, os.path.join(HERE, "selftest.sh")])
    c.status = "pass" if proc.returncode == 0 else "fail"
    c.detail = _tail(proc.stdout + "\n" + proc.stderr, 2)
    return c


def _json_cli(c: Check, *args: str) -> Optional[Dict[str, Any]]:
    proc = _run(c, [sys.executable, CLI] + list(args))
    try:
        return json.loads(proc.stdout)
    except ValueError:
        c.detail = "invalid JSON from %s: %s" % (" ".join(args[:2]), _tail(proc.stderr, 2))
        return None


def check_self_map() -> Check:
    c = Check("dogfood-map", "self-map vs hand-maintained ground truth (tests/fixtures/self-expected.json)")
    expected_path = os.path.join(TESTS, "fixtures", "self-expected.json")
    if not os.path.exists(expected_path):
        c.detail = "ground-truth fixture missing"
        return c
    with open(expected_path, encoding="utf-8") as fh:
        expected = json.load(fh)
    rep = _json_cli(c, "map", ROOT, "--json", "--no-config")
    if rep is None:
        c.status = "fail"
        return c
    labels = {}
    for n in rep["graph"]["nodes"]:
        labels[n["id"]] = "jankhunt42" if n["kind"] == "application" else n["display_label"]
    got = {(labels[e["source"]], e["kind"], e["capability"], labels[e["target"]]) for e in rep["graph"]["edges"]}
    want = {(e["source"], e["kind"], e["capability"], e["target"]) for e in expected["edges"]}
    fp = sorted(got - want)
    fn = sorted(want - got)
    bad_kinds = sorted({n["kind"] for n in rep["graph"]["nodes"]} & set(expected.get("must_not_contain", [])))
    c.data = {"expected_edges": len(want), "observed_edges": len(got), "true_positives": len(got & want),
              "false_positives": [list(x) for x in fp], "false_negatives": [list(x) for x in fn],
              "forbidden_kinds_present": bad_kinds, "exposure": rep["assessment"]["exposure"]["class"],
              "coverage": rep["coverage"]["status"]}
    c.status = "pass" if not fp and not fn and not bad_kinds else "fail"
    c.detail = "%d/%d expected edges found, %d false positive(s), %d false negative(s)" % (
        len(got & want), len(want), len(fp), len(fn))
    return c


def check_self_scan_and_passport() -> Check:
    c = Check("dogfood-passport", "self-scan and self-passport (reported, never self-approving)", mandatory=False)
    scan = _json_cli(c, "scan", ROOT, "--json")
    pp = _json_cli(c, "passport", ROOT, "--json")
    if scan is None or pp is None:
        c.status = "fail"
        return c
    c.data = {"jank_score": scan["summary"]["jank_score"], "findings": scan["summary"]["counts"],
              "passport_decision": pp["assessment"]["decision"]["result"],
              "passport_reasons": [r["rule"] for r in pp["assessment"]["decision"]["reasons"]],
              "exposure": pp["assessment"]["exposure"]["class"],
              "lifecycle": pp["lifecycle"]["state"], "acceptance": pp["lifecycle"]["acceptance"]["state"]}
    ok = pp["lifecycle"]["acceptance"]["state"] == "not-supplied"
    c.status = "pass" if ok else "fail"
    c.detail = ("self-scan Jank Score %s; self-passport decision %s. A self-issued passport is evidence about "
                "the tool's own inputs, not certification of release readiness." % (
                    c.data["jank_score"], c.data["passport_decision"]))
    return c


def _copy_tree(tmp: str) -> None:
    shutil.copytree(HERE, os.path.join(tmp, "scripts"), ignore=shutil.ignore_patterns("__pycache__"))
    shutil.copytree(TESTS, os.path.join(tmp, "tests"), ignore=shutil.ignore_patterns("__pycache__"))
    if os.path.isdir(os.path.join(ROOT, "templates")):
        shutil.copytree(os.path.join(ROOT, "templates"), os.path.join(tmp, "templates"))


def check_mutants() -> Check:
    c = Check("mutation", "representative mutants must be killed by the test suite")
    if not os.path.isdir(TESTS):
        c.detail = "tests/ directory not present"
        return c
    results = []
    # Control: the unmutated copy must pass the same tests, otherwise a
    # "kill" could just mean the copy itself is broken.
    controls: Dict[str, bool] = {}
    for pattern in sorted({m[5] for m in MUTANTS}):
        tmp = tempfile.mkdtemp(prefix="jh-control-")
        try:
            _copy_tree(tmp)
            proc = _run(c, [sys.executable, "-m", "unittest", "discover", "-s", os.path.join(tmp, "tests"),
                            "-p", pattern], timeout=600, cwd=tmp)
            controls[pattern] = proc.returncode == 0
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    if not all(controls.values()):
        c.status = "fail"
        c.detail = "control (unmutated) copy failed: %s" % ", ".join(p for p, ok in controls.items() if not ok)
        c.data = {"controls": controls}
        return c
    for mid, desc, fname, old, new, pattern in MUTANTS:
        tmp = tempfile.mkdtemp(prefix="jh-mutant-")
        try:
            _copy_tree(tmp)
            path = os.path.join(tmp, "scripts", fname)
            with open(path, encoding="utf-8") as fh:
                src = fh.read()
            if src.count(old) != 1:
                results.append({"id": mid, "description": desc, "status": "invalid",
                                "detail": "mutation anchor not found exactly once (source changed?)"})
                continue
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(src.replace(old, new))
            proc = _run(c, [sys.executable, "-m", "unittest", "discover", "-s", os.path.join(tmp, "tests"),
                            "-p", pattern], timeout=600, cwd=tmp)
            results.append({"id": mid, "description": desc,
                            "status": "killed" if proc.returncode != 0 else "survived", "tests": pattern})
        finally:
            shutil.rmtree(tmp, ignore_errors=True)
    killed = sum(1 for r in results if r["status"] == "killed")
    c.data = {"controls": controls, "attempted": len(results), "killed": killed,
              "survived": [r["id"] for r in results if r["status"] == "survived"],
              "invalid": [r["id"] for r in results if r["status"] == "invalid"], "mutants": results}
    c.status = "pass" if killed == len(results) == len(MUTANTS) else "fail"
    c.detail = "%d/%d mutants killed" % (killed, len(MUTANTS))
    return c


def _shipped_files() -> List[str]:
    try:
        out = subprocess.run(["git", "-C", ROOT, "ls-files", "-z", "--cached", "--others", "--exclude-standard"],
                             capture_output=True, timeout=30)
        if out.returncode == 0:
            files = [p for p in out.stdout.decode("utf-8", "replace").split("\0") if p]
            return [f for f in files if not f.startswith("docs/") and os.path.isfile(os.path.join(ROOT, f))]
    except (OSError, subprocess.SubprocessError):
        found = []  # no usable git: fall back to walking the tree below
    found = []
    for base, dirs, names in os.walk(ROOT):
        dirs[:] = [d for d in dirs if d not in (".git", "docs", "__pycache__")]
        found += [os.path.relpath(os.path.join(base, n), ROOT) for n in names]
    return found


def check_privacy() -> Check:
    c = Check("privacy", "shipped files and generated artifacts: no emails, tokens, keys, home paths, or PascalCase name")
    problems: List[str] = []
    home = os.path.expanduser("~")
    for rel in sorted(_shipped_files()):
        if rel.endswith((".png", ".jpg", ".gif", ".ico")):
            continue
        try:
            with open(os.path.join(ROOT, rel), encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        for m in _EMAIL_RE.finditer(text):
            before = text[max(0, m.start() - 80):m.start()].split()[-1:] or [""]
            if "://" in before[0] or text[max(0, m.start() - 3):m.start()].endswith("://"):
                continue  # URL userinfo (user:pass@host) in a test fixture, not an email address
            dom = m.group(0).split("@", 1)[1].lower()
            if not any(dom == d or dom.endswith("." + d) for d in _ALLOWED_EMAIL_DOMAINS) and not m.group(0).startswith("noreply@"):
                if "@" in m.group(0) and not re.match(r"^[\w.\-]+@\d", m.group(0)):
                    problems.append("%s: email-like string %s" % (rel, m.group(0)))
        for name, rx in _SECRET_PATTERNS:
            if rx.search(text):
                problems.append("%s: %s pattern" % (rel, name))
        if _PASCAL_RE.search(text):
            problems.append("%s: PascalCase product name (use 'jankhunt42')" % rel)
        if len(home) > 1 and home in text:
            problems.append("%s: absolute home path" % rel)
    tmp = tempfile.mkdtemp(prefix="jh-privacy-")
    try:
        demo = os.path.join(tmp, "demo-app")
        shutil.copytree(os.path.join(TESTS, "fixtures", "demo-app"), demo)
        for args in (("map", "--json"), ("map", "--html"), ("passport", "--json"), ("passport", "--html"),
                     ("map", "--json", "--redact"), ("passport", "--json", "--redact")):
            proc = _run(c, [sys.executable, CLI, args[0], demo] + list(args[1:]))
            out = proc.stdout
            for needle, what in (("example-only", "fixture password"), (tmp, "absolute temp path"), (home, "home path")):
                if needle and needle in out:
                    problems.append("generated %s leaks %s" % (" ".join(args), what))
            if "--redact" in args:
                for needle in ("ledger-db.prod.internal", "demo-org", "payments-api"):
                    if needle in out:
                        problems.append("redacted %s still shows %s" % (" ".join(args), needle))
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    c.data = {"problems": problems[:50], "files_scanned": len(_shipped_files())}
    c.status = "pass" if not problems else "fail"
    c.detail = "%d problem(s)" % len(problems)
    return c


def check_python_matrix() -> Check:
    c = Check("python-matrix", "unit tests on locally cached Python images (docker, --pull never, --network none)",
              mandatory=False)
    docker = shutil.which("docker")
    if not docker:
        c.status, c.detail = "skip", "docker not available; matrix not run (not a pass)"
        return c
    ran = []
    for image in ("python:3.9-slim", "python:3.10-slim", "python:3.11-slim", "python:3.12-slim", "python:3.13-slim",
                  "python:3.14-slim"):
        probe = subprocess.run([docker, "image", "inspect", image], capture_output=True, timeout=60)
        if probe.returncode != 0:
            ran.append({"image": image, "status": "skip", "detail": "image not cached locally; not pulled"})
            continue
        proc = _run(c, [docker, "run", "--rm", "--pull", "never", "--network", "none", "-v", "%s:/src:ro" % ROOT,
                        "-w", "/src", "-e", "PYTHONDONTWRITEBYTECODE=1", image,
                        "python", "-m", "unittest", "discover", "-s", "tests"], timeout=900)
        ran.append({"image": image, "status": "pass" if proc.returncode == 0 else "fail",
                    "detail": _tail(proc.stderr, 2)})
    c.data = {"images": ran}
    statuses = {r["status"] for r in ran}
    c.status = "fail" if "fail" in statuses else ("pass" if "pass" in statuses else "skip")
    c.detail = ", ".join("%s %s" % (r["image"], r["status"]) for r in ran)
    return c


def check_independent_analyzers() -> Check:
    c = Check("independent-analyzers", "independent tools if installed locally (never installed or fetched)",
              mandatory=False)
    results = []
    # Always available: byte-compile every script with the stdlib compiler,
    # into a throwaway directory so no cache lands in the skill directory.
    tmp = tempfile.mkdtemp(prefix="jh-compile-")
    try:
        script = ("import py_compile,sys,os\n"
                  "bad=0\n"
                  "for f in sys.argv[2:]:\n"
                  "    try: py_compile.compile(f, cfile=os.path.join(sys.argv[1], os.path.basename(f)+'.pyc'), doraise=True)\n"
                  "    except py_compile.PyCompileError as e: print(e); bad=1\n"
                  "sys.exit(bad)\n")
        files = sorted(os.path.join(HERE, f) for f in os.listdir(HERE) if f.endswith(".py")) + [CLI]
        proc = _run(c, [sys.executable, "-c", script, tmp] + files)
        results.append({"tool": "py_compile (stdlib)", "status": "pass" if proc.returncode == 0 else "fail"})
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    optional = [
        ("ruff", ["ruff", "check", "--no-cache", "--select", "E9,F63,F7,F82", HERE]),
        ("pyflakes", ["pyflakes", HERE]),
        ("bandit", ["bandit", "-q", "-ll", "-r", HERE]),
        ("shellcheck", ["shellcheck", "-S", "error", os.path.join(HERE, "selftest.sh")]),
    ]
    for name, cmd in optional:
        if not shutil.which(cmd[0]):
            results.append({"tool": name, "status": "skip", "detail": "not installed (not counted as a pass)"})
            continue
        proc = _run(c, cmd, timeout=600)
        results.append({"tool": name, "status": "pass" if proc.returncode == 0 else "fail",
                        "detail": _tail(proc.stdout + proc.stderr, 3)})
    c.data = {"tools": results}
    statuses = [r["status"] for r in results]
    c.status = "fail" if "fail" in statuses else "pass"
    c.detail = ", ".join("%s %s" % (r["tool"], r["status"]) for r in results)
    return c


def gate(checks: Sequence[Check]) -> str:
    if any(c.status == "fail" for c in checks):
        return "fail"
    if any(c.mandatory and c.status != "pass" for c in checks):
        return "insufficient-evidence"
    return "pass"


def run(full: bool) -> Dict[str, Any]:
    from jh_core import VERSION
    checks: List[Check] = []
    steps = [check_unit_tests]
    if full:
        steps += [check_shell_suite, check_self_map, check_self_scan_and_passport, check_mutants,
                  check_privacy, check_independent_analyzers, check_python_matrix]
    for step in steps:
        t0 = time.time()
        c = step()
        c.seconds = time.time() - t0
        checks.append(c)
    rev = None
    try:
        p = subprocess.run(["git", "-C", ROOT, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        rev = p.stdout.strip() or None if p.returncode == 0 else None
    except (OSError, subprocess.SubprocessError):
        rev = None  # not a git checkout, or git unavailable: report the revision as unknown
    result = gate(checks)
    return {
        "schema_version": "jankhunt.selftest.v1",
        "tool": "jankhunt42",
        "tool_version": VERSION,
        "source_revision": rev,
        "mode": "full" if full else "quick",
        "gate": result,
        "note": ("the gate rests on independent checks; a perfect self-scan or self-passport is never "
                 "a substitute for them, and this tool creates no release"),
        "checks": [c.to_dict() for c in checks],
        "not_run": [] if full else ["shell-regression", "dogfood-map", "dogfood-passport", "mutation",
                                    "privacy", "independent-analyzers", "python-matrix"],
    }


def markdown(rep: Dict[str, Any]) -> str:
    out = ["# jankhunt42 selftest (%s)" % rep["mode"], "",
           "- Gate: **%s**" % rep["gate"], "- Version: %s; revision: %s" % (rep["tool_version"], rep["source_revision"] or "unknown"),
           "- %s" % rep["note"], "", "| check | status | detail |", "|---|---|---|"]
    for c in rep["checks"]:
        out.append("| %s%s | %s | %s |" % (c["id"], "" if c["mandatory"] else " (optional)", c["status"],
                                          c["detail"].replace("\n", " ").replace("|", "/")[:160]))
    if rep["not_run"]:
        out += ["", "Not run in quick mode (use `--full`): %s" % ", ".join(rep["not_run"])]
    return "\n".join(out)


def main(args: Any) -> int:
    rep = run(bool(getattr(args, "full", False)))
    if getattr(args, "json", False):
        print(json.dumps(rep, indent=2, ensure_ascii=False))
    else:
        print(markdown(rep))
    return 0 if rep["gate"] == "pass" else 1
