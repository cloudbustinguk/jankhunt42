# Software passport, exposure, and release policy (`jankhunt42 passport`)

`passport` answers **can we responsibly ship it?** It links the evidence
jankhunt42 already produces into one versioned document and applies a small,
explainable policy. It is a **local assessment**:

- not a certificate, not a compliance attestation, and never an approval;
- lifecycle is `draft` (assessment incomplete), `assessed`, or `accepted`.
  `accepted` requires a separately supplied operator acceptance record (see
  below), which this tool never creates or infers;
- attestation verification states are what the **exporter** recorded, or
  what a native verifier reported under `--verify`; jankhunt42 itself never
  verifies signatures or signer identity;
- evidence that was not found is `not-observed` (unknown), never "absent".

## Commands

For changes between committed revisions, see [requested access changes](capability-delta.md).

```sh
jankhunt42 passport .                          # TTY: software passport; piped: Markdown
jankhunt42 passport . --json                   # jankhunt.passport.v1
jankhunt42 passport . --html > passport.html   # offline, printable
jankhunt42 passport . --redact --json          # shareable: no hosts, owners, or snippets
jankhunt42 passport . --policy ../policy.json  # operator policy (outside the repository)
jankhunt42 passport . --fail-on block          # enforce: exit 1 on block
jankhunt42 passport . --profile citizen        # software built by non-engineers: strict, explained in plain terms
jankhunt42 passport . --inventory ../inventory.json
jankhunt42 passport . --acceptance ../acceptance.json        # operator acceptance record
jankhunt42 passport . --compare old-passport.json            # what changed since a stored passport
jankhunt42 passport --compare old.json --against new.json    # two stored passports, no scan
jankhunt42 passport . --verify ../verify-plan.json           # run gh/cosign/jf on the provenance first
jankhunt42 passport . --branch-rules ../rules/app.json       # the repository's rulesets, exported by an operator
jankhunt42 passport . --emit-sandbox-policy claude-code       # an agent network fence instead of a passport (citizen.md)
```

Advisory by default (exit `0` whatever the decision). `--fail-on review`,
`insufficient-evidence`, or `block` turns on enforcement: exit `1` when the
decision is at or above that outcome (`pass < review < insufficient-evidence
< block`). Exit `2` is a usage error.

`passport` runs the scanner with the same defaults as `scan`, but never with
`--cve` or `--calibrate`: it stays offline and writes nothing.

## What a passport contains

| Section | Source | States |
|---|---|---|
| `assessment.jank` | Jank Score 2.0, unchanged arithmetic | score, grade, policy |
| `assessment.exposure` | `map` exposure class | Low / Moderate / High / Critical / Unknown |
| `assessment.decision` | policy rules below | pass / review / insufficient-evidence / block |
| `ownership` | `CODEOWNERS` (observed), `passport.owners` (declared) | observed / declared / unknown |
| `governance` | profile, custodians, public-exposure and agent leads, AI agent tooling from the map, plain-language brief | standard / citizen |
| `provenance` | SBOMs and attestations via `supply-chain` parsers; `sbom_minimum_elements` and `sbom_missing` for the most complete SBOM | observed / not-observed; met / partial / not-met / none |
| `ai` | AI-use inventory: model services the software can reach (with evidence tier and who reaches them), agent tool servers and instruction files, human-oversight posture, sensitive data reachable alongside an AI service | assessed / not assessed; `observed` |
| `alignment` | orientation crosswalk from every rule and evidence area to NIST AI RMF subcategories and AIGP domains ([`ai-governance.md`](ai-governance.md)) | orientation only |
| `data` | data sources from the map, with classifications and who classified them | assessed / not assessed |
| `operations` | CI config, tests, observability SDKs, health probes, runbooks, `SECURITY.md` | observed / inferred / declared / not-observed |
| `change_control` | the default branch's merge gate, from `--branch-rules` or Terraform GitHub resources (below) | provider-verified / declared / unknown; each check met / not-met / unknown |
| `package_sources` | registries each package manager resolves from: committed config (declared) and lockfiles (observed), assessed against `allowed_registries` | observed / declared / unknown per ecosystem |
| `egress` | declared agent-sandbox allowlists compared with the hosts the map reaches (`references/connectivity.md`) | declared / unknown |
| `subject` | git revision, dirty flag, artifact digests from attestation subjects | digests labeled exporter-reported |
| `remediation` | derived from triggered rules and missing evidence | top steps |
| `unknowns`, `limitations` | map unknowns and fixed statements | |

Evidence coverage is reported as "N of 10 areas observed, declared, or
inferred" (`change_control` is the tenth). Observability from an SDK reference is `inferred` (it suggests
telemetry; it does not prove alerting). Emails in `CODEOWNERS` are redacted.

## Decision rules

The decision is the most severe rule outcome. It is never a weighted average,
and a strong area never offsets a weak one. Defaults below are for the
`standard` profile; the `citizen` profile column is in
`references/citizen.md`.

| Rule | Triggers | Default outcome |
|---|---|---|
| `P-COV-001` (hard floor) | no files scanned; no supported files mapped; map coverage `partial`; analysis truncated | insufficient-evidence |
| `P-OWN-001` | owner unknown and exposure ≥ High (or `require.owner`) | review (insufficient-evidence when required) |
| `P-CUS-001` | `require.custodian` and no custodian named in the operator policy (a `passport.custodians` declaration is recorded but does not count) | pass unless required; then block |
| `P-DAT-001` | `exports` of sensitive data to an external destination | review; **block** (hard floor) when provider-verified |
| `P-DAT-002` | write/delete/admin, or unknown capability, over a production, high/critical, or restricted asset | review; configurable to block for provider-verified authority, and for static leads only with `static_leads: block` |
| `P-DAT-003` | `require.classification` and a reachable database, storage, or queue has unknown sensitivity | pass unless required; then insufficient-evidence |
| `P-SEC-001` | scanner leads that expose credentials or data to the public: `JH132`, `JH133`, `JH134` (major or above), critical `JH101`/`JH401`/`JH415` | review |
| `P-AGT-001` | agent-guardrail leads at major or above: any `agent`-category rule (`JH701`-`JH711`: approvals, MCP servers, sandboxes, dev containers), agent-branch CI with secrets (`JH432`), or hidden Unicode in an agent file | review |
| `P-AI-001` | a confidential or restricted data store and an external AI model service are reachable from the same principal (co-reachability, not a data flow) | review |
| `P-OPS-001` | `require.tests` / `require.ci` and the area is not **observed** (a declaration is not enough) | pass unless required; then review |
| `P-EVD-001` | `require.sbom`, `require.sbom_minimum` (no SBOM meets the NTIA minimum elements), `require.attestation`, or `require.verified_attestation` unmet; or `--verify` did not end with every check `tool-verified` | insufficient-evidence |
| `P-JNK-001` | Jank Score policy `fail`, or any blocker-severity lead | review |
| `P-EXP-001` | exposure above `max_exposure` (Unknown → insufficient-evidence) | review |
| `P-CHG-001` | `require.change_control` and code can reach the default branch without an independent human review: no pull-request rule with an approval, or a GitHub App or deploy key that can bypass the rules (weaker gaps such as no last-push approval or no required checks: review) | pass unless required; then review (unknown → insufficient-evidence) |
| `P-SUP-001` | `allowed_registries` is set and a declared or lockfile-recorded package source is outside it (a manager with no committed registry config: insufficient-evidence when `require.registry_pinning`) | pass unless registries are listed; then review |
| `P-CAP-001` | `--base REF` and the change asks for new, expanded or unresolved access (see `references/capability-delta.md`); a matching operator record can cover concrete requests (`references/capability-approval.md`) | pass without `--base`; otherwise review (hard floor) |
| `P-RUN-001` | `--detonation PATH` was made on this exact tree and its sandbox run raised an ALERT: a canary credential read, passed on or sent, or a persistence attempt (`references/detonate.md`) | pass when not supplied, made on another tree, or clean; otherwise review (hard floor) |

Under the default `static_leads: review`, static leads never block on their
own: an observed `DELETE` or a declared connection asks for grant
verification (`review`). `static_leads: block` (set by the citizen profile)
reverses the burden of proof on purpose: unverified authority over
production, critical, or restricted data, and a declared or observed
sensitive export, block until an operator inventory verifies the grants or
the flow is removed. Co-reachability of a sensitive source and an external
destination raises exposure but is not a transfer and does not trigger
`P-DAT-001`. The one exception is an external AI model service: `P-AI-001`
asks for a review when sensitive data is reachable alongside one, because
what a provider retains, trains on, or where it processes data is a
governance decision someone has to record. It still claims no data flow.

## Policy files and precedence

```json
{
  "schema_version": "jankhunt.policy.v1",
  "require": {"owner": true, "sbom": true, "sbom_minimum": false, "attestation": false, "verified_attestation": false},
  "actions": {"P-JNK-001": "block", "P-DAT-002": "block", "P-OWN-001": "insufficient-evidence"},
  "max_exposure": "High",
  "profile": "citizen",
  "custodians": ["@example-org/platform"],
  "static_leads": "block"
}
```

`require` also takes `custodian`, `tests`, `ci`, `classification`,
`change_control`, and `registry_pinning`. `allowed_registries` (operator
policy only; a repository cannot widen it) lists registry URL prefixes or
host names packages may come from, such as
`"https://artifacts.example.internal/api/npm/"`.
`profile` is `standard` or `citizen`; `custodians` (operator policy only)
names the engineers who answer for the software; `static_leads` is `review`
or `block`; `profile_exceptions` (operator policy only, citizen profile
only) relaxes the profile on purpose, one warned entry at a time: rule
actions, `require.<key>: false`, `max_exposure`, or `static_leads`.

Actions are `off`, `review`, `insufficient-evidence`, or `block`. Precedence:

1. **Defaults** (above).
2. **Operator policy**: `--policy PATH` where `PATH` is outside the scanned
   repository. It may tighten or relax defaults, but never the hard floors.
   It is labeled `operator-supplied`: a local file path is operator input,
   not proof of organizational authority.
3. **Repository policy**: `passport.policy` in `.jankhunt42.json`/`.toml`,
   or a `--policy` file inside the repository. **Tighten-only**: it may raise
   actions, add requirements, lower `max_exposure`, and opt into the citizen
   profile (`passport.profile: "citizen"`); any attempt to relax, or to
   leave the citizen profile, is ignored with a warning.

`--profile citizen` on the command line, or `"profile": "citizen"` in the
operator policy, applies the profile after the operator's ordinary
overrides, tighten-only, so a baseline policy cannot weaken it (each
override is warned). Only `profile_exceptions` relax the profile, and
repository tightening comes last. Under the citizen profile, governance
leads also come from a scan that ignores repository scan config and inline
pragmas, so the repository can add leads but not remove them.

The effective policy and its SHA-256 (`policy.hash`) are embedded in every
passport, together with each source.

## Change control (`--branch-rules`)

`change_control` answers one question: can code, an AI agent's included,
reach the default branch without an independent human review? Evidence,
strongest first:

- `--branch-rules FILE`: the repository's rulesets or classic branch
  protection as the GitHub REST API returns them. Accepted shapes: one
  ruleset (`GET /repos/{owner}/{repo}/rulesets/{id}`), a list of rulesets,
  the active rules for a branch (`GET .../rules/branches/{branch}`, which
  omits bypass actors, so that check stays `unknown`), classic protection
  (`GET .../branches/{branch}/protection`), or a wrapper
  `{"default_branch", "rulesets", "branch_protection", "branch_rules"}`.
  Outside the repository it is **provider-verified**; inside it is only a
  declaration, with a warning.
- Terraform `github_repository_ruleset` and `github_branch_protection` in
  the repository: **declared** intent, not proof of what is applied.
- Nothing: **unknown**, never "absent".

Rulesets count only when `enforcement` is `active` and their conditions
include the default branch (`~DEFAULT_BRANCH`, `~ALL`, or its name;
`--default-branch` overrides the branch git reports). The checks:

| Check | Met when |
|---|---|
| `pull_request_review` | a pull request with at least one approval is required |
| `code_owner_review` | code-owner review is required |
| `last_push_approval` | the last push must be approved by someone other than the pusher (otherwise an agent can push after approval) |
| `status_checks` | at least one status check is required |
| `deletion_protected`, `force_push_protected` | the branch cannot be deleted or force-pushed |
| `no_app_bypass` | no bypass actor of type `Integration` (a GitHub App) or `DeployKey` |
| `codeowners_coverage` | `CODEOWNERS` has a catch-all pattern with an owner |

`P-CHG-001` gives its full action for a missing review or an app bypass,
`review` for the weaker gaps, and `insufficient-evidence` when the evidence
is unknown. Under the citizen profile a repository declaration alone does
not satisfy it: the export must come from outside the repository.

## Package sources and allowed registries

Committed configuration declares where packages come from: `.npmrc`,
`.yarnrc(.yml)`, `bunfig.toml`, `pip.conf`/`pip.ini`, `--index-url` and
`--extra-index-url` in requirements files, `pyproject.toml` (Poetry, uv,
PDM sources), `Pipfile`, Maven `pom.xml` and `settings.xml` mirrors, Gradle
`repositories` (`mavenCentral()`, `google()`, `maven { url ... }`; not
`publishing`), `nuget.config`, and `.cargo/config.toml`. Lockfiles
(`package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `uv.lock`,
`poetry.lock`, `Pipfile.lock`) record where packages were fetched from and
are **observed**. A manager in use with no committed configuration is
**unknown**: the developer's machine or the CI runner decides, and the
public registry is only its default.

## The citizen pull-request gate

[`templates/citizen-gate.yml`](../templates/citizen-gate.yml) is a
required-workflow recipe: a `pull_request` job with `permissions: contents:
read`, no secrets, and SHA-pinned checkouts. It runs

```sh
jankhunt42 passport app --profile citizen --policy gate/policy/citizen.json \
  --branch-rules "gate/rules/$REPO.json" --fail-on insufficient-evidence --md
```

with the operator policy and the exported rulesets checked out from a
protected repository the citizen cannot change, so both are operator input.
It fails on `insufficient-evidence` as well as `block`, so a change that
cannot be judged (unknown change control, unclassified data, a package
manager with no registry config) does not merge. `scripts/selftest.sh` runs
the template's own command against a synthetic compliant fixture (pass), the
same fixture pointed at a public registry (blocked by `P-SUP-001`), and the
same fixture without its ruleset export (insufficient evidence).

## Repository declarations

```json
{
  "passport": {
    "owners": ["@example-org/payments-team"],
    "environment": "production",
    "assets": [
      {"match": "ledger-db", "sensitivity": "restricted", "criticality": "critical"},
      {"match": "reports", "sensitivity": "confidential"}
    ],
    "operations": {"runbook": true},
    "custodians": ["@example-org/platform"],
    "profile": "citizen",
    "bindings": [{"workload": "Deployment payments-prod/payments-api"}],
    "policy": {"require": {"owner": true}}
  }
}
```

Declarations are context with `declared` provenance. They classify assets and
name owners and custodians; they cannot verify anything, and they cannot
override an operator inventory or relax policy. Code-origin statements
(human, AI-assisted, citizen-developed) are not read: the citizen profile is
a governance choice made by the operator or the repository, not an
inference about authorship, and identical evidence under the same policy
produces an identical passport.

## Acceptance records (`--acceptance`)

Acceptance is a separate act by a person. jankhunt42 records it but never creates or infers it:

```json
{
  "accepted_by": "release-manager",
  "accepted_at": "2026-10-23T10:00:00Z",
  "expires": "2026-11-23T00:00:00Z",
  "subject_revision": "<git commit the passport reports>",
  "policy_hash": "<assessment.decision.policy.hash>",
  "decision_accepted": "review",
  "artifact_digest": "sha256:…",
  "environment": "production"
}
```

The record is honoured only if it lives **outside** the scanned repository. A record inside the repository is `rejected`.

- **Accepted:** when the revision, policy hash and decision match, the optional digest and environment match, the working tree is clean, and the record has not expired, `lifecycle.state` becomes `accepted` with `acceptance.state: declared-by-operator`. That is an unsigned operator statement, not a verification.
- **Invalidated:** any mismatch gives `invalidated`, with named reasons: `revision-changed`, `policy-changed`, `decision-changed`, `digest-changed`, `environment-changed`, `working-tree-dirty`, `expired`.
- **Rejected:** a `block` or `insufficient-evidence` decision can never be accepted. Under the citizen profile, a record whose `accepted_by` is not a custodian named in the operator policy is rejected too.

The decision itself never changes because of acceptance. `--redact` hides the acceptor, and replaces the details that rule messages quote (hostnames, file paths, custodian names) with `(details redacted)`.

## Comparing passports (`--compare`)

`--compare OLD.json` compares a stored passport with the current one, or with `--against NEW.json` for two stored documents and no scan. The `jankhunt.passport-delta.v1` output covers:
- the decision and its triggered rules (added and removed);
- exposure and Jank Score;
- evidence-area changes, owners, artifact digests, data sources (added, removed, reclassified);
- policy and graph changes, and the lifecycle;
- a `regressions` list (worse decision, higher exposure, a downgraded evidence area, a lost owner) and a `regressed` flag.

`integrity` reports whether each document's `scan_id` still matches its content. It catches edits made after generation; it is not a signature. Comparing documents of the wrong schema is a usage error (exit 2).

## Assurance levels and what is deferred

The passport covers repository-static evidence (L1) and parsed build/release
evidence (L2, exporter-reported, or `tool-verified` when `--verify` ran a
native verifier; see `references/supply-chain.md`). Verification results sit
under `provenance.verification` without timestamps (they ran at
`generated_at`), and `--redact` keeps only their outcomes. Independently collected operational
evidence (L3) enters only through an operator inventory. Not implemented:
signature verification of passports or acceptance records, platform-control
inheritance, and continuous monitoring.
