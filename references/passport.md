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
| `provenance` | SBOMs and attestations via `supply-chain` parsers | observed / not-observed |
| `data` | data sources from the map, with classifications and who classified them | assessed / not assessed |
| `operations` | CI config, tests, observability SDKs, health probes, runbooks, `SECURITY.md` | observed / inferred / declared / not-observed |
| `subject` | git revision, dirty flag, artifact digests from attestation subjects | digests labeled exporter-reported |
| `remediation` | derived from triggered rules and missing evidence | top steps |
| `unknowns`, `limitations` | map unknowns and fixed statements | |

Evidence coverage is reported as "N of 9 areas observed, declared, or
inferred". Observability from an SDK reference is `inferred` (it suggests
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
| `P-AGT-001` | agent-guardrail leads: any `agent`-category rule (`JH701`-`JH708`) at major or above, or hidden Unicode in an agent file | review |
| `P-OPS-001` | `require.tests` / `require.ci` and the area is not **observed** (a declaration is not enough) | pass unless required; then review |
| `P-EVD-001` | `require.sbom`, `require.attestation`, or `require.verified_attestation` unmet; or `--verify` did not end with every check `tool-verified` | insufficient-evidence |
| `P-JNK-001` | Jank Score policy `fail`, or any blocker-severity lead | review |
| `P-EXP-001` | exposure above `max_exposure` (Unknown → insufficient-evidence) | review |

Under the default `static_leads: review`, static leads never block on their
own: an observed `DELETE` or a declared connection asks for grant
verification (`review`). `static_leads: block` (set by the citizen profile)
reverses the burden of proof on purpose: unverified authority over
production, critical, or restricted data, and a declared or observed
sensitive export, block until an operator inventory verifies the grants or
the flow is removed. Co-reachability of a sensitive source and an external
destination raises exposure but is not a transfer and does not trigger
`P-DAT-001`.

## Policy files and precedence

```json
{
  "schema_version": "jankhunt.policy.v1",
  "require": {"owner": true, "sbom": true, "attestation": false, "verified_attestation": false},
  "actions": {"P-JNK-001": "block", "P-DAT-002": "block", "P-OWN-001": "insufficient-evidence"},
  "max_exposure": "High",
  "profile": "citizen",
  "custodians": ["@example-org/platform"],
  "static_leads": "block"
}
```

`require` also takes `custodian`, `tests`, `ci`, and `classification`.
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
