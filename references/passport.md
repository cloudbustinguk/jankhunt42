# Software passport, exposure, and release policy (`jankhunt42 passport`)

`passport` answers **can we responsibly ship it?** It links the evidence
jankhunt42 already produces into one versioned document and applies a small,
explainable policy. It is a **local assessment**:

- not a certificate, not a compliance attestation, and never an approval;
- lifecycle is `draft` (assessment incomplete) or `assessed`; `accepted`
  would require separately supplied, trusted acceptance evidence, which this
  tool does not create or infer (`acceptance.state` is `not-supplied`);
- attestation verification states are what the **exporter** recorded;
  jankhunt42 does not verify signatures or signer identity;
- evidence that was not found is `not-observed` (unknown), never "absent".

## Commands

```sh
jankhunt42 passport .                          # TTY: software passport; piped: Markdown
jankhunt42 passport . --json                   # jankhunt.passport.v1
jankhunt42 passport . --html > passport.html   # offline, printable
jankhunt42 passport . --redact --json          # shareable: no hosts, owners, or snippets
jankhunt42 passport . --policy ../policy.json  # operator policy (outside the repository)
jankhunt42 passport . --fail-on block          # enforce: exit 1 on block
jankhunt42 passport . --inventory ../inventory.json
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
and a strong area never offsets a weak one.

| Rule | Triggers | Default outcome |
|---|---|---|
| `P-COV-001` (hard floor) | no files scanned; no supported files mapped; map coverage `partial`; analysis truncated | insufficient-evidence |
| `P-OWN-001` | owner unknown and exposure ≥ High (or `require.owner`) | review (insufficient-evidence when required) |
| `P-DAT-001` | `exports` of sensitive data to an external destination | review; **block** (hard floor) when provider-verified |
| `P-DAT-002` | write/delete/admin, or unknown capability, over a production, high/critical, or restricted asset | review; configurable to block **only** for provider-verified authority |
| `P-EVD-001` | `require.sbom`, `require.attestation`, or `require.verified_attestation` unmet | insufficient-evidence |
| `P-JNK-001` | Jank Score policy `fail`, or any blocker-severity lead | review |
| `P-EXP-001` | exposure above `max_exposure` (Unknown → insufficient-evidence) | review |

Static leads never block on their own: an observed `DELETE` or a declared
connection asks for grant verification (`review`), whatever the policy says.
Co-reachability of a sensitive source and an external destination raises
exposure but is not a transfer and does not trigger `P-DAT-001`.

## Policy files and precedence

```json
{
  "schema_version": "jankhunt.policy.v1",
  "require": {"owner": true, "sbom": true, "attestation": false, "verified_attestation": false},
  "actions": {"P-JNK-001": "block", "P-DAT-002": "block", "P-OWN-001": "insufficient-evidence"},
  "max_exposure": "High"
}
```

Actions are `off`, `review`, `insufficient-evidence`, or `block`. Precedence:

1. **Defaults** (above).
2. **Operator policy**: `--policy PATH` where `PATH` is outside the scanned
   repository. It may tighten or relax defaults, but never the hard floors.
   It is labeled `operator-supplied`: a local file path is operator input,
   not proof of organizational authority.
3. **Repository policy**: `passport.policy` in `.jankhunt42.json`/`.toml`,
   or a `--policy` file inside the repository. **Tighten-only**: it may raise
   actions, add requirements, and lower `max_exposure`; any attempt to relax
   is ignored with a warning.

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
    "policy": {"require": {"owner": true}}
  }
}
```

Declarations are context with `declared` provenance. They classify assets and
name owners; they cannot verify anything, and they cannot override an
operator inventory or relax policy. Code-origin statements (human,
AI-assisted, citizen-developed) are not read and cannot change any
assessment: identical evidence produces an identical passport.

## Assurance levels and what is deferred

The passport covers repository-static evidence (L1) and parsed build/release
evidence (L2, exporter-reported). Independently collected operational
evidence (L3) enters only through an operator inventory. Not implemented in
this version: acceptance records, `passport verify`/`compare`, signature
verification, control inheritance, and drift monitoring.
