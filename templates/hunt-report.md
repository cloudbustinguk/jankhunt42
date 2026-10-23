# Deep hunt report — <target>

| Field | Value |
|---|---|
| **Objective** | <what decision this hunt informs> |
| **Focus** | all / security / reliability / performance / data / ci |
| **Scope** | <repo, paths, services> |
| **Exclusions** | <paths, environments, techniques> |
| **Baseline** | `<branch>` @ `<commit>` · <files> files · <LOC> LOC |
| **Panel** | <n> panelists · <n> rounds · <wall-clock> |
| **Date** | <UTC> |
| **Status** | In progress / Consensus reached / Verification pending / Closed |

## 1. Executive summary

- **Top confirmed findings:** <one line each>.
- **Decision:** fix now / schedule / accept risk / investigate more.
- **Residual risk:** <what remains after the planned work>.
- **Confidence in the conclusion:** high / medium / low, with the reason.

Do not present unverified leads as findings.

## 2. Baseline and method

- **Jank baseline:** <score>/100 · <grade> · policy <pass/warn/fail>.
- **Dimension scores:** security <grade>/<score>, reliability <grade>/<score>,
  maintainability <grade>/<score>, tests <grade>/<score>.
- **New code:** since `<ref>`, <n> changed lines, <n> findings, <score>/100.
- **Panel roster:** <roles and lenses>.
- **Independence:** round 1 was parallel and blind; round 2 was anonymized
  cross-examination; round 3 was verifier-led consensus.
- **Budget used:** <panelists, rounds, wall clock>.
- **Artifacts:** `hunt.json`, `panel-*.json`, `merge.json` (paths, redacted).

## 3. Consensus board

| ID | Status | Severity | Confidence | Votes | Location | Finding |
|---|---|---|---:|---:|---|---|
| M01 | confirmed | critical | high | 4/6 | `path:line` | <title> |
| M02 | supported | major | medium | 3/6 | `path:line` | <title> |
| M03 | contested | major | low | 2/6 | `path:line` | <title> |
| M04 | unverified | minor | low | 1/6 | `path:line` | <lead> |
| M05 | rejected | — | — | 2/6 | `path:line` | <false positive> |

Status definitions:

- **confirmed:** reproduced or directly observed.
- **supported:** strong static evidence and causal chain, not reproduced.
- **contested:** credible disagreement; both sides recorded.
- **unverified:** lead or hypothesis; not a finding.
- **rejected:** falsified by a guard, path, control, or failed repro.

## 4. Confirmed and supported findings

Repeat this block for each non-rejected finding, worst first.

### M01 — <title>

- **Status:** confirmed / supported
- **Severity:** critical
- **Confidence:** high
- **Location:** `path:line`
- **Rule:** `JHxxx` or `NEW`
- **Panelists:** <roles>

**Causal chain**

```text
trigger -> mechanism -> impact
```

**Evidence**

- <command, output, test, trace, or exact code with file:line>.
- <independent confirmation or second observation>.

**Reproduction**

```sh
# exact command; note if it is destructive or requires authorization
```

If the finding was confirmed by direct observation instead, attach the exact
log line, stack trace, or runtime output plus its timestamp and environment.

**Impact**

<Who can trigger it, what they gain, what data or availability is affected.>

**Fix direction**

<Smallest correct change. Sibling sites to check. Compatibility and rollback.>

**Verification plan**

<Test that fails before and passes after; command; expected result.>

**Dissent**

<Panelist, objection, and why it did or did not change the verdict.>

## 5. Contested findings

For each contested item:

- **Claim:** <strongest version>.
- **Counterclaim:** <strongest objection>.
- **Discriminating experiment:** <cheapest test that settles it>.
- **Owner / due:** <name, date>.
- **Interim decision:** <block, mitigate, accept, or wait>.

Do not hide a contested item in an appendix. It is a decision the reader must see.

## 6. Unverified leads and next experiments

| Lead | Why it matters | Cheapest experiment | Owner |
|---|---|---|---|
| <id> | <one line> | <command or observation> | <name> |

These are **not** findings. Keep them out of the confirmed count.

## 7. Rejected / false positives

| Lead | Why it was rejected | Evidence |
|---|---|---|
| <id> | <guard, unreachable path, test, framework default> | `path:line` or command |

A rejected lead is a successful result. It prevents repeat work.

## 8. Scenario coverage

| Scenario | Tested? | Result / notes |
|---|---|---|
| Hostile input | yes/no/partial | <what was tried> |
| Trust-boundary crossing | | |
| Failure injection | | |
| Scale | | |
| Concurrency | | |
| Restart / upgrade | | |
| Operator error | | |
| Malicious insider | | |
| Supply chain | | |
| Observability gap | | |
| Data lifecycle | | |
| Time | | |
| Resource limits | | |
| Abuse / DoS | | |
| Prompt injection | | |
| False positive | | |
| False negative | | |
| Fix regression | | |
| Secrets / artifacts | | |
| Recovery / runbook | | |

## 9. Residual risk and unknowns

- **Residual risk:** <what remains after the planned fixes>.
- **Unknowns:** <what the panel could not determine>.
- **Assumptions:** <what the conclusion depends on>.
- **Out-of-scope observations:** <adjacent issues, not investigated>.
- **Monitoring:** <what would detect the risk if it materializes>.

## 10. Recommended next actions

| Priority | Action | Owner | Verification |
|---|---|---|---|
| P0 | <fix / mitigate> | <name> | <test or command> |
| P1 | <harden / add test> | <name> | <test or command> |
| P2 | <investigate> | <name> | <experiment> |

## 11. Appendix

- Panel JSON and merge output (redacted).
- Commands run and exit codes.
- Baseline scorecard.
- Raw evidence (redacted).
- Tool versions.

---

**Privacy check:** no secrets, tokens, personal data, customer names, private
prompts, or internal URLs that should not be published. Redactions are marked.
