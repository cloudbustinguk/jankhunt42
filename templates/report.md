# <Incident / defect title>

| Field | Value |
|---|---|
| **Status** | Investigating / Mitigated / Fixed / Closed |
| **Severity** | Blocker / Critical / Major / Minor / Info |
| **Confidence** | High / Medium / Low |
| **Owner** | <name or team> |
| **First seen** | <UTC timestamp> |
| **Last updated** | <UTC timestamp> |
| **Affected versions** | <commit / image / release> |
| **Blast radius** | <users / services / data> |

## 1. Summary

Two or three sentences a busy reader can act on:

- What happened?
- Who or what is affected?
- What is the current status and next action?

## 2. Impact

- **Functional:** what can users no longer do?
- **Data:** what was read, written, lost, or exposed?
- **Security:** confidentiality, integrity, availability, tenancy.
- **Business:** SLA, revenue, compliance, support load.
- **Scope:** one tenant / one region / all users.

State what is **not** affected when that is useful.

## 3. Timeline (UTC)

| Time | Event |
|---|---|
| 00:00 | First abnormal signal |
| 00:00 | Detection / alert |
| 00:00 | Investigation started |
| 00:00 | Mitigation applied |
| 00:00 | Recovery confirmed |

Separate detection, start, peak, mitigation, and recovery. Do not compress them
into one timestamp.

## 4. Reproduction

```sh
# exact command, cwd, environment, input
```

- **Frequency:** always / intermittent (x of y) / one host / one user.
- **Last known good:** <commit / image / config>.
- **Preconditions:** <data, permissions, feature flags, network>.
- **Minimal input:** <file or payload, redacted>.

## 5. Root cause

Write the causal chain, not a narrative:

```text
trigger -> mechanism -> symptom
```

For each arrow, give the evidence:

| Arrow | Evidence | Confidence |
|---|---|---|
| trigger -> mechanism | <log / trace / test / code> | high/medium/low |
| mechanism -> symptom | <log / trace / test / code> | high/medium/low |

**Contributing factors:** why was this not caught? (test gap, review gap, missing
metric, unsafe default, deploy process, documentation.)

**Ruled out:** list the hypotheses that were falsified and why. This is valuable.

## 6. Evidence

- **Logs:** <path / query / time range> (redacted).
- **Metrics / traces:** <dashboard / trace ID>.
- **Code:** `path:line` and a short excerpt.
- **Diff:** <commit range or PR>.
- **Environment:** <versions, image digest, config hash>.
- **Commands:** exact commands and exit codes.

Do not paste secrets, tokens, personal data, or customer identifiers. Redact them
and note that you did.

## 7. Fix

- **Change:** <minimal correct change>.
- **Why this fixes the cause:** <one paragraph>.
- **Sibling sites checked:** <paths>.
- **Rollback:** <how, and what happens to in-flight work>.
- **Compatibility:** <old clients, mixed versions, schema>.

## 8. Verification

| Check | Command | Before | After |
|---|---|---|---|
| Original repro | `<cmd>` | fail | pass |
| Regression test | `<cmd>` | fail | pass |
| Targeted suite | `<cmd>` | — | pass |
| Full suite | `<cmd>` | — | pass |
| Build / typecheck / lint | `<cmd>` | — | pass |
| Performance / resources | `<cmd>` | baseline | measured |

Attach the raw output or a link. One green run is not enough for an intermittent
bug; report the measured frequency.

## 9. Prevention

- Regression test added: <path>.
- Monitoring/alert added: <metric / threshold>.
- Guardrail or validation added: <where>.
- Documentation/runbook updated: <path>.
- Follow-up work (with owners): <items>.

Do not list "be more careful" as prevention.

## 10. Open questions and residual risk

- <question> — owner, next experiment, due date.
- <residual risk> — accepted by, rationale, review date.

## 11. Appendix

- Raw logs / traces (redacted).
- Related issues, PRs, advisories.
- Environment snapshot.
- Scorecard (if `jankhunt` was used): `jankhunt score . --json`.

---

**Privacy check:** no secrets, tokens, personal data, customer names, private
prompts, or internal URLs that should not be published. Redactions are marked.
