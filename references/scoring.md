# Jank Score 2.0

The Jank Score is a **prioritization device**, not a compliance certificate. It
answers one question: *where should a human look first?* It is deliberately
transparent, cheap to compute, and honest about what it cannot see.

Version: `2.0` (the formula is versioned so old reports remain interpretable).

## 1. What we borrowed, and what we rejected

### From SonarQube

**Borrowed**

- **Separate dimensions.** Security, reliability, maintainability, and test
  confidence are rated independently. A clean style score must never hide a
  security problem.
- **A-E grades.** People read letters faster than decimals.
- **Density, not raw counts.** A large codebase is allowed to have more absolute
  findings; the question is how concentrated the risk is.
- **Severity floors.** One blocker makes a dimension severe even in a huge
  codebase. This mirrors SonarQube's rating-by-worst-issue philosophy.
- **New-code focus ("Clean as You Code").** Legacy debt should not block a small,
  clean change. The new-code view scores only findings on changed lines.
- **Quality-gate thinking.** A score is useful only if it feeds a decision. We
  expose an advisory policy and keep `--fail-on` as the explicit CI gate.

**Rejected**

- **"Technical debt in days."** Converting a regex hit into a precise repair time
  is fake precision. We use risk points instead.
- **One opaque number.** The headline exists, but the dimension table is the real
  output.
- **Issue-count league tables.** Counting findings rewards noisy rules. We cap
  per-rule contribution and weight by confidence and exposure.
- **A single overall grade that averages everything.** A security catastrophe must
  not be diluted by a thousand pristine style lines.

### From Veracode

**Borrowed**

- **Severity × confidence.** A critical claim with low confidence is not the same
  as a reproduced critical defect.
- **Exploitability/impact thinking.** We approximate exposure with a coarse,
  documented factor instead of pretending to have data-flow reachability.
- **Policy gates.** High-severity, high-confidence findings should change the
  decision, not just the dashboard.
- **False-positive discipline.** A rejected finding is a result. Suppressions and
  confidence are first-class.

**Rejected**

- **Proprietary CWE/CVSS machinery as the only lens.** Useful, but not sufficient
  for reliability, maintainability, tests, or CI configuration.
- **Compliance theater.** A low score is not a certification; a high score is not
  a breach.

## 2. The model

### 2.1 Risk points per finding

```text
points = severity_weight × confidence_factor × exposure_factor
```

| Severity | Weight | Meaning |
|---|---:|---|
| blocker | 40 | Active outage, data loss, or an exploitable secret in the working tree |
| critical | 20 | Direct path to serious impact |
| major | 8 | Serious defect or dangerous default |
| minor | 3 | Localized defect or maintainability drag |
| info | 1 | Context, style, or a lead |

| Confidence | Factor | Meaning |
|---|---:|---|
| high | 1.00 | Reproduced, directly observed, or mechanically certain |
| medium | 0.65 | Strong static evidence with a plausible path |
| low | 0.30 | Heuristic or pattern match needing confirmation |

| Dimension / category | Exposure | Rationale |
|---|---:|---|
| security, reliability, supply-chain | 1.00 | Runtime impact on users or data |
| ci | 0.90 | Can reach credentials and production |
| maintainability | 0.55 | Slows change; rarely causes an incident by itself |
| tests | 0.45 | Weakens the safety net; indirect impact |
| docs | 0.25 | Can mislead an operator, but usually not directly executable |

Exposure is a **coarse proxy**, not reachability analysis. A security finding in
dead code still counts; we do not have data-flow proof. The report says so.

### 2.2 Per-rule saturation

A single noisy rule must not own the score. For each rule:

- the 10 highest-point findings count fully;
- every additional finding counts at 10%.

```text
rule_points = Σ(points of top 10) + 0.10 × Σ(points of the rest)
```

This keeps a hundred `TODO`s from outranking one critical injection, while still
acknowledging volume.

### 2.3 Dimension score

```text
raw_dimension = Σ rule_points for findings in the dimension
density       = raw_dimension / max(0.25, LOC / 1000)
density_score = 100 × (1 − e^(−density / K_dimension))
floor         = max(severity_floor × confidence × exposure)
score         = max(density_score, floor)
```

`max(0.25, LOC/1000)` is a 250-line floor. It prevents a tiny file from producing
an absurd density score and keeps the formula stable for small repositories.

| Dimension | K | Why |
|---|---:|---|
| Security | 25 | Most sensitive; a little risk is a lot |
| Reliability | 35 | Serious, but tolerates more volume than security |
| Maintainability | 45 | Debt is real but rarely urgent |
| Test confidence | 30 | Weak tests are dangerous, but indirect |

Severity floors (before confidence and exposure):

| Worst severity | Floor |
|---|---:|
| blocker | 80 |
| critical | 55 |
| major | 30 |
| minor | 12 |
| info | 2 |

A critical high-confidence security finding therefore floors that dimension at
55 (D), even in a 100,000-line repository. That is intentional and mirrors
rating-by-worst-issue.

### 2.4 Headline score

```text
weighted = 0.35×security + 0.30×reliability + 0.20×maintainability + 0.15×tests
worst    = max(dimension scores)
score    = round(0.70×worst + 0.30×weighted)
```

The 70% worst-dimension anchor means a security catastrophe cannot be averaged
away. The 30% weighted term means breadth still matters: many medium problems
across dimensions should not look pristine just because none is catastrophic.

### 2.5 Grades

| Grade | Score | Reading |
|---|---:|---|
| A | 0-5 | Clean enough to stop looking at the scanner |
| B | 6-15 | Minor drag; fix on touch |
| C | 16-35 | Worth a planned pass |
| D | 36-60 | Serious; prioritize before the next release |
| E | 61-100 | Stop and fix; the risk is concentrated |

The flavor labels (`pristine`, `mild jank`, `spicy`, `grimy`, `biohazard`,
`call the priest`) are communication sugar. The grade is the stable part.

### 2.6 Advisory policy

The policy is separate from CI:

| Policy | Trigger |
|---|---|
| **fail** | Any dimension ≥ 61; overall ≥ 61; or a high/medium-confidence blocker, or a high-confidence critical, in security/reliability |
| **warn** | Overall ≥ 16; any dimension ≥ 16; or a medium-confidence critical or high-confidence major in security/reliability |
| **pass** | Everything else |

`jankhunt42 score --fail-policy` exits `1` on `fail`. This is an **advisory** gate.
Use `jankhunt42 scan --fail-on SEV` when you need a simple, explainable CI threshold.

### 2.7 New-code view ("Clean as You Code")

`--since REF` asks git for the lines changed since `REF`:

```sh
jankhunt42 scan . --since origin/main
jankhunt42 score . --since HEAD
```

Only findings whose line (or multi-line range) intersects the changed lines are
scored. The denominator is the number of changed lines, with the same 250-line
floor. The whole-tree score is still reported; the new-code score is additional.

Use the new-code view for pull requests. Use the whole-tree score for a periodic
audit. Do not use a legacy whole-tree score to block a clean one-line fix.

### 2.8 CVE findings

`scan --cve` adds OSV advisories as `JH901` findings. They use the mapped severity,
high confidence, and full exposure because a pinned vulnerable dependency is
reachable by definition (subject to the actual resolved tree). If you need CVSS
weighting, add the CVSS score to the finding's `extra` and extend
`jh_score.finding_points`; do not silently pretend the mapped severity is CVSS.

## 3. Worked examples

Assumptions: 10,000 LOC, one finding unless stated.

| Case | Dimension score | Headline | Grade | Policy |
|---|---:|---:|---|---|
| Clean | all 0 | 0 | A | pass |
| 1 critical, high confidence, security | 55 | 44 | D | fail |
| 1 blocker, high confidence, security | 80 | 64 | E | fail |
| 1 critical, low confidence, security | 16 | 13 | B | warn |
| 1 major, high confidence, security | 30 | 24 | C | warn |
| 1 major, high confidence, reliability | 30 | 24 | C | warn |
| 100 minor, high confidence, maintainability | 31 | 24 | C | warn |
| 5 critical, high confidence, security | 55 (floor dominates) | 44 | D | fail |

The last row is deliberate: five criticals in one dimension are still capped by
the dimension scale and the per-rule saturation, but the grade stays D because the
floor is not the only signal. If you need "five criticals" to be worse than "one
critical", use the count and the policy, not the score. A single number cannot
carry every distinction without becoming astrology.

## 4. Reading a scorecard

```text
JANK   ███████████░░░░░  44/100  D · grimy  policy fail
Security          ███████████░░░  55  D  1 finding
Reliability       ░░░░░░░░░░░░░░   0  A  0 findings
Maintainability   ██░░░░░░░░░░░░   4  A  7 findings
Test confidence   ░░░░░░░░░░░░░░   0  A  0 findings
```

Read it in this order:

1. **Policy:** is there a stop-the-line signal?
2. **Worst dimension:** where is the concentrated risk?
3. **Worst severity and confidence:** is the claim credible?
4. **Top rules:** which pattern is driving it?
5. **New code:** did this change make it worse?
6. **Findings:** confirm them in context. The score is not a verdict.

## 5. Calibration and drift

- Recompute on the same revision and tool version when comparing.
- Treat a change of less than one grade band as noise unless the finding set
  changed in a way you can explain.
- Do not compare scores across repositories with different rule sets, languages,
  or `--min-severity` settings.
- The score is sensitive to `--min-severity`, `--category`, and `--rule`. Record
  the scan options with the score. The default is `minor`; pass
  `--min-severity info` only when style/context findings are part of the review.
- If a rule is noisy, fix the rule or suppress the confirmed false positive; do not
  lower the whole score's sensitivity.

## 6. What the score is not

- Not a vulnerability count, CVSS replacement, or exploitability proof.
- Not a test-coverage percentage. It measures findings, not executed lines.
- Not a measure of developer productivity. Never use it to rank people.
- Not a substitute for a compiler, tests, linters, sanitizers, Semgrep, Trivy, or
  a human review.
- Not a certification. A passing score means "the built-in rules found little",
  not "this system is secure".

## 7. Implementation notes

- Module: `scripts/jh_score.py`
- CLI: `jankhunt42 score`, `jankhunt42 scan --json` (`summary.jank`), `--since REF`
- Formula version: `SCORE_VERSION = "2.0"`
- The score is deterministic: same findings + same LOC + same version = same
  result.
- The JSON includes the dimension breakdown, weights, grade bands, policy, and
  formula so a reviewer can audit the arithmetic.
