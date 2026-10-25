# Precision: how often a finding is worth a look

A scanner whose major findings are mostly noise teaches people to stop reading
majors. This page records how jankhunt42's precision is measured and what the
measurements say. It is not a guarantee about your repository.

## Method

Findings come from scans of public repositories, most of them written with AI
assistants or by people who are not professional developers. Repository names
are not published.

Each finding is labelled from the flagged line and the code around it:

| label | meaning |
|---|---|
| `TP` | a real lead worth a human look |
| `FP` | the rule's claim is false here |
| `NOISE` | the claim is true but not actionable here: test data, a deliberately vulnerable example, a protocol that requires it, best-effort cleanup |
| `UNSURE` | the context is not enough to decide |

- **Precision** is `TP / (TP + FP)`, with a 95% Wilson interval.
- **Actionable** is `TP / all`, NOISE included. It is closer to what a reader
  experiences.
- NOISE is reported separately and never folded into the false-positive rate.
  A NOISE label that a later review overturns to FP counts as a leak.

**Who labels.** The labels are agent labels (the maintainer agent), not human
judgement.
- A second model labelled sample A as a cross-check. It agreed on 57% of
  items (Cohen's kappa 0.31), and its labels were rejected: it scored 13 of 22
  on a gold set fixed before its labels were seen, and it called most NOISE a
  true lead.
- Disagreements were settled by the maintainer agent.

**Two samples, two purposes:**
- **A — stratified by rule (96 findings, 34 rules).** For finding rules that
  misfire, so rare rules count as much as common ones. It does not estimate
  what a user sees.
- **B — what a user sees (174 findings).** Every critical finding (54, a
  census), plus 120 majors drawn at random from 3,523. Within each part,
  every finding had the same chance of being picked.

## Results

Sample B, labelled on the 2.6.1 findings. The 2.6.2 rows count only the
findings 2.6.2 still reports at that severity. No finding labelled TP changed
between the two versions.

| version | severity | findings | precision | actionable |
|---|---|---|---|---|
| 2.6.1 | critical | 54 | 0.86 (0.69-0.95) | 0.46 |
| 2.6.2 | critical | 32 | 0.89 (0.73-0.96) | 0.78 |
| 2.6.1 | major | 120 | 0.37 (0.23-0.53) | 0.12 |
| 2.6.2 | major | 48 | 0.48 (0.31-0.66) | 0.29 |

What changed in 2.6.2:
- Most of the non-actionable criticals were provider-shaped keys inside other
  scanners' test suites.
- Most of the non-actionable majors were:
  - best-effort error handling (`JH201`);
  - wildcard CORS with bearer-token auth (`JH109`);
  - SQL already bound through tagged templates or placeholders (`JH104`);
  - constant HTML (`JH126`).

Sample A found the rules that misfired in 2.6.1: `JH102`, `JH103`, `JH108`,
`JH120`, `JH125`, `JH126` and `JH505`.

## Limits

- **Interval width.** 48 majors give a wide interval.
- **Clustering.** Findings cluster by repository: one repository can supply
  many findings, so the intervals understate the real uncertainty.
- **Agent labels.** They are consistent, but they are one reviewer's
  judgement. Each label carries a one-line reason, so a human can audit it.
- **Population.** Public, mostly AI-assisted repositories are not your
  repository. Enterprise code with mature practices will see fewer findings
  and a different mix.
