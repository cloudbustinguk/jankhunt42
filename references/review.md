# Diff review protocol

`jankhunt review` is a deterministic pre-pass for a code review. It answers
five questions before an LLM or a human starts reasoning about the change:

1. What exactly changed?
2. Which changed files and lines were actually inspected?
3. Which findings are new, contextual, persisting, or resolved?
4. What evidence supports each finding, and what would falsify it?
5. What evidence is still missing?

It is not a second opinions engine and it is not a replacement for
`/review`, a compiler, tests, native linters, or a human reviewer. Its output
is a **receipt-backed lead board**. The semantic reviewer still has to decide
whether a lead is real, reachable, and worth fixing.

## Modes

| Mode | Command | Diff source | Scanned revision |
|---|---|---|---|
| Working tree (default) | `review .` | `git diff HEAD` plus untracked files | working tree |
| Staged only | `review . --staged` | `git diff --cached` | index (`:path`) |
| Commit | `review . --commit SHA` | `git show SHA` | the commit tree |
| Base ref | `review . --base origin/main` | `git diff BASE...HEAD` | `HEAD` tree |
| Pull request | `review . --pr 123` | `BASE...HEAD` after checking out the PR | `HEAD` tree |

The review scans the exact revision described by the diff. A dirty working
tree will not silently change the line numbers of a committed-commit or
base-ref review. For `--pr`, the local `HEAD` must equal the PR head; otherwise
the command fails and asks you to check out the PR branch first.

## Scope model

* **New** — the finding overlaps an added line (`+` in the diff).
* **Contextual** — the finding is in a changed hunk but not on an added line.
  It is useful context, not a review-gate finding.
* **Unchanged** — the finding is in a changed file but outside every hunk. It
  is counted as suppressed and is not presented as a review finding.
* **Persisting** — a new-line finding whose stable fingerprint exists in the
  baseline.
* **Resolved** — a baseline finding whose fingerprint is absent from the
  current review.

Deleted files, binary files, generated/vendor paths, excluded globs, files
larger than `--max-file-bytes`, and files beyond `--max-files` are listed in
`review.scope.skipped_files` with a reason. Untracked files are reviewed as
all-new lines in working-tree mode.

The scope object also reports changed/reviewed file counts, changed lines,
reviewed LOC, languages, touched test files, deleted files, and untracked
files. The JSON schema is intentionally explicit so a CI job can assert that
coverage did not silently collapse to zero files.

## Receipt contract

Every review finding is a receipt. A receipt is a static-evidence record, not a
runtime proof.

```json
{
  "id": "JH-4f1c2b0a9d77",
  "rule": "JH102",
  "title": "Dynamic code execution",
  "severity": "major",
  "category": "security",
  "confidence": "medium",
  "path": "app.py",
  "line": 7,
  "column": 12,
  "end_line": null,
  "location": {"file": "app.py", "line": 7, "column": 12},
  "scope": "new",
  "verification": "supported",
  "evidence": "return eval(value)",
  "message": "eval/exec-style APIs turn data into code ...",
  "fix": "Replace with a parser, dispatch table ...",
  "counterevidence": "Static pattern/structural rule only ...",
  "repro": "jankhunt scan app.py --rule JH102 --min-severity info --json",
  "tags": [],
  "scan_id": "…",
  "receipt_version": "1.0",
  "receipt_hash": "…"
}
```

Fields that matter for adjudication:

* `evidence` — the sanitized line or structural fact that triggered the rule.
* `counterevidence` — the built-in reminder that reachability, guards, and
  runtime behavior were not reproduced.
* `repro` — the cheapest deterministic command that reproduces the lead.
* `verification` — `supported` for a high/medium-confidence static rule with
  evidence; `unverified` otherwise. The review never emits `confirmed`.
* `receipt_hash` — SHA-256 over the canonical receipt content. `id` is derived
  from it. Use the hash as a stable review artifact; do not edit the receipt
  after hashing.
* `scan_id` — identifies the scan material. `review.diff_hash` identifies the
  exact diff text used, and `review.rulepack_hash` identifies the rule catalog.

A reviewer can upgrade a lead to `confirmed` only by adding a repro command, a
test result, or direct runtime evidence. The merge command enforces the same
evidence rule for panel findings.

## Baseline and gate

Save a baseline from a clean review:

```bash
jankhunt review . --base origin/main --json --save-baseline .jankhunt/baseline.json
```

Compare a later review:

```bash
jankhunt review . --base origin/main --baseline .jankhunt/baseline.json --fail-on major
```

A baseline may be a prior `review` JSON document, a `scan` JSON document, or a
plain findings list. The review compares stable fingerprints based on rule,
path, and normalized evidence. The delta object reports:

* baseline and current scores,
* score delta when both scores exist,
* new, persisting, and resolved counts,
* new findings,
* persisting fingerprints,
* resolved findings.

`--fail-on SEV` gates **new** findings only. It excludes persisting findings so
an existing debt backlog does not block every PR. It also excludes
`unverified` leads by default; add `--include-unverified` to gate them. Supply
chain requirement failures are added to the same gate.

## Reviewer handoff

Use `--brief` to produce a Markdown pack for the host agent or an external
reviewer. It contains the scope, gate, score, receipts, contextual leads,
supply-chain evidence, and a compact output contract. The intended sequence is:

1. Run `review` and keep the JSON receipt set.
2. Give the semantic reviewer the diff plus the brief.
3. Require it to classify each lead as `confirmed`, `supported`, `contested`,
   `unverified`, or `rejected`.
4. Require new evidence for any upgrade to `confirmed`.
5. Merge or report the adjudicated result; preserve dissent and unknowns.

This division of labor is deliberate: the deterministic layer owns scope,
reproduction, coverage, and receipt integrity; the semantic layer owns context,
intent, and test design.

## Limitations

* No runtime or test execution.
* No compiler, typechecker, native linter, or language server.
* No full-repository semantic review; unchanged files are not re-reviewed.
* No cryptographic signature verification. See `supply-chain.md`.
* No dependency CVE lookup unless a separate `scan --cve` run is added to the
  review evidence. The review itself stays offline.
* The new-code score density uses added lines from every reviewed file, not
  only source code. A very large SBOM, fixture, or data file can dilute the
  denominator; check `review.scope.changed_lines` and the language list before
  comparing scores across changes.
* Static rules can be wrong. A receipt is a reason to look, not a verdict.
