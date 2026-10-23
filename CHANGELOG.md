# Changelog

All notable changes to JankHunt42 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [0.4.0] — 2026-10-23

Acts on the three highest-leverage gaps identified by an industry/competitor
review against Semgrep, SonarQube, Snyk Code, CodeQL, Checkmarx, and the
AI-code-review wave (Prbl, Copilot Autofix, Endor Labs): false-positive
noise is the market's actual bottleneck, every competing scanner has a
config file and JankHunt42 did not, and diff-only review misses the same
defect repeated across files. Also fixes a flaky selftest CI failure and
adds multi-tool platform metadata.

### Added

- **Repo config file** (`jh_config.py`): `.jankhunt.toml` (Python 3.11+,
  `tomllib`) or `.jankhunt.json` (always), discovered upward from the scan
  root the way `.git` is. Disables a rule, overrides its severity globally
  or per path glob, or ignores a subtree. Applies to `scan`, `score`, and
  `hunt` via `--config PATH` / `--no-config`; not yet wired into `review`.
- **Opt-in false-positive calibration** (`jh_calibrate.py`, `--calibrate`):
  records each rule's fired/suppressed counts into `.jankhunt/calibration.json`
  and, once a rule has enough history, downgrades its severity (confidence
  → `low`, tagged `calibrated`) based on its measured suppression rate in
  *this* repo — counting, not inference. The only flag besides `--cve` that
  writes anything.
- **Cross-file duplicate detection** (`jh_dedup.py`): clusters findings that
  share a rule and near-identical evidence (whitespace/numeric/string
  literals normalized) across two or more files, surfaced under
  `cross_file_duplicates` in every `scan`/`score`/`hunt` JSON/MD/TTY output
  with no flag needed. The existing `duplicate_blocks` check was file-local
  by construction; this catches the same defect pasted into several files
  instead.
- `_FindingAcceptor` now tracks per-rule `fired`/`suppressed` counts
  independent of `--min-severity`/`--category`/`--rule` display filters
  (`ScanResult.fired_by_rule`, `.suppressed_by_rule`), feeding calibration.

### Fixed

- **Flaky CI: `jankhunt` could exit 120 under a closed pipe.** Any command
  piped into something that reads only part of the output and exits early
  (`| head`, `| grep -q`, as the self-test's own `review --brief` check
  does) could intermittently fail. The write that raised `BrokenPipeError`
  was already caught, but CPython separately tries to flush the *buffered,
  not-yet-written* remainder of stdout at interpreter shutdown; that flush
  hits the same closed pipe outside any `try`/`except` we control and makes
  CPython set exit status 120 itself, overriding the 0 `main()` returned.
  Fixed by explicitly flushing stdout right after `main()` returns (still
  catchable there) and sinking further writes to `/dev/null` on
  `BrokenPipeError` before the implicit shutdown flush runs.
- **CI matrix:** `ubuntu-latest` dropped Python 3.9 from its preinstalled/
  downloadable set (migration to Ubuntu 26.04). Pinned the 3.9 job to
  `ubuntu-22.04` so the "Python 3.9+" compatibility claim stays tested
  instead of silently failing `setup-python`.
- Added `.claude/`, `.opencode/`, `.cursor/`, `.codex/` to `.gitignore`.
  These are where a coding agent's own local session state lives when run
  inside this repo (this repo is also a target *install* location for
  other projects via those same directory names — see the README install
  table — but this repo's own working tree should never track an agent's
  session data in it).

## [0.3.0] — 2026-10-23

Positioning and distribution release. No scanner or scoring behavior
changed; this release makes explicit what the rule catalog already covered.

### Added

- **Cross-tool compatibility.** `SKILL.md` now declares `platforms`
  (`CLAUDE_CODE`, `CURSOR`, `CODEX_CLI`) and documents the exact install
  directory for Claude Code, Cursor, Codex CLI, and OpenCode. The skill was
  already a plain `SKILL.md` + stdlib-Python CLI with no tool-specific code;
  this makes that explicit instead of reading as OpenCode-only.
- **Release provenance** (`.github/workflows/provenance.yml`): tagged
  releases are built into a source tarball and signed with a GitHub Artifact
  Attestation (keyless Sigstore), verifiable with `gh attestation verify`.
  This is independent of, and does not change, any third-party marketplace's
  own verification badge for this skill.
- **Citizen-developer and AI-assisted jank, named explicitly.** `SKILL.md`
  and the README now call out that the `security`, `reliability`,
  `maintainability`, and `tests` rule categories catch the failure pattern
  typical of pasted-in copilot suggestions and citizen-developer/low-code
  workflows — hardcoded secrets, untested happy-path logic, swallowed
  errors, duplicated scaffolding — as a side effect of catching any other
  kind of jank. No new rules were added; this documents existing coverage
  under a name buyers are searching for.

## [0.2.0] — 2026-10-23

Review-layer release. JankHunt42 now reviews a diff deterministically, emits
evidence receipts, measures coverage, compares against a baseline, and reads
supply-chain evidence without pretending to verify signatures.

### Added

- **`review` command** for working-tree, staged, commit, base-ref, and
  checked-out GitHub PR diffs. It scans the exact tree/index/commit that the
  diff describes and reports only findings on added lines as new; findings in
  changed-hunk context are labeled `contextual`, and unchanged-line findings
  are counted as suppressed rather than silently mixed into the review.
- **Review receipts** (`receipt_version` 1.0) with stable rule/location/evidence
  fields, `supported`/`unverified` verification status, counterevidence, a
  reproducible scan command, a scan ID, a rulepack hash, and a per-receipt
  SHA-256 hash. Receipts never claim runtime `confirmed` without runtime
  evidence.
- **Baseline deltas** via `review --baseline PATH` and `--save-baseline PATH`.
  Baselines accept prior review JSON, scan JSON, or a findings list; the review
  reports new, persisting, and resolved findings plus score delta. `--fail-on`
  gates new findings only and excludes persisting findings by default.
- **Coverage and scope reporting**: changed/reviewed/suppressed files, deleted
  and untracked files, changed lines, reviewed LOC, languages, test files,
  skipped-file reasons, and explicit unknowns. `--brief` emits a Markdown
  reviewer pack with the evidence contract for the host agent or an external
  reviewer.
- **`supply-chain` command** and automatic review evidence discovery for SPDX
  2.x JSON/tag-value, SPDX 3 JSON-LD, CycloneDX JSON/XML, GitHub artifact
  attestations, Sigstore/DSSE bundles, direct in-toto statements, JSONL
  `gh attestation download` output, and JFrog AppTrust / `jf evd verify`
  evidence exports.
- **Honest evidence labels**: `provider-verified` only when the exporter
  records a successful verification result (for example JFrog); GitHub/Sigstore
  signature material is reported as `unverified` with a `gh attestation verify`
  or `cosign` hint. Unsigned statements are labeled `unsigned`. JankHunt42
  does not perform cryptography itself.
- Supply-chain requirements and gates: `--require-sbom`,
  `--require-attestation`, and `--require-verified-attestation` on both
  `review` and `supply-chain`.
- New reference docs: `references/review.md` for the review protocol and
  receipt contract, and `references/supply-chain.md` for evidence formats,
  verification boundaries, and rollup behavior.
- Regression fixtures for working/staged/commit/base review, changed-line and
  contextual filtering, receipts, baseline new/persisting/resolved, SPDX JSON
  and tag-value, CycloneDX, GitHub DSSE/in-toto, JFrog evidence, explicit
  evidence-path forcing, malformed evidence, verification labels, requirement
  gates, and SARIF receipt fingerprints.

### Changed

- Version is now `0.2.0`. `review` and `supply-chain` are first-class commands in
  the CLI and the OpenCode skill workflow.
- Review output supports TTY, Markdown, JSON, SARIF, and `--brief`. Review JSON
  carries `review.scope`, `review.score`, `review.findings`,
  `review.contextual`, `review.baseline`, `review.supply_chain`,
  `review.unknowns`, and `review.gate`.
- Supply-chain evidence is context, not a vulnerability count. Missing evidence
  is a warning unless a requirement flag asks for a gate.

### Notes

- Supply-chain inspection is offline and read-only. It parses files on disk and
  never contacts a registry, transparency log, JFrog instance, or GitHub.
- `provider-verified` is the exporter's claim, not a fresh JankHunt42
  cryptographic verification. Use `gh`, `cosign`, or `jf` when an independent
  verification result is required.
- The review command is a deterministic pre-pass, not a replacement for the
  project compiler, tests, native linters, or human judgment. See
  `references/review.md` for the boundary between `supported` and `confirmed`.

## [0.1.0] — 2026-10-23

Initial release.

### Added

- OpenCode skill with an evidence-driven debugging doctrine, universal
  suspects, escalation rules, and a definition of done.
- Stdlib-only `jankhunt` CLI with `scan`, `score`, `triage`, `doctor`,
  `report`, `hunt`, `merge`, and `rules` commands.
- 79 static rules across security, reliability, maintainability, tests,
  Docker/Compose, Kubernetes, GitHub Actions, GitLab CI, supply chain, and
  documentation.
- Multi-line/structural checks: empty handlers, `return` in `finally`,
  blocking calls in async functions, missing HTTP/subprocess timeouts, long
  functions, deep nesting, duplicate blocks, Docker root stages, plaintext
  Kubernetes Secrets, `pull_request_target` checkout, CI expression injection,
  assertion-free tests, and broken Markdown links.
- TTY-first renderer with banner, dimension scorecard, severity chips, bars,
  and ranked finding cards. Cards use a severity-colored rail, bold
  index/rule/location, and labeled `evidence` / `why` / `fix` lines with
  rail-aligned wrapping. Clean Markdown/JSON/SARIF fallbacks remain.
- **Self-contained HTML report** via `scan --html`: embedded CSS/JS, score
  ring, dimension cards, hot spots, top rules, severity filters, search, and
  escaped repository data. No external fonts, scripts, styles, or images;
  portable enough to attach to a ticket.
- **Jank Score 2.0** (`scripts/jh_score.py`): severity × confidence ×
  exposure, per-rule saturation, density per KLOC, severity floors, separate
  security/reliability/maintainability/test-confidence dimensions, A-E grades,
  a weakest-dimension anchor, an advisory policy, and JSON arithmetic.
- **New-code scoring** via `--since REF` on `scan`, `score`, `report`, and
  `hunt`, using changed-line discovery from `git diff`.
- **Deep hunt** (`scripts/jh_hunt.py`): opt-in adversarial panel with nine role
  cards, a 24-scenario deck, a lead board, a round plan, self-contained agent
  prompts, a cross-examination template, guardrails, and a consensus merger
  with `confirmed`/`supported`/`contested`/`unverified`/`rejected` statuses.
- `hunt` command for machine-readable plans and prompt packs; `merge` command
  for deduplicating independent panel JSON, preserving conflicts and dissent,
  and gating only on confirmed findings. The merger enforces the evidence rule:
  a declared `confirmed` claim without a real repro command/test or runtime
  evidence is downgraded to `supported` and flagged with a gate note.
- Log triage for plain text, JSONL, gzip, and stdin: severity and timestamp
  extraction, stack-trace attachment, volatile-value normalization, and
  fingerprint clustering.
- Project/system doctor: git state, manifests, language mix, toolchains,
  limits, disk/memory, listening ports, failed units, and kernel warnings.
- Opt-in OSV.dev CVE lookup (`scan --cve`) with manifest parsing, batch
  queries, full-advisory fetching, CVE aliases, severity mapping, and fixed
  versions.
- Inline and file-level suppressions (`jankhunt: ignore`, `ignore-file`).
- Markdown investigation report generator with scorecard, environment,
  findings, log triage, a worksheet, and next moves.
- Reference docs for the method, playbooks, toolbox, scoring, and deep hunt;
  report, hunt-report, and panel-finding templates.
- Offline self-test fixture covering rules, redaction, JSON/SARIF, HTML
  parsing and escaping, score, new-code scoring, triage, hunt/merge evidence
  gating, report, TTY rendering, and packaging.
- Publishing checklist.

### Notes

- CVE lookup sends only package name, version, and ecosystem to OSV.dev.
  Without `--cve`, the scanner is fully offline.
- The Jank Score 2.0 is a prioritization device, not a compliance certificate.
  Gate CI on `--fail-on` (or `merge --fail-on` for confirmed panel findings)
  and on native test/tool results.
- Deep hunt is opt-in and read-only by default. Permission to spawn agents does
  not authorize edits, production access, exploits, or load tests.
- `confirmed` requires a repro or direct runtime evidence. Votes never upgrade
  a finding's status.
