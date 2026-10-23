# JankHunt42

**Find the jank before it finds production.**

JankHunt42 is an OpenCode skill and a standalone, stdlib-only investigation CLI. It scans code, CI pipelines, Kubernetes manifests, containers, dependencies, and logs, then ranks what is likely to hurt you. It is built for debugging and triage, not just linting: every finding is a **lead** with evidence, a rationale, and a fix direction.

**Version:** 0.2.0 · **License:** MIT · **Runtime:** Python 3.9+ · stdlib only

What makes it more than a regex wrapper:

- **Jank Score 2.0** — a transparent, dimension-based prioritization model inspired by SonarQube's ratings and Veracode's severity × confidence philosophy. It grades security, reliability, maintainability, and test confidence separately, anchors the headline to the weakest dimension, and can score only the lines changed since a git ref.
- **Evidence-gated diff review** — `jankhunt review` establishes exact scope, separates new lines from changed-hunk context, emits stable receipts with counterevidence and repro commands, measures coverage, and compares against a baseline. It is a deterministic pre-pass for `/review`, not a replacement for it.
- **Supply-chain context** — offline parsers for SPDX/CycloneDX SBOMs, GitHub/Sigstore/in-toto attestations, and JFrog AppTrust evidence. Externally verified evidence is labeled `provider-verified`; signature material JankHunt42 did not verify is labeled `unverified`.
- **Deep hunt (opt-in)** — a structured adversarial panel for high-risk or ambiguous work. Independent roles investigate, cross-examine, and reach an evidence-weighted consensus; `confirmed` requires a repro or direct runtime evidence, and dissent is preserved.

None of these is a substitute for compilers, tests, Semgrep, SonarQube, Trivy, signature verifiers, or human review. They are ways to spend attention better.

```text
  ╭──────────────────────────────────────────────────────────────────────╮
  │  J A N K H U N T 4 2   // code autopsy lab                          │
  │  /srv/api  ·  1,284 files  ·  96,420 LOC  ·  1.82s                   │
  ╰──────────────────────────────────────────────────────────────────────╯

  JANK  ██████████████░░░░░░  44/100  D · grimy  policy fail
  Security          ██████████████  55  D  2 findings
  Reliability       ███████░░░░░░░  30  C  4 findings
  Maintainability   ██░░░░░░░░░░░░   4  A  21 findings
  Test confidence   ░░░░░░░░░░░░░░   0  A  0 findings
  CRITICAL 2   MAJOR 7   MINOR 23   INFO 41

  TOP OFFENDERS
    src/api/auth.ts            ██████████████  9 findings
    .github/workflows/ci.yml   ████████        5 findings
    deploy/deployment.yaml     ██████          4 findings

  FINDINGS  ·  2 findings  ·  worst first

  ┃ 01   CRITICAL   JH101  Hardcoded secret
  ┃     src/api/auth.ts:42  security  confidence high
  ┃     │ evidence const API_KEY = "***REDACTED***"
  ┃     └ why A credential-like literal is embedded in source.
  ┃       fix Rotate the credential now, purge it from history, and…
```

TTY output uses a colored banner, a dimension scorecard, severity chips, bars, and ranked cards. Finding cards have a severity-colored rail, bold index/rule/location, and labeled `evidence` / `why` / `fix` lines. Piped output, `--md`, `NO_COLOR`, or `TERM=dumb` produces clean Markdown. `--json` and `--sarif` are stable machine formats; JSON includes the full score arithmetic and, with `--since`, a new-code view. `review --json` adds exact diff scope, receipt hashes, baseline deltas, coverage, and supply-chain evidence.

`scan --html` writes a single, self-contained visual report: score ring, dimension cards, hot spots, severity filters, and search, with embedded CSS/JS and no external assets. Redirect it to a file:

```sh
jankhunt scan . --html > jankhunt.html
```

## Why this exists

Most scanners answer “does this line match a rule?” JankHunt42 is organized around the debugging question: **what is most likely to explain the failure, and what evidence should I collect next?** It combines a fast static pass with log fingerprinting and an environment doctor, so you can move from symptom to hypothesis without assembling five tools first.

It is deliberately dependency-free: one Python 3.9+ interpreter, no `pip install`, no network unless you ask for CVE data. That makes it usable on locked-down CI runners, random customer machines, and air-gapped boxes.

## How review fits together

JankHunt42 is not trying to win the code-review chatbot contest. It does not build a code graph, run forty linters, chat in a PR, or auto-fix a branch. It provides the **deterministic evidence layer** around a semantic reviewer:

| Layer | Owns |
|---|---|
| `jankhunt review` | Exact diff scope, changed-line/context separation, static receipts, coverage, baseline deltas, supply-chain evidence, reproducible gates |
| Built-in `/review` or another semantic reviewer | Intent, design, reachability, impact, test design, adjudication, and prose |
| Compiler/tests/native tools | Correctness, build, type, lint, and runtime proof |

Run the deterministic pass first, send the diff and `--brief` to the semantic reviewer, and require new evidence before any lead is upgraded to `confirmed`. The receipt contract is in [`references/review.md`](references/review.md); evidence-format boundaries are in [`references/supply-chain.md`](references/supply-chain.md).

## Quick start

### As an OpenCode skill

Copy this folder into either location:

```sh
# Global (available in every project)
git clone https://github.com/cloudbustinguk/jankhunt42.git ~/.config/opencode/skills/jankhunt42

# Or project-local (committed with the repo)
mkdir -p .opencode/skills
cp -R /path/to/jankhunt42 .opencode/skills/jankhunt42
```

OpenCode discovers `SKILL.md` automatically. The model can invoke **JankHunt42** for debugging and audit work. Restart the session if the skill list was already loaded.

### As a standalone CLI

```sh
SKILL_DIR=~/.config/opencode/skills/jankhunt42
python3 "$SKILL_DIR/scripts/jankhunt" --version

# Optional: put it on PATH (the launcher resolves symlinks)
mkdir -p ~/.local/bin
ln -sf "$SKILL_DIR/scripts/jankhunt" ~/.local/bin/jankhunt
jankhunt --version
```

Requirements: Python 3.9+ (3.11+ recommended), Linux/macOS. Windows works for the scanner; `doctor --system` degrades gracefully where Linux-only probes are unavailable. No third-party packages.

## Commands

### Scan

```sh
jankhunt scan .                              # TTY autopsy, Markdown when piped
jankhunt scan src tests --md                 # force Markdown on a TTY
jankhunt scan . --json > jank.json           # machine-readable
jankhunt scan . --sarif > jank.sarif         # SARIF 2.1.0 for code scanning
jankhunt scan . --html > jankhunt.html       # self-contained visual report
jankhunt scan . --fail-on critical           # exit 1 if a critical+ finding exists
jankhunt scan . --min-severity major         # only major and above
jankhunt scan . --min-severity info          # include context/style findings
jankhunt scan . --category security --category ci
jankhunt scan . --rule JH101 --rule JH418
jankhunt scan . --exclude 'vendor/**' --max-files 5000
jankhunt scan . --cve                        # OSV.dev dependency advisories (network)
jankhunt scan . --since origin/main          # whole-tree + new-code score
```

Important flags:

| Flag | Meaning |
|---|---|
| `--md` | Force Markdown even on a TTY |
| `--html` | Self-contained HTML report on stdout; mutually exclusive with `--md`, `--json`, `--sarif` |
| `--no-color` | Disable ANSI colors |
| `--json` / `--sarif` | Stable machine output; ignores `--max-findings` |
| `--fail-on SEV` | Exit `1` when any finding is at least that severe |
| `--min-severity SEV` | Filter findings; default `minor` (use `info` for context) |
| `--category`, `--rule` | Narrow the rule set |
| `--exclude GLOB` | Skip paths (repeatable) |
| `--max-findings N` | Cap the human view only (default 300) |
| `--cve` | Query OSV.dev for pinned dependencies |
| `--since REF` | Also score findings on lines changed since `REF` |
| `--quiet` / `--no-progress` | Suppress the spinner |

#### HTML report

```sh
jankhunt scan . --html > jankhunt.html
open jankhunt.html                 # macOS; use xdg-open on Linux
```

The report is one portable file: embedded CSS/JS, no external fonts, scripts, styles, or images. It includes the Jank Score headline and dimensions, severity counts, top offenders, top rules, and filterable/searchable finding cards. Every repository-derived string is HTML-escaped, and secret redaction still applies. `--max-findings N` caps the human view; `--json` and `--sarif` keep the full set. Choosing `--html` together with `--md`, `--json`, or `--sarif` is a usage error (exit `2`).

### Review a diff

```sh
jankhunt review .                              # working tree + untracked files
jankhunt review . --staged                     # index only
jankhunt review . --commit HEAD                # one committed tree
jankhunt review . --base origin/main           # BASE...HEAD, scans HEAD tree
jankhunt review . --pr 123                     # checked-out GitHub PR
jankhunt review . --base origin/main --json > review.json
jankhunt review . --base origin/main --sarif > review.sarif
jankhunt review . --base origin/main --brief   # reviewer handoff pack
```

`review` scans the exact revision described by the diff: the working tree, the index, a commit tree, or `HEAD`. A committed review never silently picks up dirty working-tree edits. It separates findings into:

- **new** — overlaps an added line and participates in the new-code score and gate;
- **contextual** — in a changed hunk but on an unchanged line; useful context, not a gate finding;
- **unchanged** — in a changed file but outside every hunk; counted as suppressed.

Every machine-readable finding is a receipt: rule, location, evidence, counterevidence, a `jankhunt scan …` repro command, `supported`/`unverified` verification, scan ID, and SHA-256 `receipt_hash`. A receipt is never `confirmed` without runtime evidence. The review also reports coverage and skipped-file reasons so a zero-finding result cannot hide a scope collapse.

```sh
# Save an accepted baseline, then gate only new findings.
jankhunt review . --base origin/main --json --save-baseline .jankhunt/baseline.json
jankhunt review . --base origin/main \
  --baseline .jankhunt/baseline.json --fail-on major

# Gate unverified leads too (off by default).
jankhunt review . --base origin/main --baseline .jankhunt/baseline.json \
  --fail-on major --include-unverified
```

Important flags:

| Flag | Meaning |
|---|---|
| `--staged`, `--commit SHA`, `--base REF`, `--pr N` | Mutually exclusive diff modes |
| `--baseline PATH` | Compare with prior review JSON, scan JSON, or findings list |
| `--save-baseline PATH` | Write this review as the next baseline |
| `--fail-on SEV` | Exit `1` for **new** supported findings at/above `SEV`; persisting baseline findings are excluded |
| `--include-unverified` | Include unverified leads in the `--fail-on` gate |
| `--brief` | Markdown reviewer pack with scope, receipts, score, supply chain, and the evidence contract |
| `--no-supply-chain` | Skip SBOM/attestation discovery for this review |
| `--require-sbom`, `--require-attestation`, `--require-verified-attestation` | Add supply-chain requirements to the review gate |

The review protocol, receipt schema, baseline semantics, and reviewer handoff contract are documented in [`references/review.md`](references/review.md). The machine schema is [`templates/review-receipt.schema.json`](templates/review-receipt.schema.json).

### Supply-chain evidence

```sh
jankhunt supply-chain . --json
jankhunt supply-chain . --md
jankhunt supply-chain . --require-sbom --require-attestation
jankhunt supply-chain . --jfrog-evidence apptrust-evidence.json
jankhunt supply-chain . --no-discover --sbom build/app.spdx.json
```

| Evidence | Accepted forms |
|---|---|
| SPDX 2.x | JSON and tag-value |
| SPDX 3 | JSON-LD `@graph` |
| CycloneDX | JSON and XML |
| GitHub attestations | Sigstore/DSSE bundles and JSONL from `gh attestation download` |
| in-toto / Sigstore | Direct statements, SLSA v0.2/v1 provenance, DSSE envelopes |
| JFrog AppTrust | `evidenceVerifications`, nested `sigstoreBundle`, direct predicates, relative `downloadPath` |

The inspector is offline and read-only. `provider-verified` means the **exporter** recorded a successful verification (for example, JFrog's `verificationResult`); it is not a fresh JankHunt42 verification. GitHub/Sigstore signature material is `unverified` with a `gh attestation verify` or `cosign` hint; statements without signature material are `unsigned`. JankHunt42 does not perform cryptography. Missing evidence is a warning unless a `--require-*` flag makes it a gate. Full format and trust-boundary notes: [`references/supply-chain.md`](references/supply-chain.md).

### Score

```sh
jankhunt score .                         # dimension scorecard (TTY)
jankhunt score . --md                    # Markdown
jankhunt score . --json                  # full arithmetic, dimensions, policy
jankhunt score . --since origin/main     # new-code score
jankhunt score . --fail-policy           # advisory exit 1 when policy is fail
```

The scorecard separates **security, reliability, maintainability, and test confidence**, assigns A-E grades, and reports an advisory `pass`/`warn`/`fail` policy. It is a prioritization device, not a compliance certificate. The full model — weights, floors, saturation, new-code behavior, worked examples, and limitations — is in [`references/scoring.md`](references/scoring.md).

### Triage logs

```sh
jankhunt triage app.log
jankhunt triage app.log api.log --top 25
jankhunt triage --grep 'timeout|refused|panic' *.log
gzip -dc prod.log.gz | jankhunt triage -
jankhunt triage app.log --json
```

Triage parses plain text, JSONL, and gzip. It extracts severity and timestamps, detects stack traces, attaches continuations, normalizes volatile values (UUIDs, IPs, hex, paths, numbers, quoted strings), and clusters identical fingerprints. The result ranks clusters by severity and frequency, with line spans and samples.

### Doctor

```sh
jankhunt doctor
jankhunt doctor --json
jankhunt doctor --system          # + listening ports, failed units, kernel warnings
jankhunt doctor /path/to/project
```

Reports repository state (branch, HEAD, dirty files, conflicts, stashes), manifests and lockfiles, language mix, test count, installed toolchains and versions, CPU/RAM/disk, load, inotify and file-descriptor limits, proxy/PATH-related environment, and optional Linux system health. It flags mismatches such as “package.json with no lockfile” and “disk almost full.”

### Report

```sh
jankhunt report . --logs app.log --out jankhunt-report.md
jankhunt report . --system --cve --out report.md
```

Builds a Markdown investigation report with an executive summary, the Jank Score 2.0 scorecard, environment snapshot, static findings, log clusters, an investigation worksheet, and next moves. Safe to attach to an issue or PR. Add `--since origin/main` to include a new-code score.

### Deep hunt (opt-in)

```sh
jankhunt hunt . --focus security --panel 6 --rounds 3 --json > hunt.json
jankhunt hunt . --md --prompts > hunt-brief.md
jankhunt merge panel-*.json --md
```

A deep hunt is an adversarial panel, not a vote. It runs only when the user explicitly asks for one. The generated brief includes role prompts, a scenario deck, the lead board, guardrails, and the consensus contract. Independent panelists investigate first; cross-examination tries to falsify each claim; `merge` groups duplicates, preserves conflicts and dissent, and classifies findings as `confirmed`, `supported`, `contested`, `unverified`, or `rejected`.

`confirmed` requires a repro command/test or direct runtime evidence. Votes never upgrade a claim. The merger enforces the rule: a declared `confirmed` claim without that evidence is downgraded to `supported` with a gate note. Permission to spawn agents does not grant permission to edit code, touch production, run exploits, or start load tests. See [`references/deep-hunt.md`](references/deep-hunt.md) for the full protocol.

### Rules

```sh
jankhunt rules
jankhunt rules --category security
jankhunt rules --min-severity major
jankhunt rules --json
```

Prints the catalog with severity, category, confidence, and title. `JH901` is populated dynamically by `scan --cve`.

## What it detects

79 built-in rules, plus OSV advisories:

| Area | Examples |
|---|---|
| Secrets & credentials | Cloud keys, GitHub/Slack/Stripe tokens, private keys, generic `api_key = "..."`, committed `.env`/key files (values redacted) |
| Injection & execution | SQL concatenation/interpolation, `shell=True`, `os.system`, `child_process.exec`, `eval`, `new Function`, `document.write`, `innerHTML`, `dangerouslySetInnerHTML`, Vue `v-html`, Angular security bypasses |
| Deserialization & files | `pickle.loads`, unsafe YAML, Java `readObject`, `tarfile`/`zipfile` `extractall`, `tempfile.mktemp` |
| Crypto & auth | MD5/SHA-1/DES/RC4/ECB, `verify=False`, `rejectUnauthorized: false`, JWT verification disabled, `algorithms=["none"]`, insecure RNG near secrets, wildcard `ALLOWED_HOSTS` |
| Web hardening | Debug mode, wildcard CORS, `0.0.0.0` binds, XML parser review |
| Reliability | Empty handlers, bare/broad catches, `return` in `finally`, blocking calls in `async def`, HTTP/subprocess calls without timeouts, mutable defaults, `None` comparisons, suspicious sleeps |
| Maintainability | Long functions, deep nesting, very long lines, large files, duplicated blocks, commented-out code, TODO/FIXME, wildcard imports, suppressions, dead branches |
| Tests | Skipped/disabled tests, tests without assertions, focused tests (`.only`), tautological assertions, sleeps |
| Docker & Compose | Root final stage, unpinned base images, `ADD` from URL, privileged containers, host networking, dangerous capabilities |
| Kubernetes | Privileged pods, host namespaces, `allowPrivilegeEscalation`, root UID, `seccompProfile: Unconfined`, `hostPath`, `:latest`, deprecated APIs, plaintext `Secret` values |
| GitHub Actions | `pull_request_target` + PR-head checkout, event-expression shell injection, unpinned actions (tag/branch), `write-all`, `continue-on-error`, `npm install` |
| GitLab CI | Remote includes, unpinned `image:latest`, `allow_failure` |
| Supply chain | Missing lockfiles, unpinned npm ranges, OSV CVEs with fixed versions |
| Docs | Broken relative Markdown links |

See `jankhunt rules` for the live catalog. IDs are stable; new rules may be added without renumbering.

## CVE awareness

`scan --cve` parses pinned dependencies from:

- `package.json`, `package-lock.json`, `npm-shrinkwrap.json`
- `requirements*.txt`, `pyproject.toml` (exact `==` pins), `Pipfile.lock`, `poetry.lock`
- `Cargo.lock`, `go.mod`
- `pom.xml`, `build.gradle(.kts)`, `*.csproj`
- `Gemfile.lock`, `composer.lock`, `pubspec.lock`

It batches queries to [OSV.dev](https://osv.dev), then fetches full advisories because `querybatch` returns only IDs and modification times. Findings include advisory IDs, CVE aliases, severity, fixed versions, and references.

**Privacy:** only package name, version, and ecosystem leave the machine. Source code and manifests are never uploaded. `--cve` is opt-in; without it, everything is offline. If the network fails, the scan continues with a warning—CVE lookup is best-effort, not a build gate.

**Limits:** ranges such as `^1.2.3` and `*` are skipped because the installed version is unknown; lockfiles are preferred. OSV severity is mapped: critical→critical, high→major, medium→minor, low→info. Always confirm advisory applicability against the actual resolved dependency tree.

## Suppressions

For confirmed false positives, add a reason and rule IDs:

```python
# jankhunt: ignore JH201,JH202
except Exception:  # jankhunt: ignore JH201
    pass
```

File-level suppressions go in the first 12 lines:

```python
# jankhunt: ignore-file JH305
```

Suppressed findings do not count toward totals. Do not suppress a real defect; fix it instead.

## Jank Score 2.0

The score is a **prioritization device**, not a compliance metric. It is versioned (`2.0`) and transparent.

**Inspiration, not imitation:**

- **SonarQube:** separate ratings, A-E grades, density over raw counts, severity floors, new-code focus, quality-gate thinking.
- **Veracode:** severity × confidence, coarse exposure weighting, policy gates, false positives as first-class results.

**Model in one screen:**

```text
points    = severity_weight × confidence_factor × exposure_factor
dimension = max(100 × (1 − e^(−points_per_KLOC / K)), severity_floor)
headline  = round(0.70 × worst_dimension + 0.30 × weighted_average)
```

Per-rule contribution saturates after 10 findings. A single blocker or critical floors its dimension, mirroring rating-by-worst-issue. The 70% worst-dimension anchor prevents a security catastrophe from being averaged away by clean style.

| Grade | Score | Reading |
|---|---:|---|
| A | 0-5 | Clean enough to stop looking at the scanner |
| B | 6-15 | Minor drag; fix on touch |
| C | 16-35 | Worth a planned pass |
| D | 36-60 | Serious; prioritize before the next release |
| E | 61-100 | Stop and fix; risk is concentrated |

The advisory policy is `pass`, `warn`, or `fail`; `score --fail-policy` exits `1` on `fail`. That is not the CI gate. Gate CI on `--fail-on` and native tests. Use `--since REF` to score only changed lines, so legacy debt does not block a clean fix.

Full formula, weights, floors, worked examples, calibration, and limitations: [`references/scoring.md`](references/scoring.md).

## CI integration

### GitHub Actions

```yaml
name: jankhunt
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4   # pin to a SHA in production
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - name: Scan
        run: python3 .opencode/skills/jankhunt42/scripts/jankhunt scan . --sarif > jankhunt.sarif
      - name: Score
        run: python3 .opencode/skills/jankhunt42/scripts/jankhunt score . --json > jankhunt-score.json
      - name: Review new lines
        if: github.event_name == 'pull_request'
        run: |
          python3 .opencode/skills/jankhunt42/scripts/jankhunt review . \
            --base "${{ github.event.pull_request.base.sha }}" \
            --json > review.json
          python3 .opencode/skills/jankhunt42/scripts/jankhunt review . \
            --base "${{ github.event.pull_request.base.sha }}" \
            --fail-on major
      - name: Supply-chain evidence
        if: always()
        run: python3 .opencode/skills/jankhunt42/scripts/jankhunt supply-chain . --json > supply-chain.json
      - name: Upload SARIF
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: jankhunt.sarif
      - name: Gate
        run: python3 .opencode/skills/jankhunt42/scripts/jankhunt scan . --fail-on critical
      - name: HTML report
        if: always()
        run: python3 .opencode/skills/jankhunt42/scripts/jankhunt scan . --html > jankhunt.html
      - name: Upload reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: jankhunt-reports
          path: |
            jankhunt.html
            jankhunt-score.json
            review.json
            supply-chain.json
```

For a baseline gate, keep an accepted `review.json` artifact (or `.jankhunt/baseline.json`) and add `--baseline`. Without a baseline, `--fail-on` gates every new-line finding in the diff.

### GitLab CI

```yaml
jankhunt:
  image: python:3.12-slim
  script:
    - python3 .opencode/skills/jankhunt42/scripts/jankhunt scan . --json > jankhunt.json
    - python3 .opencode/skills/jankhunt42/scripts/jankhunt review . --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --json > review.json
    - python3 .opencode/skills/jankhunt42/scripts/jankhunt supply-chain . --json > supply-chain.json
    - python3 .opencode/skills/jankhunt42/scripts/jankhunt scan . --html > jankhunt.html
    - python3 .opencode/skills/jankhunt42/scripts/jankhunt review . --base "$CI_MERGE_REQUEST_DIFF_BASE_SHA" --fail-on major
    - python3 .opencode/skills/jankhunt42/scripts/jankhunt scan . --fail-on critical
  artifacts:
    when: always
    paths: [jankhunt.json, review.json, supply-chain.json, jankhunt.html]
```

SARIF works with GitHub code scanning, GitLab SAST ingestion, and most Sonar-style dashboards that accept SARIF 2.1.0.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran successfully; no finding met `--fail-on`, no review/supply-chain gate failed, and `--fail-policy` was not tripped |
| `1` | A finding met `--fail-on`, a review/supply-chain requirement failed, a confirmed finding met `merge --fail-on`, or `score --fail-policy` saw policy `fail` |
| `2` | Usage error, unreadable input, or a diff/reference that cannot be resolved |
| `130` | Interrupted |

## Architecture

```text
jankhunt42/
├── SKILL.md                 # OpenCode doctrine + workflow
├── README.md
├── LICENSE
├── CHANGELOG.md
├── references/
│   ├── method.md            # evidence-driven debugging method
│   ├── playbooks.md         # stack/domain playbooks
│   ├── toolbox.md           # copy-paste commands
│   ├── scoring.md           # Jank Score 2.0 philosophy and formula
│   ├── review.md            # diff review, receipts, baselines, coverage
│   ├── supply-chain.md      # SBOM/attestation evidence and trust boundaries
│   └── deep-hunt.md         # adversarial panel protocol
├── templates/
│   ├── report.md            # investigation report template
│   ├── hunt-report.md       # deep-hunt report template
│   ├── panel-finding.json   # panelist output contract
│   └── review-receipt.schema.json  # receipt JSON Schema
└── scripts/
    ├── jankhunt             # CLI entry point (stdlib only)
    ├── jh_core.py           # types, file discovery, language detection, sanitizer
    ├── jh_rules.py          # rule catalog + pattern engine
    ├── jh_checks.py         # structural/multi-line checks
    ├── jh_triage.py         # log parsing and clustering
    ├── jh_doctor.py         # project/system diagnostics
    ├── jh_cve.py            # manifest parsers + OSV client
    ├── jh_score.py          # Jank Score 2.0 + new-code diff
    ├── jh_review.py         # diff scope, receipts, baselines, review renderers
    ├── jh_supply.py         # SBOM, attestation, and JFrog evidence parsers
    ├── jh_hunt.py           # deep-hunt planner, prompts, consensus merger
    ├── jh_render.py         # TTY and Markdown renderers
    ├── jh_html.py           # self-contained HTML scan report
    └── selftest.sh          # offline regression fixture
```

The scanner is read-only. It does not install packages, modify the repo, or call external services unless `--cve` is passed. `review` and `supply-chain` are read-only too: review runs git diff/show commands and reads the target tree; supply-chain reads evidence files on disk and never contacts GitHub, Sigstore, JFrog, or a registry. File discovery uses `git ls-files` when available and otherwise walks the tree with conservative ignores (`.git`, `node_modules`, `vendor`, build output, generated/minified files, lockfiles for static rules).

## Development

```sh
cd jankhunt42/scripts
python3 -m py_compile jh_core.py jh_rules.py jh_checks.py jh_triage.py jh_doctor.py jh_cve.py jh_score.py jh_review.py jh_supply.py jh_hunt.py jh_render.py jh_html.py jankhunt
./selftest.sh
```

The self-test builds temporary fixtures covering Python, CI, Kubernetes, Docker, tests, secrets, logs, git review modes, baselines, SBOMs, attestations, and JFrog evidence. It asserts that representative rules fire, that secrets are redacted, that JSON/SARIF parse, that the HTML report is parseable, self-contained, and escaped, that Jank Score 2.0 and the new-code view work, that review separates new/contextual/unchanged findings and gates only new baseline findings, that supply-chain evidence gets honest verification labels, that log clusters merge volatile values, and that hunt/merge preserve conflicts and dissent while downgrading unsupported `confirmed` claims. It does not require network.

When adding a rule:

1. Add it to `RULES` in `jh_rules.py` with a unique `JHxxx` ID, severity, category, confidence, message, and fix.
2. Prefer a line pattern; use a `check=` function in `jh_checks.py` for multi-line/structural logic.
3. Add a fixture case to `selftest.sh`.
4. Run the self-scan (`jankhunt scan scripts`) and the fixture.
5. Update `README.md` if the rule introduces a new category.

## Limitations and false positives

- Heuristics, not semantic analysis. Regex rules can miss data flow and can fire on examples, generated code, or documentation.
- Language coverage is uneven: Python/JS/TS/Go/Java/C-family are strongest; other languages get generic checks.
- Kubernetes rules inspect YAML text, not the rendered Helm chart or live cluster. `kubectl diff`/`kubeconform`/policy engines are still required.
- CI rules see static workflow text; expressions and reusable workflows can change behavior at runtime.
- Lockfile-based CVE checks only see pinned versions; ranges are skipped.
- `doctor --system` is Linux-centric. On macOS/Windows, some probes are skipped.
- The Jank Score 2.0 is a prioritization heuristic, not a vulnerability count, coverage percentage, or compliance certificate. Its dimension scores are not comparable across repositories with different rule sets or scan flags.
- `review` is a static pre-pass: it does not run tests, execute code, infer full data flow, or re-review unchanged files. A receipt is a reason to investigate, not a verdict. Baseline matching uses stable rule/path/evidence fingerprints, not semantic identity across refactors. The new-code score density includes added lines from every reviewed file; a very large data/evidence file can dilute it.
- `review --pr` requires `gh` and a checked-out PR head; it does not fetch or merge a remote branch itself. Binary files, generated paths, excluded globs, oversized files, and files beyond `--max-files` are listed as skipped rather than silently ignored.
- Supply-chain parsing does not verify cryptography, transparency logs, certificate chains, artifact-to-source binding, SBOM completeness, or license policy. `provider-verified` is the exporter's recorded result. Use `gh attestation verify`, `cosign verify-attestation`, or `jf evd verify` in trusted CI when independent verification is required.
- Deep hunt quality depends on the host's subagent support and the panelists' evidence discipline. A unanimous panel is not proof; only a repro or direct runtime evidence is `confirmed`.

If a finding is wrong, confirm it in context, then suppress it with a reason or improve the rule. A scanner that cries wolf is worse than no scanner.

## Publishing checklist

- [ ] `SKILL.md` frontmatter has name, description, license, compatibility, and metadata.
- [ ] Version synchronized in `SKILL.md`, `jh_core.py`, `README.md`, and `CHANGELOG.md`.
- [ ] `LICENSE` present.
- [ ] `scripts/selftest.sh` passes on a clean checkout.
- [ ] No `__pycache__`, `.pyc`, secrets, generated reports, or private user prompt text committed.
- [ ] README commands verified from a different working directory.
- [ ] `references/scoring.md`, `references/review.md`, `references/supply-chain.md`, and `references/deep-hunt.md` are linked from `SKILL.md`.
- [ ] The receipt schema and review/supply-chain docs are included in the release archive.
- [ ] `git status` is clean, the tag matches `0.2.0`, and the release archive is rebuilt from the clean tree.
- [ ] Tag the release and publish the folder/repo. If using an OpenCode skill catalog, point it at `SKILL.md`; keep `scripts/`, `references/`, and `templates/` alongside it.

## License

MIT. See `LICENSE`.

---

Built for people who would rather read one causal chain than ten dashboards.
