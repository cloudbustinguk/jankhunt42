# jankhunt42

<p align="center">
  <img src="assets/jankhunt42.png" alt="jankhunt42 logo: a grinning, bearded hacker hunched over a green-backlit keyboard, with the jankhunt42 wordmark beneath" width="320">
</p>

**Find the jank before it finds production, then work out what it can hurt and whether you can ship it.**

jankhunt42 is a local-first investigation and assurance toolkit: an [Agent Skill](https://skills-hub.ai/skill-md) (the open `SKILL.md` standard) for Claude Code, Cursor, Codex CLI, and OpenCode, plus a standalone CLI that needs nothing but Python 3.9+. No packages, no service, no telemetry, no network unless you ask for it (`scan --cve`, `--verify … --online`).

**Version:** 2.3.0 · **License:** MIT · **Runtime:** Python 3.9+ · stdlib only

## Three questions

| Question | Command | What you get |
|---|---|---|
| **What's broken?** | `scan`, `score`, `review`, `triage`, `doctor`, `hunt` | Evidence-backed leads across code, CI, Kubernetes, containers, secrets and dependencies; Jank Score 2.0; diff review with receipts and baselines; log clustering; an opt-in adversarial deep hunt |
| **What can it hurt?** | `map`, `map --base REF` | A typed connectivity graph (apps, workloads, identities, databases, APIs, storage, queues, external services) with a receipt per edge, confidentiality/integrity/availability blast radius, trust-boundary crossings, explicit unknowns, and a graph diff |
| **Can we responsibly ship it?** | `passport` | A software passport linking ownership, provenance, data sources, operations evidence, the Jank Score and the exposure class to an explainable `pass` / `review` / `insufficient-evidence` / `block` decision |

Each answer keeps its own evidence model. A Jank Score is not an exposure class, and neither is a release decision. A scanner lead is not a confirmed defect, a graph path is not proven access, and a passport is not an approval.

## Citizen developers and AI agents

People who are not software engineers now build and ship software with AI coding agents. That software inherits their credentials, the tools their agent is wired to, and their access to production data, so its blast radius is real even when nobody on the team has read the code. jankhunt42 governs it in three offline steps:

```sh
jankhunt42 scan . --category agent          # what an agent would do when it opens or works in this repository
jankhunt42 map .                            # what the software and its agent's MCP servers can reach
jankhunt42 passport . --profile citizen     # a strict release decision, explained in plain terms
```

- **Agent workspace checks** (`JH701`-`JH708`): approval bypasses committed in VS Code, Claude Code, Codex, or Zed settings; folder-open tasks, project hooks, and API base-URL overrides; agent CLIs run with permission-bypass flags; MCP servers launched from unpinned packages, holding literal credentials, or reached over plaintext HTTP; hidden HTML-comment instructions, "do not tell the user", and credential exfiltration in agent instruction files; issue and PR text fed to AI steps in CI.
- **Mistakes AI-built apps make** (`JH131`-`JH134`): secrets behind `NEXT_PUBLIC_`/`VITE_`-style prefixes (including Supabase `service_role` keys), `dangerouslyAllowBrowser` LLM clients, open Firebase rules, disabled row-level security, write policies `USING (true)`, public buckets, and invisible Unicode (tag characters are decoded for the reviewer).
- **The agent's blast radius:** `map` turns MCP server definitions into an AI-agent principal with edges to each server, the endpoints it is pointed at, and the credentials it holds (by name only). An agent whose database server points at production is High exposure, exactly like code with the same reach.
- **The citizen profile** blocks a release without an owner, a named engineering **custodian**, observed tests and CI, and declared data classification; on public exposure or agent-guardrail leads; above Moderate exposure; and on authority over production or restricted data that nobody has verified. The passport leads with a plain-language brief, and an acceptance record must be signed by a named custodian.

The profile is a governance choice made by an operator (`--profile citizen`, or `"profile": "citizen"` in an operator policy) or declared by the repository (`passport.profile`), never a guess about who wrote the code, and the repository can opt in but never out. Details, the incidents these checks map to, and limits: [`references/citizen.md`](references/citizen.md).

## 60-second quick start

```sh
git clone https://github.com/cloudbustinguk/jankhunt42.git ~/.config/opencode/skills/jankhunt42
alias jankhunt42="python3 ~/.config/opencode/skills/jankhunt42/scripts/jankhunt42"

cd your-repo
jankhunt42 scan .                  # what's broken?
jankhunt42 map .                   # what can it hurt?
jankhunt42 passport .              # can we responsibly ship it?
jankhunt42 map . --html > map.html # the blast radius explorer, offline
```

An interactive terminal gets the rich views, in the same colours as the HTML views (exact with `COLORTERM=truecolor`, the nearest 256-colour match otherwise, and the light palette when `COLORFGBG` reports a light background). Pipes get clean Markdown, and `NO_COLOR` or `TERM=dumb` turn colour off. `--json` gives versioned machine output, and `--html` gives one self-contained file.

## Example: the synthetic demo repository

Everything below is real output from the checked-in synthetic fixture `tests/fixtures/demo-app`. It is a fictional payments service with a Postgres ledger, a Redis cache, an S3 report export, an LLM call, a Kubernetes deployment, a GitHub Actions deploy workflow, and some Terraform. The test suite regenerates this output and fails if the README drifts from it.

`jankhunt42 map tests/fixtures/demo-app` at 100 columns:

<!-- sample:map-100 -->
```text
╭────────────────────────────────────────────────────────────────────────────────────────────────╮
│   J A N K H U N T 4 2   // blast radius explorer                                               │
│ demo-app  ·  working-tree  ·  19 nodes  ·  19 edges                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

╭─ what can it hurt? ────────────────────────────────────────────────────────────────────────────╮
│ EXPOSURE              High  qualitative; a path is a possibility, not proof                    │
│ evidence coverage     complete-for-supported-types  (11/13 files, 8 adapters)                  │
│ edge evidence         0 [verified]  17 [supported]  2 [inferred]  0 [unknown]                  │
│ reach                 0 known [verified]  ·  37 potential  ·  7 unknown-capability             │
│ breadth               1.264 over 4 trust domains (informational, never blocks)                 │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

connected systems
  2 api   1 application   3 database   3 external   5 identity   1 storage   1 unknown   3 workload

trust-boundary crossings
  internal→external

highest-impact admissible paths
  High integrity [supported] X-HIGH-AUTH
    possible mutating/destructive authority over a production, critical, or sensitive asset
    demo-app -[deletes/delete, observed]→ postgresql ledger-db.prod.internal
  High availability [supported] X-HIGH-AUTH
    possible mutating/destructive authority over a production, critical, or sensitive asset
    demo-app -[deletes/delete, observed]→ postgresql ledger-db.prod.internal
  High confidentiality [supported] X-HIGH-EGRESS
    sensitive source and external destination are reachable from the same principal (possible
    egress path; no data-flow evidence implied)
    demo-app -[reads/read, observed]→ postgresql ledger-db.prod.internal
  High integrity [supported] X-HIGH-AUTH
    possible mutating/destructive authority over a production, critical, or sensitive asset
    demo-app -[writes/write, observed]→ s3 bucket demo-reports-prod
  High confidentiality [supported] X-HIGH-READ
    supported read reach to restricted data
    k8s Deployment payments-prod/payments-api -[authenticates-as/unknown, declared]→ k8s service
      account payments-prod/payments-api -[reads/read, declared]→ kubernetes secrets
      (cluster)

unknowns  (unknown is not safe, and not dangerous)
  ? effective-privileges: effective grants are not verified for 19 edge(s); static evidence
      cannot prove privileges
  ? unresolved-targets: 1 endpoint(s) are resolved only at runtime (environment, secrets, or SDK
      defaults)
  ? unknown-capability: 7 connection(s) have unknown capability; treated as possibly read,
      write, or destructive
  ? data-classification: 6 asset(s) have no declared data sensitivity
  ? environment: 7 asset(s) have unknown environment (production vs non-production)
  ? code-to-workload-binding: which workload runs the repository code is not inferred; declare
      it with passport.bindings if needed
  ? runtime-reachability: static analysis only: network reachability, firewalls, and live data
      movement were not tested

  explore: jankhunt42 map . --html > map.html   ·   data: --json   ·   shareable: --redact
```
<!-- /sample -->

`jankhunt42 passport tests/fixtures/demo-app` at 100 columns:

<!-- sample:passport-100 -->
```text
╭────────────────────────────────────────────────────────────────────────────────────────────────╮
│   J A N K H U N T 4 2   // software passport                                                   │
│ demo-app  ·  revision unknown                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

╭─ can we responsibly ship it? ──────────────────────────────────────────────────────────────────╮
│ RELEASE ASSESSMENT    REVIEW  advisory                                                         │
│ technical jank score  67/100  grade E  policy fail                                             │
│ exposure              High  separate from the Jank Score                                       │
│ evidence coverage     4/9 areas observed, declared, or inferred                                │
│ lifecycle             assessed  ·  acceptance [not-supplied]                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

why  (rule outcomes, not a weighted score)
  REVIEW P-DAT-002 possible mutating, destructive, or unknown authority over a production,
      critical, or restricted asset; verify effective grants
  REVIEW P-JNK-001 Jank Score policy fail; 0 blocker-severity lead(s) (leads, not confirmed
      defects)

evidence
  ownership [observed]   provenance [not-observed]   data inventory [observed]   ci [observed]
  tests [not-observed]   observability [not-observed]   health checks [observed]
  runbook [not-observed]   security policy [not-observed]
  owners: @demo-org/payments-team

next steps
  1. Verify effective grants for the flagged connections and scope them to least privilege;
     record the result in an operator inventory to turn leads into verified evidence.
  2. Work down the weakest Jank Score dimension first (`jankhunt42 score`), then the
     highest-severity leads (`jankhunt42 scan --min-severity critical`).
  3. Add or declare observability evidence (currently not observed).
  4. Add or declare runbook evidence (currently not observed).
  5. Generate an SBOM and build provenance for released artifacts.

  export: jankhunt42 passport . --json | --html > passport.html   ·   shareable: --redact
```
<!-- /sample -->

Read it the way the tool means it:

- The exposure is **High** because of *possible* destructive authority: an observed `DELETE` statement against a database declared `restricted`/`critical`. The edge is `observed`, not `verified`, which is why the reach reads "0 known".
- The decision is **review**, not **block**. Static leads ask for grant verification; they never block on their own.
- The co-reachability of the restricted ledger and an external endpoint raises exposure, but it is reported as a *possible* egress path, not a data flow.
- Runbook and observability are **not-observed**, which means unknown, not absent.

### The HTML views

The same fixture with `--html`: each view is one self-contained, offline file (no external assets, a no-network content security policy, everything escaped). These are screenshots of real output in the dark theme; unlike the text samples above, the test suite does not regenerate them.

`jankhunt42 map tests/fixtures/demo-app --html` is the blast radius explorer. Here it is opened with the deep link `#principal=application:4be897baf0fc1700&impact=integrity&select=database:a497c14ce27e2ace`: the magenta paths are everything the application could modify, dashed where the evidence is only inferred, and the inspector shows the selected ledger database with its sanitized evidence receipt.

![The jankhunt42 blast radius explorer: summary cards (exposure High, 19 nodes and edges, 7 unknown capabilities), then the connectivity graph with the application's integrity blast radius highlighted in magenta towards the ledger database, an S3 bucket, a Redis cache and external endpoints, and an inspector panel describing the restricted, critical production ledger database](assets/readme/blast-radius-explorer.png)

`jankhunt42 passport tests/fixtures/demo-app --html` is the software passport: the decision, the rules that produced it, and the evidence behind each area. It is printable.

![The jankhunt42 software passport: release assessment review, Jank Score 67/100 grade E, exposure High, evidence coverage 4 of 9, lifecycle assessed, followed by the two review reasons and the table of every rule with its outcome](assets/readme/software-passport.png)

`jankhunt42 passport . --profile citizen --html` on a small synthetic app built the way AI app builders do: a Supabase and OpenAI front end, a Cursor MCP config whose unpinned database server points at a production host, and VS Code agent auto-approve. It was generated in a scratch directory for this screenshot and is not checked in, because its agent settings are deliberately unsafe; the test suite builds the same kind of app at test time.

![The jankhunt42 citizen-profile passport: release assessment block, profile citizen with no custodian named, exposure High, then an "in plain terms" brief listing eight blocking reasons in plain language, what the software and its AI agent set-up can reach (including an unpinned database tool server reaching a production host), and the first rule reasons](assets/readme/citizen-passport.png)

`jankhunt42 scan tests/fixtures/demo-app --html` is the scan report: the Jank Score, the severity mix, the four-dimension scorecard, hot spots, and every finding with its evidence.

![The jankhunt42 scan report: Jank Score 67 out of 100, grade E, labelled biohazard with a policy fail and Security as the weakest dimension, severity counts, and a scorecard for security, reliability, maintainability and test confidence](assets/readme/scan-report.png)

## The evidence model

| State | Meaning |
|---|---|
| `observed` | The repository directly contains it: a literal endpoint, an SQL verb in a string, an HTTP call |
| `declared` | Configuration or a manifest says so: env values, Kubernetes RBAC, workflow `permissions:`, `.jankhunt42.json` declarations |
| `inferred` | A heuristic: an SDK import, a manifest dependency, an endpoint resolved by environment-variable name |
| `provider-verified` / `verified` | From an operator-supplied inventory **outside** the repository, or an exporter-recorded attestation verification. jankhunt42 itself verifies no signatures |
| `unknown` | Not established. Never treated as safe, never as proven dangerous |
| `refuted` / `disproven` | Explicitly refuted by a trusted operator inventory, and excluded |

Terminal, HTML, JSON, the skill, and this README all use the same words. Paths take the strength of their weakest edge. "Known" reach means verified; everything else is potential.

## What can it hurt? `map`

```sh
jankhunt42 map .                              # exposure, coverage, crossings, top paths, unknowns
jankhunt42 map . --json                       # jankhunt.map.v1 (templates/map.schema.json)
jankhunt42 map . --html > map.html            # blast radius explorer
jankhunt42 map . --base HEAD~1 --json         # graph delta from committed git objects only
jankhunt42 map . --redact --json              # shareable: pseudonymous IDs, no hosts or snippets
jankhunt42 map . --inventory ../inventory.json # operator inventory: classifications and verified grants
jankhunt42 map . --what-if ../scenario.json    # hypothetical: revoke, block egress, compromise an identity
jankhunt42 map . --drift ../stored-map.json    # stored map vs the current repository
jankhunt42 map . --mermaid > map.mmd           # Mermaid flowchart for docs
jankhunt42 map . --csv map-csv                 # nodes.csv + edges.csv (formula-injection safe)
```

**Discovery** is offline and static. It reads Python, JavaScript/TypeScript and .NET code; `.env`, config and appsettings files; Kubernetes workloads and RBAC; docker-compose; GitHub Actions permissions and cloud logins; Terraform data stores and privileged role grants; MCP server definitions for coding agents (Claude Code, Cursor, VS Code, Gemini CLI, Codex, opencode, Claude Desktop); and dependency manifests (as weak evidence). Hosted data services such as Supabase, Firebase, Neon, Upstash, Airtable, and Google Sheets count as data stores. Secret references are recorded by name and never dereferenced. Dynamic endpoints become explicit unresolved targets rather than invented hosts.

**Blast radius** walks each principal's admissible edges separately for confidentiality, integrity and availability. It uses a bounded, deterministic traversal with witness paths, and every reachable asset is counted once. Unknown capability counts as *possibly* anything, never read-only. An independent brute-force oracle checks the traversal on thousands of seeded graphs.

**Exposure** is one qualitative class: Low, Moderate, High, Critical, or Unknown. Its rules are monotone, so more authority, sensitivity or reach can never lower it. There is no probabilistic score and no claim of exploitability.

**The HTML explorer** is one file with a `default-src 'none'` Content-Security-Policy, so it makes no requests. It has:

- a column graph with pan, zoom and keyboard navigation;
- an inspector that shows every node and edge with its receipts (`file:line`, adapter, sanitized snippet, assumptions);
- filters by kind and minimum evidence, a search box, an unknowns overlay, and a per-principal confidentiality/integrity/availability highlight with witness paths;
- a coverage and unknowns tab, an edges table (shown first for graphs over 300 nodes), and a graph-delta tab for `--base`.

**What-if** (`--what-if scenario.json`) applies hypothetical mutations to a copy of the graph and reports the resulting delta: revoke, remove, add, set capability, block egress, compromise an identity. **Drift** (`--drift`) compares a stored map with the current tree. **Bindings** in `.jankhunt42.json` declare which workload runs the repository code. Trusted operator inventories may weight edges, giving a heuristic **path strength** that orders paths but never changes a class. OpenAPI documents enrich API nodes without inventing calls.

**`--base REF`** builds both sides from committed git objects only. Dirty or untracked files cannot contaminate the diff. It reports new and removed edges, permission escalations, newly reachable sensitive assets, trust-boundary changes, and coverage regression.

Semantics, adapters, inventory format, and limits: [`references/connectivity.md`](references/connectivity.md).

## Can we responsibly ship it? `passport`

```sh
jankhunt42 passport .                          # decision, reasons, evidence areas, next steps
jankhunt42 passport . --json                   # jankhunt.passport.v1 (templates/passport.schema.json)
jankhunt42 passport . --html > passport.html   # printable, offline
jankhunt42 passport . --policy ../policy.json  # operator policy (outside the repo)
jankhunt42 passport . --fail-on block          # opt-in enforcement: exit 1 at or above block
jankhunt42 passport . --profile citizen        # strict governance for software built by non-engineers
jankhunt42 passport . --compare ../old-passport.json      # regressions since a stored passport
jankhunt42 passport . --acceptance ../acceptance.json     # operator acceptance record, bound to revision + policy
```

The decision is the most severe of twelve named rules. These cover coverage (a hard floor), owner, engineering custodian, sensitive external export, production authority, data classification, public exposure, agent guardrails, tests and CI, mandatory supply-chain evidence, the Jank Score policy, and maximum exposure. It is never a weighted average, and `insufficient-evidence` can never become `pass`. Under the default `standard` profile, the custodian, classification, and tests/CI rules apply only when a policy requires them, and static leads ask for review rather than block; the `citizen` profile requires all of them and blocks.

Policy precedence is defaults < operator `--policy` (outside the repository) < hard floors. Repository config (`passport.policy`, or a `--policy` file inside the repo) can only tighten.

Lifecycle is `draft`, `assessed`, or `accepted`. `accepted` requires an operator acceptance record from outside the repository, bound to the exact revision, policy hash, decision, and (optionally) artifact digest and environment. Any change invalidates it with named reasons, and a `block` or `insufficient-evidence` decision can never be accepted. `--compare` reports regressions between passports, with a self-consistency integrity check (not a signature).

Rules, precedence, declarations, and schema: [`references/passport.md`](references/passport.md).

## What's broken? Investigation

These are the established 1.x capabilities, unchanged in behaviour and machine output.

### Scan and score

```sh
jankhunt42 scan .                       # TTY "code autopsy"; Markdown when piped
jankhunt42 scan . --json                # full machine report
jankhunt42 scan . --sarif > jank.sarif  # SARIF 2.1.0 for code scanning
jankhunt42 scan . --html > jankhunt42.html
jankhunt42 scan . --fail-on critical    # explicit CI gate
jankhunt42 scan . --since HEAD          # whole-tree plus new-code score
jankhunt42 score . --json               # Jank Score 2.0 breakdown
jankhunt42 rules --category security    # the rule catalog
```

There are 96 static rules. They cover:

- secrets and credentials, including registry and AI-provider token formats;
- AI-agent workspaces and citizen-built apps (above);
- injection, unsafe deserialization and archives, and crypto/TLS/JWT/CORS mistakes;
- swallowed errors, missing timeouts, blocking calls in async code;
- complexity, and test hygiene;
- Docker and Compose, Kubernetes security context, GitHub Actions and GitLab CI pitfalls (including `toJSON(secrets)`, `secrets: inherit`, and checkouts of untrusted pull-request code that bypass `actions/checkout`'s protection);
- dependency confusion through pip extra indexes, and Dependabot without a cooldown or with external code execution;
- lockfiles, unpinned dependencies, and broken Markdown links.

`scan --cve` adds OSV.dev advisories. It is opt-in, and only package name, version and ecosystem leave the machine.

**Jank Score 2.0** is a transparent prioritization device with four dimensions (security, reliability, maintainability, tests) and A-E grades. Its headline is anchored to the worst dimension, so a security problem cannot be averaged away:

```text
points    = severity_weight × confidence_factor × exposure_factor
dimension = max(100 × (1 − e^(−points_per_KLOC / K)), severity_floor)
headline  = round(0.70 × worst_dimension + 0.30 × weighted_average)
```

The arithmetic is unchanged in 2.0. Details: [`references/scoring.md`](references/scoring.md).

### Review a diff

```sh
jankhunt42 review . --json                          # working tree, staged, untracked
jankhunt42 review . --base HEAD~1 --json            # committed changes; scans HEAD, never a dirty tree
jankhunt42 review . --staged --md
jankhunt42 review . --commit HEAD --brief           # handoff for a semantic reviewer
jankhunt42 review . --base HEAD~1 --save-baseline baseline.json --json
jankhunt42 review . --base HEAD~1 --baseline baseline.json --fail-on major
```

`review` is the deterministic evidence layer. It provides exact scope, separates new lines from context, and emits receipts with hashes, repro commands and counterevidence, plus coverage, baselines and supply-chain context. A receipt is `supported` or `unverified`, never `confirmed` without a repro. Protocol: [`references/review.md`](references/review.md).

### Supply chain, logs, environment, reports

```sh
jankhunt42 supply-chain . --json                    # SPDX/CycloneDX, in-toto/Sigstore/GitHub, JFrog AppTrust
jankhunt42 supply-chain . --require-sbom
jankhunt42 supply-chain . --verify ../verify-plan.json        # run gh/cosign/jf; offline with a bundle + trusted root
jankhunt42 supply-chain . --verify ../verify-plan.json --online   # also fetch from GitHub (attestations, Actions artifacts)
jankhunt42 triage app.log --top 25                  # fingerprint and rank log clusters
jankhunt42 doctor --system                          # repo and host health
jankhunt42 report . --logs app.log --out report.md  # scan + doctor + logs
```

Supply-chain parsing is offline. `provider-verified` means the exporter recorded a verification. jankhunt42 never checks a signature itself: `--verify PLAN` runs the native verifiers (`gh attestation verify`, `cosign verify-blob-attestation`, `jf evd verify`) against a plan kept outside the repository that names the signer to trust, and records `tool-verified`, `signature-only`, `failed` or `not-run`. Without `--online` nothing is fetched and a verifier runs only if it can verify offline; with `--online`, bundles can be fetched from the GitHub attestations API and SBOMs from Actions artifacts (which need a token and are unsigned). See [`references/supply-chain.md`](references/supply-chain.md).

### Deep hunt (opt-in)

```sh
jankhunt42 hunt . --focus security --panel 6 --json > hunt.json
jankhunt42 merge panel-*.json --md
```

A deep hunt is a structured adversarial panel: independent roles, cross-examination, and an evidence-weighted consensus that preserves dissent. In the skill it runs only when the user explicitly says "deep hunt". `confirmed` requires a repro or runtime evidence. Protocol: [`references/deep-hunt.md`](references/deep-hunt.md).

## Configuration, privacy, and security

**`.jankhunt42.json`** (or `.toml` on Python 3.11+) is discovered upward from the scan root. It tunes rules, severities, path scopes and ignores for `scan`, `score` and `hunt`. Its `passport` section holds repository declarations: owners, asset sensitivity and criticality, operations evidence, and tighten-only policy.

```json
{
  "rules": {"JH205": {"enabled": false}},
  "paths": {"legacy/**": {"severity": {"JH101": "info"}}},
  "ignore": ["vendor/**"],
  "passport": {
    "owners": ["@example-org/payments"],
    "assets": [{"match": "ledger-db", "sensitivity": "restricted", "criticality": "critical"}],
    "policy": {"require": {"owner": true}}
  }
}
```

- **Suppressions:** add `# jankhunt42: ignore JH201` inline, with a reason, for a confirmed false positive only. A file-level `# jankhunt42: ignore-file JH305` goes in the first 12 lines. The pre-0.4 `jankhunt:` prefix is still honoured.
- **Calibration:** `scan --calibrate` maintains `.jankhunt42/calibration.json` and downgrades rules that this repository consistently suppresses. It is opt-in, and with `--cve` it is one of only two flags that write or send anything.
- **Offline by default:** only two opt-ins reach a network. `scan --cve` sends package names and versions to OSV.dev. `--verify … --online` sends the repository name and artifact digests to the GitHub API and lets `gh`/`cosign`/`jf` go online. `map` and `passport` never resolve, probe, or connect to anything they find.
- **Redaction:** credentials, URL userinfo, query strings and paths, connection-string secrets, keys, tokens and emails are removed before anything is hashed, displayed or stored. Repository control characters are neutralized before they reach a terminal. HTML output escapes everything and runs under a no-network CSP.
- **Sensitive architecture:** a connectivity graph can reveal internal topology. Use `--redact` for anything you share. Generated artifacts contain relative paths only.
- **Untrusted repositories:** jankhunt42 never executes repository code or scripts. Instructions embedded in repository content are data, not commands.

## Install as an agent skill

jankhunt42 is one `SKILL.md` directory. Put it where your tool already looks for skills:

| Tool | Project scope | User scope |
| --- | --- | --- |
| Claude Code | `.claude/skills/jankhunt42/` | `~/.claude/skills/jankhunt42/` |
| Cursor | `.cursor/skills/jankhunt42/` | — |
| Codex CLI | `.codex/skills/jankhunt42/` (also reads `.agents/skills/`) | `~/.codex/skills/jankhunt42/` |
| OpenCode | `.opencode/skills/jankhunt42/` (also reads `.claude/skills/`, `.agents/skills/`) | `~/.config/opencode/skills/jankhunt42/` |

The skill routes debugging and scanning requests, mapping/exposure/blast-radius requests, and passport/release-readiness requests to the matching command and reference. It never starts a deep hunt without explicit permission.

The listing on [skills-hub.ai](https://skills-hub.ai/skills/jankhunt42) carries the `SKILL.md` instructions only. Clone the repository to get the CLI.

### Verifying a release

Every `vX.Y.Z` tag is built into a source tarball and attested in CI with a [GitHub Artifact Attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) (keyless Sigstore, tied to this repository's Actions identity; see `.github/workflows/provenance.yml`):

```sh
gh attestation verify jankhunt42-<version>.tar.gz -R cloudbustinguk/jankhunt42
```

This confirms that the tarball came from this repository's CI at the tagged commit. It says nothing about any marketplace's review.

## CI integration

```yaml
name: jankhunt42
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  assure:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v7   # pin to a SHA in production
        with:
          fetch-depth: 0
          persist-credentials: false
      - uses: actions/setup-python@v6
        with:
          python-version: "3.12"
      - run: python3 .opencode/skills/jankhunt42/scripts/jankhunt42 scan . --sarif > jankhunt42.sarif
      - run: python3 .opencode/skills/jankhunt42/scripts/jankhunt42 map . --json > map.json
      - name: What changed in what it can reach
        if: github.event_name == 'pull_request'
        run: python3 .opencode/skills/jankhunt42/scripts/jankhunt42 map . --base "${{ github.event.pull_request.base.sha }}" --md >> "$GITHUB_STEP_SUMMARY"
      - name: Passport (enforced; add --profile citizen for software built by non-engineers)
        run: python3 .opencode/skills/jankhunt42/scripts/jankhunt42 passport . --json --fail-on block > passport.json
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: jankhunt42.sarif
```

Keep enforcement explicit. `scan --fail-on SEV`, `review --fail-on SEV` with a baseline, and `passport --fail-on OUTCOME` are the gates; everything else is advisory. GitLab CI works the same way, since every command is plain `python3`.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran successfully and no explicit gate tripped (`map` and an advisory `passport` always exit 0) |
| `1` | A gate tripped: `scan`/`review --fail-on`, a supply-chain requirement, `merge --fail-on`, `score --fail-policy`, `passport --fail-on`, or a failing `selftest` |
| `2` | Usage error, unreadable input, unresolvable git ref, or invalid inventory/policy file |
| `130` | Interrupted |

## Self-assurance

```sh
jankhunt42 selftest           # the unit suite
jankhunt42 selftest --full    # everything below, with a pass/fail/insufficient-evidence gate
```

`selftest --full` runs:

- the unittest suite: an independent reference oracle for reachability, metamorphic and monotonicity properties, adapter fixtures, policy precedence, `--base` isolation, seeded fuzzing, golden terminal snapshots, schema checks, and cross-version compatibility against the previous local release tag;
- the end-to-end shell regression suite;
- a self-map compared with a hand-maintained ground truth;
- a self-scan and self-passport, reported but never self-approving;
- sixteen mutants that the tests must kill, each with an unmutated control;
- a privacy scan of shipped files and generated artifacts;
- a stdlib byte-compile of every script, plus ruff, pyflakes, bandit and shellcheck when they are already installed (never installed for you);
- the suite on locally cached Python 3.9 to 3.14 container images (every minor version), which are never pulled.

Python 3.9 is past its upstream end of life. It stays the minimum only because some systems still ship it as their `python3` (for example macOS Command Line Tools and RHEL 9); use a current Python where you can. TOML config needs 3.11+; JSON config works everywhere.

Missing optional tools are reported as `skip`, never as a pass. A perfect self-score is not evidence of correctness; the independent checks are.

## Architecture

```text
SKILL.md                 routing doctrine for agents (three questions, permission gates)
references/              method, playbooks, toolbox, scoring, review, supply-chain, deep-hunt,
                         connectivity (map), passport (passport, exposure, policy)
templates/               report templates; review-receipt, map, and passport JSON Schemas
scripts/jankhunt42       CLI entry point
scripts/jh_core.py       types, discovery, sanitizer, safe_text      scripts/jh_rules.py, jh_checks.py  scanner rules
scripts/jh_score.py      Jank Score 2.0                              scripts/jh_review.py   diff review and receipts
scripts/jh_supply.py     SBOM/attestation/JFrog parsers              scripts/jh_hunt.py     deep hunt and merge
scripts/jh_graph.py      graph model, sanitizing, reachability, exposure, diff, redaction
scripts/jh_map.py        discovery adapters, coverage, map views    scripts/jh_yaml.py     bounded YAML subset reader
scripts/jh_policy.py     passport rules, profiles, precedence       scripts/jh_passport.py passport assembly
scripts/jh_agent.py      MCP and agent workspace config parsing
scripts/jh_views.py      map/passport terminal views                scripts/jh_explorer.py offline HTML explorer
scripts/jh_selftest.py   self-assurance orchestrator                scripts/selftest.sh    shell regression suite
tests/                   unittest suite, oracle, fixtures (synthetic), golden snapshots
```

There is no circular dependency between scoring, the graph and the passport: they share only the canonical JSON shapes. `scan` never computes a passport.

## Migrating from 1.x

- Every 1.x command, flag, exit code, JSON field and SARIF field is unchanged. The compatibility suite runs the 1.1.0 release and 2.0 side by side on the demo fixture and requires identical `scan`/`score`/`rules` JSON and SARIF (ignoring only version, timing, and absolute-root fields).
- 2.1.0 adds options only (`map --what-if/--drift/--mermaid/--csv`, `passport --acceptance/--compare/--against`), plus `passport.bindings`. It also narrows `JH104`, which no longer flags parameterized `%s`/`%(name)s` placeholders; this removes findings and never adds them.
- 2.2.0 adds options only (`supply-chain --verify/--online/--fetch-dir`, `passport --verify/--online`) and additive fields (`key_source`, `origin`, `verification`). JFrog records whose key came from the Sigstore bundle now carry a warning; their state is unchanged.
- 2.3.0 adds 17 rules (`JH131`-`JH134`, `JH427`-`JH431`, `JH701`-`JH708`, with the new `agent` category), `passport --profile`, `passport.profile` and `passport.custodians`, five passport rules, an additive `governance` section, and the map's `mcp` adapter. Every older rule's catalog entry and every existing JSON and SARIF field is unchanged. Under the standard profile, `P-SEC-001` and `P-AGT-001` add `review` reasons when their leads appear. The effective policy gained keys, so the policy hash changed: acceptance records bound to an earlier hash must be re-issued. `JH502` no longer fires on unittest-style assertions or on assertions made in helper methods, and `JH401` no longer treats a CI workflow named `secrets.yml` as a credential file.
- New top-level commands: `map`, `passport`, `selftest`. The new payloads carry their own schema versions (`jankhunt.map.v1`, `jankhunt.passport.v1`).
- The product name is written `jankhunt42` everywhere, including the `SKILL.md` `name` and the human-readable Markdown and HTML titles (`# jankhunt42 scan`). If you grepped human output for the old capitalization, update the pattern; machine formats were already lowercase.
- Repository strings in terminal and Markdown output now have control and bidi characters replaced with `U+FFFD`, so a hostile repository cannot drive your terminal.

## Development

```sh
export PYTHONDONTWRITEBYTECODE=1              # selftest.sh rejects stray __pycache__ in the skill dir
python3 -m unittest discover -s tests         # fast suite
bash scripts/selftest.sh                       # end-to-end regression
python3 scripts/jankhunt42 selftest --full     # everything, with a gate
JH_UPDATE_SNAPSHOTS=1 python3 -m unittest discover -s tests -p test_terminal.py   # accept an intended view change
```

To add a rule, add it to `RULES` in `jh_rules.py` (or a `check=` in `jh_checks.py`), add a fixture case to `selftest.sh`, and run the self-scan. To add a map adapter, add it to `jh_map.py` with positive *and* negative fixtures in `tests/test_map.py`. Keep every claim's `verification` honest, and update `tests/fixtures/self-expected.json` by hand if this repository's own connectivity changes. Fixtures must be synthetic.

## Limitations

- **Heuristics:** findings and edges come from static text, not data flow or runtime observation. They can miss things and can fire on examples.
- **Agents:** agent-workspace rules read configuration text; they do not run the agent or its MCP servers, and agent settings change between versions. A server's tools, and what they can do, are not visible statically. The citizen profile governs the release decision; it is not a sandbox.
- **Map:** no Helm, Kustomize, HCL or variable evaluation. No live network, firewall or IAM evaluation. Which workload runs the repository code is not inferred; declare it with `passport.bindings`. Monorepos map as one application. `.sql` migrations and tests are not mapped. Mermaid output is not checked with a Mermaid renderer.
- **Effective privileges:** these are never proven from repository evidence. Verified authority needs an operator inventory, and jankhunt42 does not verify that inventory's own provenance.
- **Exposure and decisions:** these are explainable heuristics, not calibrated probabilities or compliance results. Adapter accuracy is measured only on this repository's synthetic fixtures and its own ground truth.
- **Supply chain:** parsing verifies no cryptography. Use `gh attestation verify`, `cosign` or `jf evd verify` in trusted CI.
- **Deep hunt:** quality depends on the host's subagents and the evidence discipline of its panel.
- **Calibration:** calibration is counting, not judgement. `.jankhunt42.json` rules do not yet apply to `review`.

If a finding is wrong, confirm it in context, then suppress it with a reason or improve the rule. A scanner that cries wolf is worse than no scanner.

## Publishing checklist

- [ ] `jankhunt42 selftest --full` gate is `pass` on a clean checkout.
- [ ] The version is synchronized in `SKILL.md`, `scripts/jh_core.py`, this README, and `CHANGELOG.md`.
- [ ] No `__pycache__`, generated reports, secrets, private prompts, or agent working files are committed.
- [ ] README and SKILL commands are exercised by `tests/test_docs.py`.
- [ ] The tag matches the version, and the release archive is built from the clean tree by `provenance.yml`.

## License

MIT. See `LICENSE`.

---

Built for people who would rather read one causal chain than ten dashboards.
