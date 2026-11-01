# jankhunt42

<p align="center">
  <img src="assets/jankhunt42.png" alt="jankhunt42 logo: a citizen developer, grinning wildly through a beard and glasses, hammers a keyboard so hard the keycaps fly off, while screens full of AI agent faces glow behind; the jankhunt42 wordmark beneath" width="320">
</p>

**People who are not software engineers now ship software with AI coding agents. jankhunt42 finds the jank before it finds production, works out what it can hurt, and helps decide whether it can ship.**

AI app builders and coding agents let anyone turn an idea into running software in an afternoon. That software inherits its builder's credentials, the tools their agent is wired to, and their access to production data, often without an engineer ever looking at it. jankhunt42 is the review that is missing. It reads a repository the way a security engineer would and explains what it finds in plain terms, both to the citizen developer who built it and to the team asked to approve it.

jankhunt42 is local-first. It is an [Agent Skill](https://skills-hub.ai/skill-md) for Claude Code, Cursor, Codex CLI and OpenCode, plus a standalone CLI that needs nothing but Python 3.9+. There are no packages, no service, no telemetry, and no network access unless you ask for it (`scan --cve`, `--verify … --online`, `sandbox --fetch`).

**Version:** 4.4.0 · **License:** MIT · **Runtime:** Python 3.9+ · stdlib only

## Three questions

| Question | Commands | What you get |
|---|---|---|
| **What's broken?** | `scan`, `review`, `supply-chain` | Evidence-backed leads across code, CI, Kubernetes, containers, secrets, dependencies, and AI-agent workspaces; Jank Score 2.0; diff review with receipts |
| **What can it hurt?** | `map`, `map --base REF` | A typed connectivity graph with a receipt per edge, covering apps, CI, Kubernetes, Terraform, n8n workflows, cloud data platforms (Azure, AWS, Google Cloud, Databricks, Snowflake) and cloud identities; confidentiality/integrity/availability blast radius; a credential blast radius per identity; trust-boundary crossings, explicit unknowns, and a graph diff |
| **Can we responsibly ship it?** | `passport`, `sandbox` | Ownership, provenance and SBOM quality, data sources, AI use, operations evidence, change control on the default branch, package sources, the Jank Score and the exposure class, joined in an explainable `pass` / `review` / `insufficient-evidence` / `block` decision; a pull-request gate recipe for citizen developers |

Each answer keeps its own evidence model:

- A Jank Score is not an exposure class, and neither is a release decision.
- A scanner lead is not a confirmed defect.
- A graph path is not proven access.
- A passport is not an approval.

## Quick start

```sh
git clone https://github.com/cloudbustinguk/jankhunt42.git ~/.config/opencode/skills/jankhunt42
alias jankhunt42="python3 ~/.config/opencode/skills/jankhunt42/scripts/jankhunt42"

cd your-repo
jankhunt42 scan .                  # what's broken?
jankhunt42 map .                   # what can it hurt?
jankhunt42 passport .              # can we responsibly ship it?
jankhunt42 map . --html > map.html # the blast radius explorer, offline
```

Output adapts to where it goes:

- **Interactive terminals** get the rich views, in the same colours as the HTML views. Colour is exact with `COLORTERM=truecolor`, and a light palette is used when `COLORFGBG` reports a light background.
- **Pipes** get clean Markdown. `NO_COLOR` or `TERM=dumb` turns colour off.
- **`--json`** gives versioned machine output.
- **`--html`** gives one self-contained, offline file.

## Citizen developers and AI agents

People who are not software engineers now build and ship software with AI coding agents. That software inherits their credentials, the tools their agent is wired to, and their access to production data. jankhunt42 governs it offline:

```sh
jankhunt42 scan . --category agent          # what an agent would do when it opens or works in this repository
jankhunt42 map .                            # what the software and its agent's MCP servers can reach
jankhunt42 passport . --profile citizen     # a strict release decision, explained in plain terms
jankhunt42 passport . --emit-sandbox-policy claude-code   # a least-privilege network fence for the agent (also codex, openshell)
jankhunt42 passport . --emit-sandbox-policy claude-code --sandbox-network-ceiling /etc/it/approved.json   # capped by IT's approved list
jankhunt42 sandbox .                    # opt-in: run the install hooks, the dependencies as they load, and what runs on open in a sandbox
jankhunt42 agent-fuzz validate campaign.json --json  # validate a campaign; does not run an agent yet
jankhunt42 agent-fuzz evaluate campaign.json observations.json --json  # score supplied observations; does not run an agent
jankhunt42 agent-fuzz evaluate campaign.json observations.json --html > report.html  # offline report; TTYs get a case summary
jankhunt42 passport . --base <ref> --md   # what new access this change asks for (for IT to approve)
jankhunt42 passport . --base <ref> --policy /etc/it/policy.json --emit-capability-approval   # an approval record for IT to fill in
```

- **Agent workspace checks** (`JH701`-`JH711`, `JH432`):
  - approval bypasses committed in VS Code, Claude Code, Codex, or Zed settings;
  - sandboxes that let agent commands reach any host, the Docker socket, or credential paths (Codex, Claude Code, OpenShell), and dev containers that weaken isolation;
  - CI that runs any pushed branch, an agent's included, with secrets or a write token;
  - commands that run on folder open, in dev containers, or in hooks;
  - agent CLIs started with bypass flags;
  - unpinned or credential-holding MCP servers;
  - hidden instructions in agent files;
  - untrusted issue and PR text fed to AI steps in CI.
- **Mistakes AI-built apps make** (`JH131`-`JH134`):
  - secrets behind `NEXT_PUBLIC_`/`VITE_`-style prefixes;
  - `dangerouslyAllowBrowser` LLM clients;
  - open Firebase rules, disabled row-level security, and public buckets;
  - invisible Unicode.
- **ASP.NET Core checks** (`JH135`-`JH143`): data endpoints without visible authorization, credentialed open CORS, developer errors, public HTTP listeners, interpolated SQL, unsafe type deserialization, personal fields sent to AI clients, floating NuGet versions and build downloads. See [the .NET guide](references/dotnet.md). The sandbox restores and builds hash-pinned NuGet packages offline in a separate SDK image.
- **The citizen profile** will not pass a release without:
  - an owner, and an engineering custodian named by the operator;
  - observed tests and CI;
  - declared data classification.

  It blocks on public exposure, agent-guardrail leads, sensitive data reachable alongside an AI service, exposure above Moderate, and unverified authority over production data. The repository can opt in to the profile but never out.
- **AI governance**:
  - The passport inventories the AI model services and agent tooling a repository uses.
  - Every rule maps to the NIST AI RMF and AIGP outcomes it informs. This is orientation, not certification.

Details and limits: [`references/citizen.md`](references/citizen.md) and [`references/ai-governance.md`](references/ai-governance.md).

## Gallery

Real output from the synthetic fixture `tests/fixtures/demo-app`, a fictional payments service. The citizen example is a small synthetic app built the way AI app builders do. Its agent settings are deliberately unsafe, so it is not checked in.

<table>
  <tr>
    <th width="50%">In the terminal</th>
    <th width="50%">As one offline HTML file (<code>--html</code>)</th>
  </tr>
  <tr>
    <td colspan="2"><b>What's broken?</b> <code>jankhunt42 scan .</code>: the Jank Score, its four dimensions, hot spots, and every finding with its evidence.</td>
  </tr>
  <tr>
    <td><img src="assets/readme/terminal-scan.png" alt="Terminal scan view: the code autopsy banner, a Jank gauge at 67 out of 100 graded E with the label biohazard and policy fail, the four dimension bars, top offenders and rules, and the first finding with evidence, why and fix"></td>
    <td><img src="assets/readme/scan-report.png" alt="HTML scan report: a score ring at 67 out of 100 graded E labelled biohazard, severity counts, and a scorecard for security, reliability, maintainability and test confidence"></td>
  </tr>
  <tr>
    <td colspan="2"><b>What can it hurt?</b> <code>jankhunt42 map .</code>: the exposure class, evidence coverage, trust-boundary crossings, and the highest-impact paths. The explorer is shown with the application's integrity blast radius highlighted.</td>
  </tr>
  <tr>
    <td><img src="assets/readme/terminal-map.png" alt="Terminal map view: the blast radius explorer banner, exposure High, evidence coverage and edge evidence counts, connected systems by kind, an internal-to-external trust-boundary crossing, and High integrity and confidentiality paths to the production ledger database"></td>
    <td><img src="assets/readme/blast-radius-explorer.png" alt="HTML blast radius explorer: summary cards, the connectivity graph with the application's integrity reach highlighted in magenta towards the ledger database, an S3 bucket, a Redis cache and external endpoints, and an inspector panel for the restricted production ledger database"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Can we responsibly ship it?</b> <code>jankhunt42 passport .</code>: the decision, the rules that produced it (including sensitive data reachable alongside an AI service), the evidence areas, and the AI services in use.</td>
  </tr>
  <tr>
    <td><img src="assets/readme/terminal-passport.png" alt="Terminal passport: release assessment REVIEW, Jank Score 67 out of 100, exposure High, evidence coverage 4 of 9, three review reasons P-DAT-002, P-AI-001 and P-JNK-001, the evidence areas, and the start of the AI use section"></td>
    <td><img src="assets/readme/software-passport.png" alt="HTML passport: summary cards for review, 67 out of 100, High, 4 of 9 and assessed, the three review reasons, and the table of every rule with its outcome"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Software built by citizen developers.</b> <code>jankhunt42 passport . --profile citizen</code> leads with a plain-language brief: why it blocks, what the software and its AI agent's tool servers can reach, and who must sign off.</td>
  </tr>
  <tr>
    <td><img src="assets/readme/terminal-citizen.png" alt="Terminal citizen passport: release assessment BLOCK, Jank Score 80 out of 100, exposure High, and an in-plain-terms box listing eight blocking reasons, what the software can reach, the AI service it uses, and an unpinned database tool server reaching a production host"></td>
    <td><img src="assets/readme/citizen-passport.png" alt="HTML citizen passport: release assessment block under the citizen profile with no custodian named, exposure High, and the plain-language brief with the blocking reasons and what the software and its agent set-up can reach"></td>
  </tr>
  <tr>
    <td colspan="2"><b>Run it in a sandbox (opt-in).</b> <code>jankhunt42 sandbox .</code> runs the install hooks and what runs when the folder is opened, in a disposable container with the network off and canary credentials, and reads like a firewall log. <code>passport --sandbox-run</code> sets what it tried against what the code declares.</td>
  </tr>
  <tr>
    <td><img src="assets/readme/terminal-sandbox.png" alt="Terminal sandbox run: 3 ALERT and 3 DENY with complete coverage; an npm postinstall and a VS Code folder-open task ran; the audit log shows canary reads of ~/.aws/credentials and ~/.npmrc, a persistence attempt on ~/.bashrc, two DNS lookups and a blocked connection to 203.0.113.9:443."></td>
    <td><img src="assets/readme/sandbox-passport.png" alt="HTML passport with the sandbox run: review on P-RUN-001 for 3 ALERTs and P-RUN-002 for 2 destinations the repository does not declare; a table marks api.invoices.example.com declared, and collector.telemetry-cdn.example and 203.0.113.9:443 undeclared."></td>
  </tr>
  <tr>
    <td colspan="2"><b>Did the observed behavior match policy?</b> <code>jankhunt42 agent-fuzz evaluate CAMPAIGN.json OBSERVATIONS.json</code> scores evidence supplied by an adapter. These gallery examples use synthetic observations; no agent was run, and file hashes do not authenticate the evidence.</td>
  </tr>
  <tr>
    <td><img src="assets/readme/terminal-agent-fuzz.png" alt="Terminal agent-fuzz evaluation from synthetic caller-provided observations: one fail, five passes, one inconclusive case and one case where policy was not loaded; the report states no agent was run."></td>
    <td><img src="assets/readme/agent-fuzz-report.png" alt="Offline HTML agent-fuzz report with synthetic caller-provided observations: fail verdict, five passes, one fail, one inconclusive case and one policy-not-loaded case, plus scope and hash caveats."></td>
  </tr>
</table>

Text output for the same fixture, regenerated by the test suite on every run, is in [`references/examples.md`](references/examples.md), with notes on how to read it.

## Commands

```sh
# What's broken?
jankhunt42 scan .                        # TTY "code autopsy"; Markdown when piped
jankhunt42 scan . --json                 # full machine report
jankhunt42 scan . --sarif > jank.sarif   # SARIF 2.1.0 for code scanning
jankhunt42 scan . --html > jankhunt42.html
jankhunt42 scan . --fail-on critical     # explicit CI gate
jankhunt42 scan . --since HEAD           # whole-tree plus new-code score
jankhunt42 scan . --score --json         # Jank Score 2.0 breakdown
jankhunt42 rules --category security     # the rule catalog
jankhunt42 review . --base HEAD~1 --json # committed changes, with receipts
jankhunt42 review . --staged --md
jankhunt42 review . --commit HEAD --brief            # handoff for a semantic reviewer
jankhunt42 review . --base HEAD~1 --save-baseline baseline.json --json
jankhunt42 review . --base HEAD~1 --baseline baseline.json --fail-on major
jankhunt42 triage app.log --top 25       # debugging helper: fingerprint and rank log clusters
jankhunt42 doctor --system               # debugging helper: repo and host health

# What can it hurt?
jankhunt42 map . --json                        # jankhunt.map.v1 (templates/map.schema.json)
jankhunt42 map . --base HEAD~1 --json          # graph delta from committed git objects only
jankhunt42 map . --redact --json               # shareable: pseudonymous IDs, no hosts or snippets
jankhunt42 map . --inventory ../inventory.json # operator inventory: classifications and verified grants
jankhunt42 map . --what-if ../scenario.json    # hypothetical: revoke, block egress, compromise an identity
jankhunt42 map . --drift ../stored-map.json    # stored map vs the current repository
jankhunt42 map . --mermaid > map.mmd           # Mermaid flowchart for docs
jankhunt42 map . --csv map-csv                 # nodes.csv + edges.csv (formula-injection safe)

# Can we responsibly ship it?
jankhunt42 passport . --json                   # jankhunt.passport.v1 (templates/passport.schema.json)
jankhunt42 passport . --html > passport.html   # printable, offline
jankhunt42 passport . --policy ../policy.json  # operator policy (outside the repo)
jankhunt42 passport . --fail-on block          # opt-in enforcement: exit 1 at or above block
jankhunt42 passport . --compare ../old-passport.json      # regressions since a stored passport
jankhunt42 passport . --acceptance ../acceptance.json     # operator acceptance, bound to revision and policy
jankhunt42 sandbox . --json                   # opt-in sandbox run of the install hooks and what runs on open
jankhunt42 sandbox . --fetch https://registry.npmjs.org/ --json   # dependencies' hooks too: fetches the pinned npm packages, verified
jankhunt42 passport . --sandbox-run /path/outside/run.json   # carry a saved run into the passport (P-RUN-001, P-RUN-002)
jankhunt42 passport . --branch-rules ../rules/app.json    # rulesets exported by an operator: is review enforced?
jankhunt42 supply-chain . --json                          # SPDX/CycloneDX, in-toto/Sigstore/GitHub, JFrog
jankhunt42 supply-chain . --require-sbom-minimum          # fail unless an SBOM has the NTIA minimum elements
jankhunt42 supply-chain . --verify ../verify-plan.json    # run gh/cosign/jf against a plan outside the repo
jankhunt42 selftest --full                                # self-assurance, with a pass/fail gate
```

Policy precedence is defaults, then an operator `--policy` from outside the repository, then hard floors. Repository config can only tighten. Jank Score 2.0 is a transparent prioritization device: four dimensions, A-E grades, and a headline anchored to the worst dimension.

## The evidence model

| State | Meaning |
|---|---|
| `observed` | The repository directly contains it: a literal endpoint, an SQL verb in a string, an HTTP call |
| `declared` | Configuration or a manifest says so: env values, Kubernetes RBAC, workflow `permissions:`, `.jankhunt42.json` declarations |
| `inferred` | A heuristic: an SDK import, a manifest dependency, an endpoint resolved by environment-variable name |
| `provider-verified` / `verified` | From an operator-supplied inventory **outside** the repository, or an exporter-recorded attestation verification |
| `tool-verified` | A native verifier (`gh`, `cosign`, `jf`) checked the signature against a plan naming the signer; jankhunt42 itself verifies no signatures |
| `unknown` | Not established. Never treated as safe, never as proven dangerous |
| `refuted` | Explicitly refuted by a trusted operator inventory, and excluded |

Paths take the strength of their weakest edge. "Known" reach means verified; everything else is potential.

## Configuration

`.jankhunt42.json` is discovered upward from the scan root (`.toml` also works on Python 3.11+):

- It tunes rules, severities, path scopes and ignores.
- Its `passport` section holds repository declarations: owners, asset sensitivity and criticality, operations evidence, and tighten-only policy.

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

Suppress a confirmed false positive inline, with a reason: `# jankhunt42: ignore JH201`. File-level suppression is `# jankhunt42: ignore-file JH305`, in the first 12 lines.

## Privacy and security

- **Offline by default.** Only two opt-ins reach a network:
  - `scan --cve` sends package names and versions to OSV.dev;
  - `--verify … --online` sends the repository name and artifact digests to the GitHub API.

  `map` and `passport` never resolve, probe, or connect to anything they find.
- **Redaction.** Credentials, URL userinfo, query strings, connection-string secrets, keys, tokens and emails are removed before anything is hashed, displayed or stored. Repository control characters are neutralized before they reach a terminal. HTML output escapes everything and runs under a no-network content security policy.
- **Sharing.** A connectivity graph can reveal internal topology, so use `--redact` for anything you share. Generated artifacts contain relative paths only.
- **Untrusted repositories.** jankhunt42 never executes repository code. Instructions embedded in repository content are data, not commands. Its Git calls switch off every way a repository's own configuration can name a program (hooks, fsmonitor, clean/smudge filters, diff drivers and text converters, signature checking), never write the index or use the network, and drop inherited variables that name a program (`GIT_EXTERNAL_DIFF`, `GIT_SSH_COMMAND`, `GIT_PAGER`, editors). A test proves each of these runs under plain Git and never under jankhunt42.

## Install as an agent skill

jankhunt42 is one `SKILL.md` directory. Put it where your tool already looks for skills:

| Tool | Project scope | User scope |
| --- | --- | --- |
| Claude Code | `.claude/skills/jankhunt42/` | `~/.claude/skills/jankhunt42/` |
| Cursor | `.cursor/skills/jankhunt42/` | — |
| Codex CLI | `.codex/skills/jankhunt42/` (also reads `.agents/skills/`) | `~/.codex/skills/jankhunt42/` |
| OpenCode | `.opencode/skills/jankhunt42/` (also reads `.claude/skills/`, `.agents/skills/`) | `~/.config/opencode/skills/jankhunt42/` |

The skill routes requests to the matching command and reference:

- debugging and scanning;
- mapping, exposure and blast radius;
- passport and release readiness;
- citizen-developer governance.

It never runs a repository's code without explicit permission. The listing on [skills-hub.ai](https://skills-hub.ai/skills/jankhunt42) carries the `SKILL.md` instructions only; clone the repository to get the CLI.

### Verifying a release

Every `vX.Y.Z` tag is built into a source tarball and attested in CI with a [GitHub Artifact Attestation](https://docs.github.com/en/actions/security-guides/using-artifact-attestations-to-establish-provenance-for-builds) (keyless Sigstore, tied to this repository's Actions identity):

```sh
gh attestation verify jankhunt42-<version>.tar.gz -R cloudbustinguk/jankhunt42
```

This confirms the tarball came from this repository's CI at the tagged commit. It says nothing about any marketplace's review.

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

Keep enforcement explicit. The gates are:

- `scan --fail-on SEV`;
- `review --fail-on SEV`, with a baseline;
- `passport --fail-on OUTCOME`;
- the `supply-chain --require-*` flags.

Everything else is advisory.

## Exit codes

| Code | Meaning |
|---|---|
| `0` | Ran successfully and no explicit gate tripped (`map` and an advisory `passport` always exit 0) |
| `1` | A gate tripped: `--fail-on`, a supply-chain requirement, `scan --score --fail-policy`, a failing `selftest`, or a sandbox ALERT |
| `2` | Usage error, unreadable input, unresolvable git ref, or invalid inventory/policy file |
| `130` | Interrupted |

## Limits

- **Static evidence only.** Findings and edges come from text, not data flow or runtime observation. They can miss things and can fire on examples. Effective privileges are never proven from a repository.
- **Agents.** Agent rules read configuration; they do not run the agent or its MCP servers. The citizen profile governs a release decision; it is not a sandbox.
- **Decisions.** Exposure classes and passport decisions are explainable heuristics, not probabilities or compliance results. The NIST AI RMF and AIGP crosswalk is orientation only.
- **Supply chain.** Parsing verifies no cryptography; the native verifiers do. SBOM quality counts fields; it does not judge their accuracy.

If a finding is wrong, confirm it in context, then suppress it with a reason or improve the rule. A scanner that cries wolf is worse than no scanner.

## Documentation
| Reference | Covers |
|---|---|
| [`references/examples.md`](references/examples.md) | Text output for the demo fixture, and how to read it |
| [`references/connectivity.md`](references/connectivity.md) | `map`: adapters, edge semantics, blast radius, exposure, inventory format, what-if, drift |
| [`references/passport.md`](references/passport.md) | `passport`: sections, rules, policy precedence, declarations, acceptance, comparison |
| [`references/citizen.md`](references/citizen.md) | The citizen profile, agent workspace checks, and the incidents they map to |
| [`references/ai-governance.md`](references/ai-governance.md) | AI-use inventory, `P-AI-001`, and the NIST AI RMF / AIGP crosswalk |
| [`references/agent-policy-corpus.md`](references/agent-policy-corpus.md) | Source-linked agent policy research and proposed fuzz experiments |
| [`references/supply-chain.md`](references/supply-chain.md) | SBOMs and their minimum elements, attestations, JFrog evidence, `--verify` |
| [`references/scoring.md`](references/scoring.md) | Jank Score 2.0 formula, weights, and limits |
| [`references/precision.md`](references/precision.md) | How often a finding is worth a look: labelled samples, method, limits |
| [`references/review.md`](references/review.md) | Diff review protocol, receipts, baselines |
| [`references/method.md`](references/method.md), [`references/playbooks.md`](references/playbooks.md), [`references/toolbox.md`](references/toolbox.md) | Debugging method, failure playbooks, native tool commands |
| [`references/n8n.md`](references/n8n.md) | n8n workflows: what they reach, credentials by name, comparing versions |
| [`references/change-review.md`](references/change-review.md) | `passport --base`: the new access a change asks for, and approving one change so CI passes it next time |
| [`references/sandbox.md`](references/sandbox.md) | `sandbox`: running the install hooks, the dependencies as they load, and what runs on open in a sandbox, the audit log, canaries and limits |
| [`references/dotnet.md`](references/dotnet.md) | ASP.NET Core leads, their limits, and offline NuGet restore/build |
| [`references/rulesets.md`](references/rulesets.md) | site rulesets (`--ruleset`) and `--ignore-rule`: your own rules, shipped rules set aside or re-rated, and trust |
| [`references/development.md`](references/development.md) | Architecture, development workflow, self-assurance, compatibility and migration notes |
| [`CHANGELOG.md`](CHANGELOG.md) | Every release |

## License

MIT. See `LICENSE`.

---

Built for people who would rather read one causal chain than ten dashboards.
