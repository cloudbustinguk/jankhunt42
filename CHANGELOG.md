# Changelog

All notable changes to jankhunt42 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [2.6.0] — 2026-10-25

Static containment evidence: who can merge, what an agent's sandbox can
reach, and where packages come from.

### Added

- **Change control** (passport `change_control`, rule `P-CHG-001`): can code
  reach the default branch without an independent human review?
  - Evidence comes from `passport --branch-rules FILE`, the repository's
    rulesets or branch protection exported from the GitHub REST API. It is
    provider-verified only outside the repository.
  - Terraform `github_repository_ruleset` and `github_branch_protection`
    count as declared intent.
  - The checks: a pull request with an approval, code-owner review,
    last-push approval, required checks, deletion and force-push
    protection, no GitHub App or deploy-key bypass, and CODEOWNERS
    coverage.
  - Under the citizen profile: block on no review or an app bypass;
    insufficient-evidence when unknown or only declared in the repository.
- **Package sources** (passport `package_sources`, rule `P-SUP-001`):
  - Each package manager's registries, declared in npm, Yarn, Bun, pip,
    Poetry, uv, PDM, Pipfile, Maven, Gradle, NuGet and Cargo config, or
    observed in lockfiles.
  - They are checked against an operator's `allowed_registries`.
  - A manager with no committed config is unknown, not "public".
- **Citizen pull-request gate:** `templates/citizen-gate.yml`, a required
  workflow with a read-only token, no secrets and pinned checkouts. It
  fails on `insufficient-evidence` as well as `block`, so a change that
  cannot be judged does not merge. The shell selftest runs the template's
  own command on a synthetic fixture.
- **Agent sandbox and platform rules:**
  - `JH709`: Codex network access and wildcard proxy domains; Claude Code
    sandbox wildcards, sockets, escape-hatch commands and write paths;
    OpenShell wildcard binaries and hosts, private `allowed_ips`, and
    full access on wildcards.
  - `JH710`: OpenShell audit mode, Landlock `best_effort`, `tls: skip`,
    uninspected credentials, and fail-open middleware.
  - `JH711`: dev containers that run privileged, share host networking,
    or mount the Docker socket.
- **Agent-branch CI** (`JH432`): a workflow on a push to any branch, or to
  agent branches, whose jobs hold secrets or a write-scoped token.
- **Egress boundary** (map and passport `egress`): declared agent-sandbox
  allowlists (Codex, Claude Code, OpenShell) compared with the hosts the
  map reaches. It reports hosts outside the boundary with their evidence
  tier, allowed entries nothing uses, and wildcards. With no allowlist it
  stays unknown.
- Mutants `M21`-`M28`: bypass actors ignored, a branch-rules export inside
  the repository trusted, every `yaml.load` treated as safe (`JH106` had
  none), disallowed registries ignored, egress hosts outside the boundary
  hidden, write tokens on any-branch workflows ignored, shared-tenant
  sandbox wildcards ignored, and declared-only change control satisfying
  the citizen profile.

### Fixed

From a soak trial on 106 more vibe-coded repositories (v0, Windsurf,
Cursor, Claude Code, and "vibe coding" projects in JavaScript, C#, Java
and PHP): critical findings fell from 84 to 10.

- `JH111` skips curl-pipe-shell text that is only printed, and is minor
  in test code. An official vendor installer over TLS is major, not
  critical.
- `JH101`:
  - Not secrets: token-auth usernames (`x-oauth-basic`), `$VAR/path`
    values, UPPER_SNAKE secret names, sentences, and `REPLACE_WITH_…`
    placeholders.
  - Minor: common default passwords, AWS key ids in presigned URLs, and
    Firebase web config API keys.
- From a third trial on 80 more (Copilot agent, Supabase/Next.js/Stripe,
  Firebase/React, Power Apps, n8n, Blazor and Flask with OpenAI, Lovable,
  bolt.new):
  - `JH101`:
    - Not secrets: regular expressions, CSS custom properties, error-message
      sentences, and elided examples (`"sk-live-..."`).
    - A value ends at its own closing quote, so an apostrophe inside it no
      longer cuts it short.
    - Keys in `google-services.json` and `GoogleService-Info.plist` are
      Firebase client config (minor).
  - `JH134` skips emulator and test rules files.
  - `JH111` skips `curl … | sh` written as prose (no URL, variable or flag).
  - `JH132` needs an environment read in code; a local constant named
    `PUBLIC_SECRET` is not one.
- `JH115` needs an assignment, keyword argument or default; an assertion on
  `verify_signature()`'s result is not one. It also reads dict keys in
  strings.
- `JH419` no longer treats `pull_request.head.sha` (a commit hash) as
  attacker-controlled.
- `JH134` rates a public read rule as major; public writes stay critical.
- Security leads inside a deliberately vulnerable example
  (`examples/vulnerable-…/`) are minor.
- `map --base`: a capability that becomes unknown is a possible escalation
  (`possible: true`), never a reduction, and an unknown capability that
  becomes known is marked `was_unknown`. Before, read to unknown counted as
  less authority.
- `passport --branch-rules` accepts JSON lists (a list of rulesets, or the
  `rules/branches` export), as documented.
- Online verification closes HTTP error responses instead of leaking them.
- The executable-docs test also runs commands written inline in README.md
  and SKILL.md, not only fenced blocks; the test suite no longer leaks file
  handles.
- The shareable passport (`--redact`) no longer carries custodian names in
  the embedded effective policy. The new sections are redacted too:
  registry URLs, egress hosts, ruleset notes and bypass actor ids.

## [2.5.0] — 2026-10-24

### Added

The blast radius map now covers cloud data platforms and cloud identity,
trained on a trial of 24 public Databricks, Azure Terraform, SQL Server,
PostgreSQL and Snowflake repositories.

- **Data platforms:**
  - Hosts for Azure SQL, PostgreSQL and MySQL, Cosmos DB, Storage, Service
    Bus, Redis, Key Vault, Databricks, Synapse, Fabric/OneLake, Data
    Explorer, AI Search, Azure OpenAI; AWS RDS, Redshift and S3; BigQuery
    and Cloud Storage; Snowflake; MongoDB Atlas.
  - JDBC URLs, including SQL Server's `;databaseName=` properties.
  - Per-tenant hosts written as bare strings
    (`server_hostname="adb-….azuredatabricks.net"`).
- **Spark and Databricks:**
  - Unity Catalog reads, writes and deletes from `spark.read.table`,
    `saveAsTable` (overwrite counts as delete) and `spark.sql` text,
    including `CREATE OR REPLACE TABLE`, `INSERT OVERWRITE` and `MERGE`.
  - f-string table names (`f"{catalog}.silver.orders"`) are resolved through
    simple string assignments in the file or, for a single value, anywhere
    in the repository. An unresolved catalog gets its own node.
  - `dbutils.secrets` as a named identity, and `dbutils.fs` operations.
  - Jupyter notebooks and Databricks source notebooks, including `%sql`
    and `# MAGIC %sql` cells.
  - Three-part SQL names count only in Spark files, so SQL Server's
    `database.dbo.table` is not taken for a catalog; inside `spark.sql`
    text, `schema.table` and `{table}` names count too.
- **More languages:** Go, Rust, Java and Kotlin imports and environment
  reads, plus `go.mod`, `Cargo.toml`, `pom.xml` and `build.gradle`
  manifests.
- **Azure identity:**
  - `DefaultAzureCredential`, managed identity and service principal
    credentials in Python, .NET, JavaScript, Go and Java.
  - Key Vault secret reads, writes and deletes.
  - Terraform `azurerm` read in depth: managed identities on any resource
    with an `identity` block, user-assigned identities, role assignments
    with capabilities taken from the role name or built-in GUID (including
    `<resource>.identity[0].principal_id` principals and AKS kubelet
    identities), custom role definitions (capability from their actions),
    Key Vault access policies, multi-line lists, and `data` blocks for
    existing resources. Scopes are labelled by depth: only a subscription,
    resource group or management group is a broad scope.
- **Credential blast radius**, a new graph heuristic: for each identity,
  what it unlocks if misused or leaked, and who holds it. Flags: `shared`,
  `secret-store-pivot`, `broad-scope`, `holder-not-visible`. It is shown
  in every map view and never changes the exposure class.
- Key Vault is `restricted` by resource type, as Kubernetes Secrets already
  were. Data store names that suggest personal, health or financial data
  add a `sensitivity_hint` and the `sensitive-by-name` unknown, never a
  sensitivity.
- `JH134` flags database firewall rules open to every IPv4 address and
  `publicly_accessible = true` database instances.

### Fixed

From a trial on 47 public citizen-developer and vibe-coded repositories:
Lovable and bolt.new apps, Replit and streamlit apps, and Python,
TypeScript, C#, Go, Rust and C++ projects.

- `JH101`:
  - The `sk-` pattern needs a word boundary; URL slugs such as
    `Risk-Management-…` matched it.
  - These are not secrets: URLs without a password or token material, a
    key's own name as its value, the xkcd example passphrase,
    concatenations, and test-data tokens with short ids
    (`test_redaction_d84e11`).
  - Capitalised words with a number (`Summer_Pass_2024`) read as a chosen
    password and stay secrets, as they were before.
  - Translation files are skipped, and Markdown and `.txt` documentation is
    minor. Other text files such as `.pypirc` keep their severity.
- `JH401` treats Supabase publishable and anon keys as public. Without a
  telling key name, only base62-like tokens count, not hex ids or hashes.
- `JH104` looks for concatenation in the SQL literal or the query's first
  argument, not in later, parameterized arguments. The literal's own quote
  ends it, so `"… name = '" + name` is caught and `LIKE '%is back'` is no
  longer read as `%` formatting.
- `JH106` accepts `Loader=Loader` aliased from `SafeLoader`.
- `JH112` no longer treats a bare `key` (React and history keys) as a
  secret.
- `JH131` is minor in test data, where hostile Unicode is deliberate.
- `JH132` needs the variable to be read in code (also inside a template
  literal) or defined as a JSON, YAML or TOML key, not mentioned in a
  sentence inside a string.
- `JH134` rates a `USING (true)` policy for one named role as minor.
  `public`, `anon` and `authenticated` stay major, and so does a policy
  with no `TO` clause, whatever its quoted name says.

## [2.4.2] — 2026-10-24

A second, wider field trial and an SBOM trial. Eleven more public repositories
were added, taking the trial to nineteen: Java, Go, Terraform, Docker
Compose samples, a Next.js/Stripe/Supabase starter, an Azure OpenAI chat
sample, a large multi-provider AI chat app, and self-hosted tools. Critical
findings across them fell from 77 to 18. Real SBOMs were also run through
`supply-chain`: release SBOMs from syft, goreleaser, trivy and cosign, plus
GitHub dependency-graph exports. JSON and SARIF fields are unchanged.

### Added

- `supply-chain` reads syft's native JSON. It records no creation time, so
  it never meets the minimum elements on its own.
- `supply-chain` reads GitHub's dependency-graph SBOM export; the
  `{"sbom": ...}` wrapper is removed.
- The map recognises Azure OpenAI from Python and JavaScript `AzureOpenAI`
  clients. The `openai` package serves both providers.

### Fixed

- `JH101`:
  - A PEM or PGP key header counts only when key material follows it. Armor
    headers such as `Proc-Type:` are skipped. `...` and `NOTAREALKEY`
    placeholders don't count.
  - Private keys in test data are major instead of critical.
  - These are no longer reported: a provider prefix followed by words, CamelCase
    text or a short counter (`sk-lf-RandomString…`, `sk-…-secret-0001`); a
    lowercase name under a non-password key (`token: 'identifier'`); and
    matches that run across string boundaries into code.
- `JH102` no longer reports `client.eval(...)` (a method, such as Redis
  `EVAL`), or `exec(...)` outside Python (there it runs a command). Dynamic
  code in tests is minor.
- `JH106` checks each language's own deserializers. JavaScript `yaml.load`
  is js-yaml 4's safe loader. Python `yaml.load` with a safe `Loader` is
  accepted. C# `BinaryFormatter` and Ruby `Marshal.load` are added.
- `JH201` treats a catch or except block that holds only a comment
  explaining why as deliberate, as ESLint's `no-empty` does.
- `JH204` treats a single literal message (`console.log("listening on
  5000")`) as logging; dumping values still counts. Tooling directories
  (`extra/`, `tasks/`, `hack/`) count as scripts.
- `JH415` reports only credential keys or secret-looking values in a Secret,
  not connection details such as type, host, port, database and username.
- The YAML reader handles plain scalars continued over several lines.

## [2.4.1] — 2026-10-24

Precision from a field trial. The scanner and the map were run on eight
public repositories: two AI web apps, two MCP server projects, a polyglot
Kubernetes demo, a .NET reference app, a Python web template, and a large
Rust workspace. Critical findings fell from 111 to 10. Every passport that
was `insufficient-evidence` only because a file could not be read now has
full coverage. No rule was removed, and JSON and SARIF fields are unchanged.

### Fixed

- `JH101` no longer reports:
  - references such as `env(...)`, `{{ ... }}` and `$( ... )`;
  - generated runs such as `abcdefgh…` and `12345678…`;
  - descriptive fixture values such as `"test-token"`, `"managed-api-key"`
    and `"…SYNTHETIC_CREDENTIAL"`, and text labels.

  A generic `key = "..."` assignment in test code is now minor with low
  confidence. Provider-shaped tokens and private keys keep their severity
  everywhere.
- `JH401`:
  - `.npmrc` and `.pypirc` count only their auth settings.
  - A `.env` value counts when its key names a credential, or the value is a
    URL with a password or a long token. Placeholders such as `changethis`
    do not count.
  - A PEM file counts only when it holds a private key; certificates are
    public.
- `JH414` reports only capabilities that are added. It no longer reports
  `capabilities.drop: [ALL]`, which is the hardened setting.
- `JH502` recognises Rust tests: assert macros, `assert_*` helpers,
  `unwrap`/`expect`, `?`, and a returned `Result`. It also recognises
  JavaScript helpers named `verify*`, `assert*` or `check*`. It no longer
  treats `regex.test(x)`, Rust test attributes, markdown, or pytest fixtures
  named `test_*` as tests.
- `JH104` requires SQL structure plus real interpolation, or a quote next to
  `+`. Arithmetic inside SQL text, `?` placeholders, GraphQL builders and URL
  query names are not dynamic SQL.
- `JH105` reports `verify=False` only on HTTP clients (requests, httpx,
  sessions, clients), not on a function's own `verify` flag. It finds the
  enclosing call across lines, and also reports `session.verify = False`.
- `JH112` is limited to Python's `random` and JavaScript's `Math.random`.
- `JH119` accepts tarfile's `data` and `tar` extraction filters. `JH120` no
  longer reports `zipfile`, which strips absolute paths and `..` itself.
- `JH102` ignores `exec` and `eval` of a constant string.
- `JH204` checks each language's own debug hooks. `console.log` in CLI
  scripts, examples, migrations and tests is output, not a leftover.
- Rust test files named `*_tests.rs` and `tests.rs` count as tests.
- Map coverage:
  - The YAML reader handles flow collections spread over several lines,
    which formatters produce for long `needs:` lists, and documents that are
    a single scalar.
  - A UTF-8 byte-order mark is stripped.
  - `appsettings*.json` may contain comments and trailing commas, as .NET
    allows.
  - Helm and Go templates are reported as the `unrendered-templates`
    unknown, instead of parse failures that made coverage partial.

### Added

- More AI services are recognised:
  - the Vercel AI SDK's provider packages, and its AI Gateway
    (`import { gateway } from "ai"`);
  - Cohere, Replicate, Hugging Face, Together, Vertex AI and Bedrock;
  - LangChain's provider packages;
  - .NET's Azure OpenAI and OpenAI clients.
- Mutants M19 (the placeholder filter hides real credentials) and M20 (TLS
  bypasses on HTTP clients go unreported), for 20 in total.

### Compatibility

- Scan results change. The rules above report fewer findings, and some
  `JH101` findings in test code are now minor. Passports whose coverage was
  partial only because of these files can now reach `pass` or `review`.

## [2.4.0] — 2026-10-24

Evidence you can rely on, and AI governance you can explain. SBOMs are now
checked against the minimum elements. The passport inventories the AI
services and agent tooling a repository uses, asks for a decision when
sensitive data sits beside an AI service, and maps every rule to the NIST AI
RMF and AIGP outcomes it informs. Existing JSON and SARIF fields are
unchanged.

### Added

- **SBOM minimum elements.** Every parsed SBOM carries a `quality` block that
  counts the NTIA 2021 minimum elements: supplier, name, version, unique
  identifier (purl or CPE), dependency relationships, author, and timestamp.
  The result is `met`, `partial` (with a `missing` list and counts), or
  `not-met`. The CISA 2025 draft additions (hash, licence, tool name,
  generation context) are listed separately and never required. Also new:
  - the summary field `sbom_minimum_elements`;
  - a Markdown column and a line per SBOM naming what is missing;
  - `supply-chain --require-sbom-minimum`;
  - policy `require.sbom_minimum`, which feeds `P-EVD-001`;
  - passport `provenance.sbom_minimum_elements` and `sbom_missing`.
- SBOM package records gain `hashes` (algorithm names) and `cpe`.
- **AI-use inventory.** The passport's new `ai` section lists:
  - the external AI model services the software can reach, each with its
    evidence tier and who reaches it;
  - agent tool servers and instruction files;
  - a human-oversight posture taken from the `JH702`-`JH704` leads;
  - confidential or restricted data reachable alongside an AI service.
  `--redact` pseudonymizes it.
- **`P-AI-001`**: sensitive data and an external AI service are reachable
  together. It asks someone to decide what reaches the provider and how the
  provider handles it (retention, training use, region). The standard
  profile reviews, the citizen profile blocks. It is co-reachability, not a
  claimed data flow. It gets its own brief line and remediation step.
- **Framework orientation.** A new `alignment` section maps every policy rule
  and evidence area to NIST AI RMF 1.0 subcategories (quoted from NIST AI
  100-1) and IAPP AIGP Body of Knowledge v2.1 domains (paraphrased). It is
  orientation only, not a conformity assessment. The Markdown and HTML views
  add "AI use" and "Framework orientation" sections, and the terminal adds an
  "ai use" block, all shown only when AI use is observed.
- `references/ai-governance.md`, and mutants M17 (`P-AI-001` never fires) and
  M18 (every SBOM meets the minimum), for 18 in total.

### Fixed

- SPDX 3.0.1 JSON-LD documents now read the 3.0.1 property names
  (`software_packageVersion`, `software_packageUrl`, `suppliedBy`,
  `verifiedUsing`, `externalIdentifier`), licences recorded through
  relationships, and `CreationInfo`. Versions, purls, and suppliers in such
  documents were missed before.
- SPDX tag-value: the purl comes from `ExternalRef … purl`, no longer from
  `PackageDownloadLocation`, and every `Creator` line is read.
- CycloneDX: the supplier no longer falls back to `group`, which is a
  namespace. The XML parser reads suppliers, licences, hashes, and CPEs, and
  no longer counts tool components as packages.
- The terminal scan view's Jank headline row was 9 columns wider than its
  frame and wrapped at every width; the gauge now takes only the space left.
- CHANGELOG: restored the 2.0.0 heading, which was lost in 2.1.0.

### Changed

- The README is reorganized around a gallery that pairs each terminal view
  with its HTML view (scan, map, passport, citizen passport), followed by one
  command reference. The generated text samples moved to
  `references/examples.md`. Architecture, development, self-assurance, and
  migration notes moved to `references/development.md`.

### Compatibility

- Fields are only added. The effective policy gained `require.sbom_minimum`
  and a `P-AI-001` action, so the policy hash changed. Re-issue acceptance
  records bound to an earlier hash.
- Under the standard profile, `P-AI-001` adds a `review` reason when
  sensitive data is reachable alongside an AI service. The demo fixture now
  reviews on it.
- A CycloneDX component whose only "supplier" was its `group` now has no
  supplier.

## [2.3.0] — 2026-10-24

Governing citizen developers and the blast radius their software inherits.
People who are not software engineers now ship software with AI coding
agents; this release checks what those agents are allowed to do, maps what
their tools can reach, and adds a strict passport profile for software built
this way. Everything stays offline and static, and existing JSON and SARIF
fields are unchanged.

### Added

- `passport --profile citizen` (also `"profile": "citizen"` in an operator
  policy, or `passport.profile` in repository config, which can opt in but
  never out). It requires an owner, a named engineering custodian, observed
  tests and CI, and declared data classification, and it blocks on public
  exposure, agent-guardrail leads, exposure above Moderate, sensitive
  external exports, a failed Jank Score policy, and authority over
  production or restricted data that nobody has verified
  (`static_leads: block`).
- Five passport rules: `P-CUS-001` (engineering custodian), `P-DAT-003`
  (data classification), `P-SEC-001` (credentials or data exposed to the
  public), `P-AGT-001` (agent guardrails bypassed or agent tooling
  unpinned), and `P-OPS-001` (tests and CI observed). Under the standard
  profile `P-SEC-001` and `P-AGT-001` give `review`, and the others apply only
  when a policy requires them.
- Custodians: only `custodians` in an operator policy satisfy `P-CUS-001`;
  `passport.custodians` in the repository is recorded as a declaration but
  does not count. Under the citizen profile an acceptance record must be
  signed by a custodian named in the operator policy.
- The citizen profile is applied after the operator's ordinary settings, so
  a baseline policy cannot weaken it (each override is warned);
  `profile_exceptions` in the operator policy relax rule actions,
  requirements, `max_exposure`, or `static_leads` on purpose, each with a
  warning. Governance leads also come from a scan that ignores repository
  scan config and inline pragmas (the repository can add leads, never
  remove them), and `governance.repository_suppressed_leads` reports
  exactly what repository tuning would hide. If that scan reaches
  `--max-files`, a citizen passport is `insufficient-evidence`. All
  repository policies are merged in one pass, after the operator's
  exceptions.
- Shareable (`--redact`) maps and passports withhold warnings, which can
  quote declaration patterns, object names, and paths.
- A `governance` section in passports: profile, custodians, the leads behind
  `P-SEC-001`/`P-AGT-001`, the AI agent tooling found in the map, and a
  plain-language brief, which citizen passports lead with in the terminal,
  Markdown, and HTML views. `--redact` hides server names, credentials,
  endpoints, and custodians, and the hostnames, paths, and names that rule
  messages quote.
- The map's `mcp` adapter: MCP server definitions for Claude Code, Cursor,
  VS Code, Gemini CLI, Codex, opencode, and Claude Desktop become an AI agent
  principal with edges to each server, the endpoints it is pointed at, and
  its credentials (by name only), plus an `agent-tool-capability` unknown.
- The map recognizes the stack AI app builders use: Supabase,
  Firebase/Firestore, Neon, Upstash, Turso, Airtable, and Google Sheets as
  data stores, and Stripe, Twilio, SendGrid, Resend, Slack, Notion, and model
  APIs as external services.
- 17 scanner rules (96 in total), with a new `agent` category scored under
  security:
  - `JH701`-`JH708` (agent): suspicious agent instructions (hidden HTML
    comments with commands or credential references, instruction overrides,
    "do not tell the user", pipe-to-shell, credential exfiltration); agent
    CLIs run with approval-bypass flags; approval bypasses committed in VS
    Code, Claude Code, Codex, or Zed settings; folder-open tasks, project
    hooks, dev container `initializeCommand`, credential helpers, and API
    base-URL or proxy overrides; MCP
    servers launched from unpinned packages or images, holding literal
    credentials, or reached over plaintext HTTP; issue, PR, or comment text
    fed to AI agent steps in GitHub workflows.
  - `JH131`-`JH134`: hidden Unicode (tag characters, decoded for the
    reviewer; bidi controls; invisible characters; stacked variation
    selectors); secrets shipped to the browser through public env prefixes,
    including Supabase `service_role` keys; `dangerouslyAllowBrowser` LLM
    clients; data stores open to the public (Firebase rules, disabled
    row-level security, permissive policies, writes granted to `anon`,
    public buckets and IAM bindings).
  - `JH427`-`JH431`: `toJSON(secrets)`, `secrets: inherit`, pip extra
    indexes (dependency confusion), Dependabot external code execution, and
    Dependabot without a cooldown.
- `JH101` and redaction know npm, PyPI, GitLab, Hugging Face, Groq,
  SendGrid, DigitalOcean, Shopify, and Slack webhook formats, and PGP
  private key blocks.
- `references/citizen.md`, routing and doctrine for citizen developers in
  `SKILL.md`, and four selftest mutants (16 in total).

### Changed

- `JH418` also covers `workflow_run`, `refs/pull/...` refs, fork repository
  checkouts, `allow-unsafe-pr-checkout: true`, and `gh pr checkout` or
  `git fetch` of pull-request refs in run steps; it looks only at the step
  it reports. `JH419` knows more untrusted fields (discussions, commit
  messages and authors, PR head labels, `workflow_run` heads) and also
  checks `actions/github-script` scripts.
- Finding evidence shows invisible, bidi, and tag characters as `<U+XXXX>`,
  and terminal output neutralizes tag and invisible format characters too,
  so hidden text cannot ride a report into a reader's or an agent's context.
- The effective policy has new keys (`profile`, `custodians`,
  `static_leads`, more `require` entries), so policy hashes changed;
  acceptance records bound to an earlier hash must be re-issued.
- Directory walks (outside git) now include agent and editor workspace
  directories such as `.vscode`, `.claude`, `.cursor`, and `.codex`.
- CI uses Node 24 action majors pinned to full commit SHAs
  (`actions/checkout` v7.0.1 with `persist-credentials: false`,
  `actions/setup-python` v6.3.0, `actions/attest-build-provenance` v4.2.2,
  `softprops/action-gh-release` v3.0.3). The README CI example uses current
  majors. GitHub releases now carry their CHANGELOG section as release
  notes (earlier releases showed only a compare link).
- The `SKILL.md` description is within the 1,024-character Agent Skills
  limit.
- Terminal views use the HTML views' colours: the scan report palette for
  `scan`, the explorer palette for `map` and `passport`. Exact in truecolor
  terminals (`COLORTERM=truecolor`), nearest xterm-256 otherwise, and the
  explorer's light palette when `COLORFGBG` reports a light background. The
  wordmark and banner border use the cyan-to-magenta brand gradient (it used
  to step through unrelated 256-colour hues), blast-radius path edges are
  magenta, grades are coloured badges, severities and hot-spot bars match the
  scan report, and `declared` evidence is violet. Text is unchanged.
- README shows screenshots of the HTML views, including a citizen-profile passport.

### Fixed

- `JH502` flagged nearly every unittest-style test: `self.assertEqual` and
  friends did not match its word-boundary pattern. It now accepts any
  `assert*` call and assertions made inside helper methods (directly or
  through other helpers).
- A connection string whose password is a placeholder
  (`postgresql://user:${PASSWORD}@host/db`) lost its concrete host and
  became an unresolved target.
- `JH401` treated a CI workflow named `secrets.yml` as a credential file.
- Test fixtures carried literal bidi and byte-order-mark characters; they
  are escape sequences now.

## [2.2.0] — 2026-10-24

Opt-in attestation verification by native tools. Offline stays the default;
no existing option, exit code, or schema field changed, and new fields are
additive.

### Added

- `supply-chain --verify PLAN.json` and `passport --verify PLAN.json`: run
  `gh attestation verify`, `cosign verify-blob-attestation`, or
  `jf evd verify` from a verification plan (`jankhunt.verify.v1`,
  `templates/verify.schema.json`). The plan names the subjects and the
  signer identity to trust, so it must live outside the scanned repository;
  unknown keys are errors. Results are `tool-verified`, `signature-only`,
  `failed`, `not-run`, or `error`, with the verifier, version, command, and
  reason. jankhunt42 still performs no cryptography itself.
- Offline unless `--online`: without it no connection is opened and a
  verifier runs only with a bundle plus a Sigstore trusted root. With it,
  bundles are fetched by artifact digest from the GitHub attestations API and
  SBOMs from GitHub Actions artifacts (digest-checked, size-bounded, marked
  unsigned). `GH_TOKEN`/`GITHUB_TOKEN` is sent only to api.github.com and
  never to a redirect target. `--fetch-dir DIR` keeps fetched files.
- A requested verification that does not end `tool-verified` fails the
  supply-chain gate and triggers `P-EVD-001` in a passport.
  `--require-verified-attestation` accepts `provider-verified` or
  `tool-verified`, never `signature-only`.
- JFrog `keySource` is recorded as `key_source`. A Sigstore bundle key
  (the key embedded in the bundle) proves consistency, not the signer: it
  carries a warning, is `signature-only` in verification mode, and is
  re-checked with cosign when the plan names a certificate identity.
- Three more selftest mutants (not-run counted as verified, token sent on
  redirect, in-repository plan trusted).
- The CI matrix and the `selftest --full` container matrix now cover every
  minor version from 3.9 to 3.14 (3.10, 3.11, and 3.14 added).
  Python 3.9 remains the minimum for systems that still ship it, although it
  is past its upstream end of life.

### Fixed

- `gh` accepts only one signer constraint; verification passes the most
  specific one in the plan (found by a live check against the v2.1.0
  release, now covered by the tests).
- Passport provenance listed every attestation's kind as `unknown`; it now
  reports the predicate kind (for example `slsa-provenance-v1`).

## [2.1.0] — 2026-10-23

The pieces deferred from 2.0.0, all opt-in and additive. No existing option,
exit code, or schema field changed; new fields are additive.

### Added

- `map --what-if SCENARIO.json`: hypothetical mutations (`revoke`,
  `remove-node`, `remove-edge`, `add-edge`, `set-capability`,
  `block-egress`, `compromise-identity`) on a copy of the graph, reported as
  a full graph delta plus compromised-identity blast radii. Nothing is
  changed or executed; added edges are `declared` and labeled hypothetical.
- `map --drift MAP.json`: stored map vs the current repository
  (`snapshot-drift`; static change, explicitly not runtime drift).
- `map --mermaid` and `map --csv DIR`: Mermaid flowchart (entity-escaped
  labels, dashed inferred edges, explicit truncation) and nodes/edges CSV
  (formula-injection safe). JSON remains canonical.
- OpenAPI/Swagger adapter: enriches API nodes the code already calls, or
  records what the application exposes. It never creates an edge.
- `passport.bindings`: declare which workload runs the repository code; the
  code inherits that workload's identities and the unknown disappears.
- Path strength: trusted operator inventories may weight grants
  (`attenuation` 0-1); reachable assets gain `strength` and a witness path
  from exact bounded max-product search, checked against a brute-force
  oracle. Presentation only; never affects exposure or policy.
- `passport --acceptance PATH`: operator acceptance records (outside the
  repository only), bound to revision, policy hash, decision, and optional
  digest/environment; `accepted` (declared-by-operator), `invalidated` with
  named reasons, or `rejected`. Block and insufficient-evidence decisions
  can never be accepted.
- `passport --compare OLD.json [--against NEW.json]`:
  `jankhunt.passport-delta.v1` with regressions and a scan_id
  self-consistency (not signature) check.
- Two more selftest mutants (acceptance binding, CSV formula injection).

### Fixed

- `JH104` (Dynamic SQL) no longer fires on parameterized `%s`/`%(name)s`
  placeholders; `"..." % value`, concatenation, and f-strings are still
  flagged. This only removes findings (verified against 1.1.0).

## [2.0.0] — 2026-10-23

jankhunt42 now answers three questions instead of one: **what's broken?**
(unchanged scanner, review, supply chain, Jank Score 2.0, deep hunt),
**what can it hurt?** (`map`), and **can we responsibly ship it?**
(`passport`). Everything stays local, offline, and stdlib-only.

### Added

- `map`: offline connectivity discovery and blast radius. Adapters for
  Python, JavaScript/TypeScript, .NET, `.env`/config/appsettings,
  Kubernetes workloads and RBAC, docker-compose, GitHub Actions
  permissions and cloud logins, Terraform data stores and privileged grants,
  and dependency manifests. A typed directed multigraph with stable IDs, a
  sanitized receipt (path, line, hash, assumptions) for every claim, and
  explicit evidence states (`observed`, `declared`, `inferred`,
  `provider-verified`, `unknown`, `refuted`). Per-impact (C/I/A) bounded
  reachability with witness paths, trust-boundary crossings, a monotone
  qualitative exposure class (Low/Moderate/High/Critical/Unknown), a
  saturating breadth indicator (informational only), explicit unknowns, and
  coverage. JSON (`jankhunt.map.v1`), Markdown, a terminal "blast radius
  explorer" view, and a self-contained offline HTML explorer (CSP
  `default-src 'none'`, evidence inspector, filters, C/I/A highlighting).
- `map --base REF`: graph delta built from committed git objects only
  (added/removed nodes and edges, permission escalations, newly reachable
  sensitive assets, trust-boundary changes, coverage regression).
- `map --inventory PATH`: operator inventory for classifications and grants;
  `provider-verified` only when the file is outside the scanned repository.
- `map/passport --redact`: shareable pseudonymized output.
- `passport`: software passport (`jankhunt.passport.v1`) linking Jank Score,
  exposure, ownership (CODEOWNERS/declared), provenance (SBOM/attestations,
  exporter-reported), data sources, operations evidence, unknowns, and
  remediation steps, with an explainable decision (pass / review /
  insufficient-evidence / block) from seven named rules, hard floors,
  tighten-only repository policy, operator `--policy`, and opt-in
  `--fail-on` enforcement. Lifecycle stops at `assessed`; acceptance is
  never inferred.
- `selftest [--full] [--json]`: independent self-assurance (oracle-checked
  tests, metamorphic and monotonicity properties, seeded fuzzing, golden
  terminal snapshots, cross-version compatibility, a hand-maintained
  self-map ground truth, seven mutants with controls, a privacy scan, and an
  offline Python 3.9/3.12/3.13 container matrix when images are cached).
- `tests/`: stdlib unittest suite, independent brute-force reachability
  oracle, synthetic `demo-app` fixture, golden snapshots, executable-docs test.
- `references/connectivity.md`, `references/passport.md`,
  `templates/map.schema.json`, `templates/passport.schema.json`.
- `.jankhunt42.json` `passport` section: owners, asset classifications,
  operations declarations, tighten-only policy.

### Changed

- `SKILL.md` is now a routing document organized by the three questions
  (257 lines, down from 405); detail moved to references. Debugging doctrine
  and the deep-hunt permission gate are preserved.
- `README.md` rewritten around the three questions; its sample output is
  generated from the synthetic fixture and checked by the test suite.
- The product name is written `jankhunt42` everywhere, including the
  `SKILL.md` `name` field and human-readable Markdown/HTML titles
  (`# jankhunt42 scan`). Machine formats were already lowercase.
- `--help` leads with the three questions.

### Security

- Repository-sourced strings in terminal and Markdown output (scan, review,
  map, passport) have control, escape, and bidi characters replaced with
  U+FFFD, so a hostile repository cannot rewrite the reviewer's terminal.

### Compatibility

- `scan`, `score`, `review`, `supply-chain`, `hunt`, `merge`, `triage`,
  `doctor`, `report`, and `rules` keep their options, exit codes, JSON, and
  SARIF. Verified by running 1.1.0 and 2.0.0 side by side on the demo fixture.
  Jank Score 2.0 arithmetic is unchanged; `scan` never computes a passport.

## [1.1.0] — 2026-10-23

First 1.x release. No functional changes from 0.4.0: the CLI, rules,
config format, and output schemas are identical. The jump to 1.x is so the
repo version and the skills-hub.ai listing version stay the same. That
registry numbered its first upload (0.2.0-era content) 1.0.0 and only
accepts newer versions above it, so 1.0.0 is taken there and this release
is 1.1.0.

### Changed

- Version bumped to 1.1.0 in `SKILL.md`, `scripts/jh_core.py`, and README.

## [0.4.0] — 2026-10-23

Acts on the three highest-leverage gaps identified by an industry/competitor
review against Semgrep, SonarQube, Snyk Code, CodeQL, Checkmarx, and the
AI-code-review wave (Prbl, Copilot Autofix, Endor Labs): false-positive
noise is the market's actual bottleneck, every competing scanner has a
config file and jankhunt42 did not, and diff-only review misses the same
defect repeated across files. Also fixes a flaky selftest CI failure and
adds multi-tool platform metadata.

### Changed

- **CLI renamed `jankhunt` → `jankhunt42`** (`scripts/jankhunt42`), to stop
  colliding with "jank hunting," the established browser/mobile
  performance-profiling term (Chrome DevTools, Perfetto, Flutter, Android).
  The name now matches the project everywhere: `prog`, `--version`, JSON
  `tool`, SARIF driver name, error prefixes, repro commands in receipts,
  config files (`.jankhunt42.toml`/`.json`), and the calibration ledger
  directory (`.jankhunt42/`). Update scripts, aliases, and symlinks that
  invoke `scripts/jankhunt`.
- **Inline pragma is now `# jankhunt42: ignore …`.** The old
  `# jankhunt: ignore …` / `ignore-file` prefix is still honored, so
  existing suppressions keep working.
- **SARIF consumers:** the driver name changed from `jankhunt` to
  `jankhunt42`, so GitHub code scanning (and similar) will treat this as a
  new tool. Alerts filed under the old name will not auto-close; dismiss or
  close them once after upgrading. Review baselines are unaffected (they
  match on rule/path/evidence fingerprints, not tool name).

### Added

- **Repo config file** (`jh_config.py`): `.jankhunt42.toml` (Python 3.11+,
  `tomllib`) or `.jankhunt42.json` (always), discovered upward from the scan
  root the way `.git` is. Disables a rule, overrides its severity globally
  or per path glob, or ignores a subtree. Applies to `scan`, `score`, and
  `hunt` via `--config PATH` / `--no-config`; not yet wired into `review`.
- **Opt-in false-positive calibration** (`jh_calibrate.py`, `--calibrate`):
  records each rule's fired/suppressed counts into `.jankhunt42/calibration.json`
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

- **Flaky CI: `jankhunt42` could exit 120 under a closed pipe.** Any command
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

Review-layer release. jankhunt42 now reviews a diff deterministically, emits
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
  or `cosign` hint. Unsigned statements are labeled `unsigned`. jankhunt42
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
- `provider-verified` is the exporter's claim, not a fresh jankhunt42
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
