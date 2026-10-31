# Changelog

All notable changes to jankhunt42 are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
semantic versioning.

## [4.4.0] — 2026-10-31

### Added

- Citizen passports show repository instruction and agent configuration files
  near findings as candidate context, with explicit unknowns for the original
  agent, policy loading, managed guardrails, and causation. Shareable reports
  alias the paths.

## [4.3.1] — 2026-10-31

### Added

- A source-linked research corpus covering enterprise controls, instruction
  discovery, and proposed policy-fuzz experiments for Claude Code, Codex,
  Cursor, and OpenCode. The corpus distinguishes documented behavior from
  experiments that still need live-client verification.

## [4.3.0] — 2026-10-31

An agent-policy fuzzing foundation, with more precise findings.

### Added

- `agent-fuzz validate` checks bounded, declarative campaigns for Claude Code,
  Codex, Cursor and OpenCode. It does not run an agent.
- `agent-fuzz evaluate` scores caller-provided, per-case observations. TUI and
  self-contained offline HTML reports show case outcomes without copying raw
  event resources or policy text. These observations are not authenticated
  agent runs or proof that an organization-wide policy was effective.
- A baseline campaign and design contract for safe future runner and adapter
  work.

### Changed

- Tightened finding precision for embedded examples and agent flags, improved
  recall for swallowed writes and generated credentials, and avoided `JH205`
  leads for documented HTTP routes.

### Compatibility

- Existing scan and report schemas remain unchanged; `agent-fuzz` is additive.

## [4.2.0] — 2026-10-29

ASP.NET Core review and a sandbox for .NET restore/build.

### Added

- Nine static leads (`JH135`–`JH143`) cover data endpoints without visible authorization,
  credentialed all-origin CORS, developer errors outside a development guard, public
  cleartext Kestrel listeners, C# interpolation at raw database APIs, type metadata
  deserialization, personal fields passed to AI clients, floating NuGet versions,
  and MSBuild network downloads. Public constant health responses, authorized route
  groups/controllers, guarded developer pages, parameterized EF/Dapper calls and
  comment/string examples have explicit negative tests. Development comparisons and
  production controls are scoped to their branches; reassigned groups cannot pass
  authorization to child routes. These are structural leads,
  with project-local context, not a C# compiler or proof of deployment behavior.
- `JH135` and `JH136` join the citizen profile's public-exposure leads (`P-SEC-001`).
- NuGet `sandbox --fetch`: default `packages.lock.json` v1/v2, a literal unconditional
  locked-mode project, normalized package identities, and verified SHA512 content
  hashes. Existing HTTPS/origin/address restrictions and the shared download budget
  apply. Downloaded archives stay unopened on the host. Conflicting pins and linked,
  conditional or unsupported inputs produce explicit gaps/refusals.
- `sandbox --nuget-cache DIR` supplies a read-only folder feed. The separate .NET 10
  SDK image runs traced `dotnet restore --locked-mode` and `dotnet build --no-restore`
  offline, with telemetry disabled. Missing SDKs/caches and failed commands produce
  partial coverage. A live invented NuGet build target proves canary reads are seen.
- Offline regression tests and mutants M200–M232 (224 mutants in total).

### Compatibility

- Existing JSON/SARIF schemas and sandbox isolation remain; NuGet receipts/cache counts
  are additive. The hidden `detonate`/`--detonation` aliases remain accepted through
  4.2, extending the previous transition period.

## [4.1.0] — 2026-10-29

Deeper into the sandbox, and a scan your team can make its own.

### Changed

- **`detonate` is now `sandbox`.** The command runs a repository's code in a
  disposable sandbox and records what it tries; "detonate" presumed the
  code was hostile. `jankhunt42 sandbox .` replaces it, `passport
  --sandbox-run FILE` replaces `--detonation`, results carry the schema
  `jankhunt.sandbox.v1`, the image is `localhost/jankhunt42-sandbox:0.1`
  (built from `templates/sandbox.Containerfile`), and the guide is
  `references/sandbox.md`. The old command and flag still work, hidden,
  until 4.2; the passport still reads results saved as
  `jankhunt.detonate.v1`; and an image built under the old name is used
  when the new one is absent.

### Added

- **The sandbox loads each dependency (`--surface import`).** A package can
  wait until it is loaded: code at the top of its `index.js` or
  `__init__.py` runs when the application imports it, with no install hook
  at all. After the install step, the sandbox loads each direct dependency
  once, as the application would (Node's `import()` for npm packages, so
  CommonJS and ES modules both load; a small loader for Python packages,
  which imports the modules the distribution installed). Each load is its
  own step, so every event names the package that caused it. Installed
  `.pth` files, which a real install runs at every Python start, run in a
  step of their own. After each load the sandbox waits two seconds, so a
  timer or thread the package deferred (even one that would let the
  process exit first) runs where it is seen. It needs the dependencies installed, and coverage
  says so when they are not. At most 40 dependencies load, 20 seconds
  each; names reach the runner only as quoted arguments, and only when
  they are package names. The default run now covers install, import and
  open.
- **`--fetch` for Python.** `sandbox --fetch https://pypi.org/ --fetch
  https://files.pythonhosted.org/` also fetches what a hash-pinned
  `requirements.txt` pins (`name==version --hash=sha256:...`, nothing
  looser), through the index's JSON API, verified against the pinned
  hashes, into a wheelhouse for that run, under the same HTTPS, address
  and size rules as the npm fetch. Wheels come first; a source package is
  fetched only when no pinned wheel exists, and the receipt marks that its
  build runs code. Designed and built by Codex (mutants M170 to M183).
- **Python dependencies declared in `pyproject.toml`** install and load
  when there is no `requirements.txt` (modern projects often have none).
  Each requirement goes to pip as one quoted argument, and only when it
  starts with a package name, so none can pass for a pip option.
- **curl and wget in the image,** because a real machine has them: code
  that shells out to them now tries, and is seen trying. Rebuild the image
  once (`templates/sandbox.Containerfile`); until then an image built under
  the old name is used, and coverage says it lacks them.
- **Four more canaries:** the GitHub CLI's `hosts.yml`, a Docker
  `config.json`, a kube config and a `.pypirc`, the credential files
  attackers sweep for. The sandbox trials found the first: a dependency
  that read the GitHub CLI's token went unseen.
- **`--ignore-rule JH417`** on `scan`, `review` and `passport` sets a rule
  aside for one run, for a rule your team owns the answer to (whether a
  trusted publisher's tag is good enough is a policy choice). Its findings
  are not reported, scored or gated on; the JSON lists it in
  `ignored_rules`, and the passport in `scope.ignored_rules`. An unknown
  id is refused.
- **Site rulesets (`--ruleset FILE.json`).** Your site policy in one file
  (`jankhunt.ruleset.v1`): rules of your own, on the same engine as the
  shipped ones, plus shipped rules set aside or re-rated. Every site rule
  carries match and no-match examples, and a ruleset whose rule fails its
  own examples is refused. Ids starting with `JH` stay reserved. A ruleset
  outside the repository is the operator's policy and applies everywhere;
  one inside it is treated like `.jankhunt42.toml`, so its ignores do not
  reach the citizen profile's governance scans. Reports record each
  ruleset's name, sha256 and trust. See `references/rulesets.md` and
  `templates/site-ruleset.example.json`.

### Removed

- **The `score` alias,** as 4.0.0 said: use `jankhunt42 scan --score`. The
  old name exits 2 and says so.

Mutants M161 to M195.

## [4.0.1] — 2026-10-27

What the citizen-developer trials found. A local model wrote eight small
apps the way an AI agent writes them for someone who is not a software
engineer (.NET 10 APIs, Python 3.12, Node/TypeScript APIs, Vite/React
UIs), with an answer key. 4.0.0 caught 9 of their 17 planted problems
and raised no real false alarm on 17 decoys. This release closes five of
the misses and makes the citizen brief say what is wrong.

### Added

- **The citizen brief names the problems.** Under the decision, "The
  most serious problems found" lists up to three, one per kind, in plain
  words with the file and line to open ("A secret key or password is
  written into the code: src/supabase.ts, line 5."). The passport keeps
  them in `governance.top_problems`; `--redact` hides the paths. The
  sandbox rules (`P-RUN-001`, `P-RUN-002`) now have plain wording too.
- **Sandbox views.** `detonate` has a terminal view that reads like a
  firewall audit log: the verdict, what ran, and every attempt, ALERTs
  first. Piped, or with `--md`, it prints Markdown as before; `--no-color`
  is new. The HTML passport shows the sandbox run right under the
  decision: each ALERT, and every destination the run tried, marked
  declared or undeclared; each attempt carries `declared`, which the
  shareable copy keeps. The README has screenshots of both.

### Changed

- **JH101** reads a database password inside a connection string
  (`Server=...;Password=...` in `appsettings.json`, `web.config` or a
  DSN in code), and a Supabase service-role key: a JWT whose payload has
  `role: service_role`. The public anon key stays quiet. A password for
  a database on localhost or in a local container is minor: usually a
  development default. Both are redacted in the evidence, a quoted
  password whole however the source quotes it (`\"...\"` in C#, `""...""`
  in a verbatim string, `'...'` with doubled or backslash-escaped quotes
  inside), and so is
  any other secret on a line that another rule reports: every finding's
  evidence now goes through the redactor.
- **JH105** reads TLS checks turned off through Python's `ssl` module
  (`verify_mode = ssl.CERT_NONE`, `check_hostname = False`,
  `cert_reqs=ssl.CERT_NONE`) and .NET's certificate callbacks
  (`ServerCertificateCustomValidationCallback = ... => true`,
  `DangerousAcceptAnyServerCertificateValidator`). A TLS server that
  does not ask clients for certificates stays quiet: that is the default.
- **JH111** reads npm scripts: `"postinstall": "curl ... | sh"` in
  `package.json` runs on every install. Each script is checked on its
  own, read as npm reads the file: the top-level `scripts` only, every
  JSON escape decoded, the last of a duplicated key. Other text in JSON
  stays quiet.
- **JH701** reports a hidden HTML comment in an agent instruction file
  that tells the agent not to ask the user. The same words in visible
  text are a style preference and stay quiet.

### Fixed

- **Deeply nested JSON no longer stops a run.** In 4.0.0 a
  `.jankhunt42.json` nested past Python's JSON decoder limit (about 1,000
  levels on Python 3.9 to 3.11, more on newer ones) stopped `scan`, and
  a deeply nested `package.json`, `.mcp.json` or `.jankhunt42.json`
  stopped `passport`, with a traceback and no report. Every parse of a
  repository, network or user file now treats such a file as unreadable,
  and the npm script reader walks any depth, as npm does.

Mutants M146 to M158.

## [4.0.0] — 2026-10-27

A smaller jankhunt42, and the first release audited whole before it was
tagged: Codex's six findings are fixed inside it. The commands that did not
serve the three questions
are gone or folded in, so the main help now lists eight commands, and
`SKILL.md` is under 200 lines. Alongside that: dependencies' install hooks
in the sandbox, n8n Code nodes, and declared-versus-attempted network
evidence.

### Added

- **`detonate --fetch URL`: run the dependencies' install hooks too.**
  Most install-time attacks hide in a dependency's hook. `--fetch` gets
  the npm packages the lockfile pins, safely, for this run:

  ```sh
  jankhunt42 detonate . --fetch https://registry.npmjs.org/
  ```

  - jankhunt42 downloads exactly the tarballs the lockfile pins. No
    package manager runs online, so no package code runs while fetching.
  - It downloads only from HTTPS origins you name, only from a public
    address, and connects to the address it checked.
  - It refuses redirects and URLs with credentials, dot segments or
    encoded separators, and checks every byte against the lockfile's
    `sha512`.
  - Size limits count every byte received, headers and framing included,
    and a download stops the moment it reaches its limit. Downloads that
    then fail verification or are cut short count too. A URL the lockfile pins to two different
    hashes is refused, and the lockfile is read without following links.
  - The npm cache is built offline in the same sandbox, used for this
    run, and deleted afterwards. The result's `fetch` section lists the
    counts and every refused package; refused packages make coverage
    partial.

  It is the only detonate option that uses the network. See "Fetching
  npm dependencies" in `references/detonate.md`. Mutants M130 to M134
  and M138 to M145.
- **n8n Code nodes are read.** Literal `fetch`, `axios`,
  `this.helpers.httpRequest` and `$http` calls in a Code or Function
  node's JavaScript now appear as calls of that node, with a JSON pointer
  and a code line. The code itself stays an "arbitrary behaviour" unknown,
  dynamic calls and Python stay unknown, and output for ordinary code is
  byte-identical to before. Designed and built by Codex (proposal A12,
  mutants M122 to M129).
- **Declared versus attempted.** With `passport --detonation`, every
  destination the sandbox run tried to reach (each DNS name, each
  address) is compared with what the repository declares: the hosts in
  its own map, plus the operator's network ceiling. Anything else is
  listed, and the new rule `P-RUN-002` asks for review (block in the
  citizen profile). A connection must match the declared port too, and
  every attempt is compared, however many there are. This is evidence of
  intent: what the code tries, set against what it admits to. It only
  adds outcomes, and `--redact` hides the names. Mutants M135 to M137.
- **`scan --score`** shows the Jank Score breakdown (it was `score`), with
  `--fail-policy`. It refuses `--fail-on`, which gates on findings, not
  on the score.

### Changed

- **`score` is now `scan --score`.** The old name still works in 4.0 and
  prints a notice; it goes in 4.1.
- **`triage` and `doctor` leave the main help.** Both still work, as
  debugging helpers.
- **`passport --help` and `review --help` group their options by job:**
  output, the decision, change review, sandbox, change control,
  comparing, supply chain, inputs, and limits. No option changed.
- `--sandbox-network-ceiling` is also accepted with `passport --detonation`.
- **Docs:** `SKILL.md` is under 200 lines, with a shorter description.
  `references/capability-delta.md` and `references/capability-approval.md`
  are now one page, `references/change-review.md`. The debugging
  workflow's native tools and usual suspects moved to
  `references/method.md`.
- A passport's next step for `P-JNK-001` points to `scan --score`. The
  review brief no longer ends with "Then run `jankhunt42 merge`".

### Removed

- **`hunt` and `merge`** (the deep-hunt panel plan and its consensus
  merge), with `references/deep-hunt.md`, `templates/hunt-report.md`,
  `templates/panel-finding.json` and `scripts/jh_hunt.py`. A host agent
  that wants several reviewers can run `review --brief` for each.
- **`report`.** Use `scan --md`, plus `doctor` or `triage` if you need them.

Each removed name exits 2 with a pointer to what replaces it.

## [3.6.2] — 2026-10-27

The last batched precision patch from the mass soak, which has now
stopped.

### Fixed

- **JH104 catches f-string SQL that quotes its value.** A pattern for SQL
  built in f-strings rejected any f-string holding the other quote
  character. So `sql = f"... WHERE name = '{name}'"`, the commonest SQL
  injection shape in Python, was missed once assigned to a variable. It
  is caught now: across our test corpora, 15 more real leads.
- **JH104: column lists made from constants** (`', '.join(ALL_COLUMNS)`,
  `COLS.replace(...)`) are not injection. A list made from a variable, a
  call or an attribute (`BAG.value`) still is.
- **Faster on data-heavy repositories:** duplicate-block detection
  compiles its patterns once, and the n8n check only parses `.json`
  files. Findings are identical.

## [3.6.1] — 2026-10-27

### Security

Fixes from Codex's audit of `passport --detonation`. The audit found no way
for a run to relieve anything, so these concern which run counts:
- **`--base` now binds a run to the commit itself.** The passport used to
  compare against a filtered copy of the commit that dropped executable
  modes. A run on the real tree read as stale, while a run on a stripped,
  different tree could match. The digest now comes from the commit's own
  objects: modes, link targets and bytes (M114).
- **A tree that cannot be read whole matches nothing.** An unreadable
  folder used to count as empty, so a different tree could match (M113).
- **Result files must be re-run.** The digest now records git's executable
  bit over sorted entries (format 2). Results from 3.5.0 and 3.6.0 say
  "re-run detonate" instead of failing to match silently.
- **Shared passports alias sandbox step names** (task labels, server names)
  (M115). Alert kinds outside the known set read "other", including in
  `P-RUN-001`'s message.

Fixes from Codex's audit of the dependency caches (3.6.0):
- **The cache copy can't be steered.** It is one pass:
  - folders are opened from their parent's descriptor, never through a
    link (M116);
  - files are opened without following links and must be regular files;
  - the 768 MB limit counts the bytes actually copied (M119).

  A cache that changes while it is read, or holds the run's own temporary
  folder, can no longer grow the copy or slip in a linked file.
- **A repository can't quietly skip the installs.** pip runs as
  `python3 -I -m pip`, so a `pip.py` in the repository is not used (M117).
  `npm ci` installs dev, optional and peer dependencies whatever the
  repository's `.npmrc` says (M118).
- **Corrected advice:** making a cache can run package code (a source
  build, a git dependency's scripts). The docs now say to make it in a
  disposable, credential-free environment with registry-only network, from
  a hash-locked list you control. The earlier "without running anything"
  was wrong.

## [3.6.0] — 2026-10-27

### Added

- **detonate runs dependencies' install hooks too, offline from a cache
  you supply.** Most install-time attacks hide in a dependency's
  `postinstall`, not in the repository.
  - **npm:** with `--npm-cache DIR` and a lockfile, detonate runs
    `npm ci --offline --foreground-scripts` as one traced step. The
    package's own hooks and every dependency's run inside it, against the
    usual canaries and audit log.
  - **Python:** with `--wheelhouse DIR`, requirements and the build backend
    install offline.
  - **The caches:** each must be a real directory outside the repository,
    at most 768 MB. It is copied into the run, so your directory is never
    written to. detonate still never touches the network.

  A live test builds an invented dependency into a cache offline and sees
  its `postinstall` read the canary. Mutants M120 and M121. See
  "Dependencies" in `references/detonate.md`, including how to make a cache
  without running anything.

## [3.5.0] — 2026-10-27

### Added

- **A sandbox run becomes passport evidence.** Save `detonate --json`
  outside the repository and pass `passport --detonation PATH`.
  - The run counts only if it was made on exactly the tree the passport
    assesses: every result now records a digest of its tree's files,
    executable bits and links. A run on any other tree is shown as not
    used.
  - Its ALERTs (a canary credential read, passed on or sent, or a
    persistence attempt) make the new rule `P-RUN-001` review, or block in
    the citizen profile, as a hard floor.
  - Sandbox evidence only ever adds an outcome. A clean run relieves
    nothing and proves nothing about paths it did not reach.

  The passport gains `sandbox_run` and a "Sandbox run" section, and
  `--redact` removes alert details. Mutants M110 to M112.

- **n8n triggers.** Webhook and Schedule Trigger nodes now show how a
  workflow starts: from an outside request, or unattended.
  - With `passport --base`, a new or changed trigger is a request for IT to
    review, even when the export marks the workflow inactive.
  - Only facts are reported: the methods, the authentication mode, whether
    a filter is declared, and the schedule's units. Routes and cron text
    never appear.

  Designed and built by Codex (proposal A11b, mutants M100 to M105), with
  every matched n8n parameter name checked against the upstream node
  descriptions.

### Security

- detonate: a missing exit status, or one cut short, now makes coverage
  partial. Before, a valid trace with no usable exit status still read as
  complete. Found by Codex while verifying 3.4.1.

### Documentation

- The passport rule table now lists `P-CAP-001` (missing since 3.1.0) and
  `P-RUN-001`.

## [3.4.1] — 2026-10-27

### Security

- **detonate no longer trusts the files the sandbox writes.** The output
  folder is writable by the code under test, but detonate read its exit
  codes, traces and DNS log with ordinary opens. A hook could replace
  `dns.log` with a link to a file the user can read, and the host would copy
  that file into the report. This has been present since 3.0.0. Every
  output file is now read:
  - through the folder's descriptor, never through a link;
  - only if it is a regular file with one link;
  - within size bounds (M96).

  Anything unusable makes coverage partial. Found by Codex.
- **An empty or forged trace no longer counts as observation:** a step is
  traced only if its trace shows the step starting (M97).
- **DNS lines must be host names (M98).** Every repository-derived message,
  including an MCP server's name, is one sanitized line. Report fields are
  escaped, so nothing the code writes can look like a report line.
- **VS Code folder-open tasks follow VS Code more closely:**
  - their `dependsOn` tasks run first, so a payload placed in a dependency
    is run (M99);
  - an escaped space is left unquoted, and strong quoting wraps the value
    as VS Code does;
  - file-wide options and old-format files are coverage gaps.

  Found by Codex.

## [3.4.0] — 2026-10-27

### Added

- **n8n workflows in the map and passport.** Exported n8n workflows (JSON)
  now show what each automation can reach:
  - HTTP services, with host and port;
  - Postgres, MySQL and MongoDB, Google Sheets and Airtable, with the
    operation (read, write or delete);
  - the credentials it uses, by type and name only.

  How it reads them:
  - Expressions, Code nodes, unknown versions and community nodes stay
    explicit unknowns.
  - Nothing is evaluated, run or fetched.
  - With `passport --base`, new access in a workflow is a change for IT to
    review. A late edit or a rewiring of an unresolved node needs review
    too.
  - A secret-shaped literal in a node's parameters is a JH101 lead that
    points at the parameter and never contains the value.

  See `references/n8n.md`. Designed and built by Codex (proposal A11a,
  mutants M83 to M90).

## [3.3.0] — 2026-10-27

### Added

- **detonate runs what a repository runs when it is opened, not only when
  it is installed.** Once a folder is trusted, opening it in an agent or an
  editor can run commands. detonate now runs each one once in the same
  sandbox, with the same canaries and audit log:
  - agent hooks and helper commands (`.claude/settings*.json`,
    `.gemini/settings.json`), each hook with a synthetic event;
  - dev container commands, with `initializeCommand` marked because it
    runs on the host in real use;
  - VS Code folder-open tasks, written as VS Code writes them: an argument
    is quoted only when it has an unquoted space, so `$VAR` and `$(...)`
    stay live as in the editor. Shell, environment and working-folder
    options and unknown variables are coverage gaps. Thanks to Codex's
    quoting baseline (M95);
  - MCP stdio servers, started with one `initialize` request and stopped
    after 20 seconds.

  `--surface install|open|all` picks which; the default is all. See
  `references/detonate.md`.

### Security

- detonate writes each command to its own file and runs it with `sh` under
  the tracer, so repository text never becomes part of the runner (M91).
- detonate never reads a config path that contains a link. A repository's
  `.claude` could point at the user's own settings (M92).
- detonate plans from the snapshot, so what runs is exactly what was read.
- The report shows commands redacted and cut to one line. Step names carry
  repository text (hook events, task labels, server names), so each is one
  plain, bounded line and cannot forge a report line (M94).
- npx reading its own `~/.npmrc` is INFO, like npm.

## [3.2.0] — 2026-10-27

### Added

- **Approve one access change, so CI passes it next time.** After IT
  reviews a `passport --base` comparison:
  - `--emit-capability-approval` prints a pre-filled record with every
    binding: subject, both commits, the comparison, context and policy
    hashes, and the exact request IDs.
  - IT adds the approver, expiry and rationale and keeps the record outside
    the repository.
  - `--capability-approval PATH` then lets that exact comparison pass
    `P-CAP-001`.

  The rules around it:
  - The operator policy names the subject, the allowed approvers and the
    maximum lifetime. A repository policy can only narrow them.
  - Any change in commit, application, analyzer, policy, inventory or
    ceiling, any missing or extra request, an unlisted approver, or an
    expired record invalidates it.
  - Nothing unresolved, truncated or not concrete can be approved.
  - The assurance is `declared-by-operator`, never "verified", and it never
    approves the application.

  See `references/capability-approval.md`. Designed and built by the third
  agent (Codex, proposal A10 v2); mutants M76 to M81.

### Security

- `passport --base`: a file in a language jankhunt42 has no connectivity
  reader for (a shell script, say) is compared whole. An edit far from its
  first line no longer passes as unchanged. Found by Codex. Mutant M82.

## [3.1.2] — 2026-10-27

The day's batched precision patch, from mass-test batches b19 to b24 and
the mass tester's verification pass. Each fix was checked against invented
probes and the test corpora; the maintainer narrowed three of the tester's
proposals before applying them.

### Fixed

- `JH101`: a provider-shaped run inside a long base64 blob, such as
  embedded font or image data, is not a key. A key on its own still is.
- `JH104`: SQL that interpolates only placeholders
  (`f"... IN ({placeholders})"`, built from `?` or `%s`), with the values
  passed separately, is not dynamic. Any other interpolated value stays
  major, even with parameters beside it.
- `JH109`: CORS text inside a sentence of advice or documentation (a quoted
  string of eight or more words, with no `${...}`) configures nothing.
- `JH124` to `JH126`: a match inside a JavaScript regex literal (a
  detector's `/innerHTML|dangerouslySetInnerHTML/`) is not a sink.
- `JH131`: bidirectional characters that sit only inside a regex character
  class in a regex literal (a sanitizer stripping them) are minor, as they
  already were next to a detector word.
- `JH203`: `BUG` counts as a marker only where a marker sits: at the start
  of a comment, or before `:`, `(`, `-` or the end of the line. "The BUG
  reporting pipeline" is prose. TODO, FIXME and HACK are unchanged.
- `JH205`: lines inside a `/** ... */` documentation block (JSDoc, Javadoc,
  PHPDoc) describe code shapes; they are not commented-out code. A plain
  `/* ... */` block still counts.
- `JH502` (Python): a checking helper called on a test-support module
  (`mytestlib.check_ok(...)`, `test_utils.assert_valid(...)`) is an
  assertion. A method of the code under test (`limiter.check_n(...)`) is
  not.

## [3.1.1] — 2026-10-26

### Security

- **`passport --base`: a hook or MCP server whose definition changed no
  longer passes as unchanged.** 3.1.0 treated an item that was unresolved
  at both commits as unchanged without forcing review. But it matched such
  items by their coarse identity, which for hooks and MCP servers leaves out
  the command and its arguments. So replacing a hook's command, or changing
  an MCP server from `--scope read` to `--scope admin`, passed `P-CAP-001`.
  - Such an item now counts as unchanged only when its definition is
    demonstrably the same. For an MCP server that means its command,
    arguments, environment and header names, URL and transport (a changed
    credential value alone does not count). For anything else, it means
    the text around its evidence, so moving code is still no change.
  - Anything else is reported as `definition-changed` and needs review.
  - Nothing compared is exported.
  - Found by the third agent (Codex) the hour 3.1.0 shipped. New mutant
    M74.
- **`passport --base --redact`: unchanged unknowns are redacted too.** The
  shareable copy redacted `unknowns` but not 3.1.0's `unchanged_unknowns`,
  so the name of an MCP server could survive. They now get the same
  ID-and-detail-only projection. Also found by Codex. New mutant M75.

## [3.1.0] — 2026-10-26

From the third agent's proposal A10, reviewed and adjusted by the
maintainer.

### Added

- **What new access does this change ask for?** `jankhunt42 passport .
  --base REF` compares two commits, read from Git objects only (uncommitted
  files are left out and no code runs), and lists the access the newer one
  asks for:
  - new hosts and ports;
  - credentials read or passed (names only);
  - new write, delete or admin authority and scopes;
  - new production reach;
  - new agent capabilities (MCP servers, approval bypasses, hooks).

  Each request comes with evidence. Requests are compared by who does what
  to which target, so moving code adds nothing.
  - **The decision:**
    - New `P-CAP-001` sends new or newly unresolved access to review.
    - An incomplete comparison falls to the `P-COV-001` floor.
    - With `--sandbox-network-ceiling`, each new host is marked within or
      outside IT's approved list.
  - **The comparison cannot be gamed:** repository ignore globs, inline
    suppressions and disabled rules do not apply to it. Production writes
    rank first, so a flood of harmless hosts cannot bury them. Counts drive
    policy before display limits.
  - **Unresolved items are judged by what changed:**
    - newly unresolved: needs review;
    - unresolved at the base and apparently resolved now: needs review;
    - unresolved in both: listed as unchanged, without forcing review.
  - **Output:** the passport field `capability_delta`, plain approver
    lines in Markdown and the terminal, `references/capability-delta.md`,
    and mutants M64 to M71.
  - **Deferred:** recorded external approvals of a delta, registry
    changes, and renamed principals.

## [3.0.0] — 2026-10-26

### Added

- **`jankhunt42 detonate`: run the install hooks in a sandbox and log what
  they try.** Static analysis says what code could do; `detonate` runs a
  repository's own npm hooks (`preinstall`, `install`, `postinstall`,
  `prepare`) and Python build (`setup.py`, a pyproject backend) in a
  disposable rootless container and reports what they attempt.
  - **The sandbox:**
    - the network is off;
    - the root filesystem is read-only;
    - every capability is dropped, with `no-new-privileges`;
    - processes, memory, CPU and time are limited;
    - the repository is snapshotted without `.git` or followed links;
    - fresh, never-issued canary credentials (AWS, GitHub, npm, SSH, `.env`)
      sit in a throwaway, read-only home;
    - everything is deleted afterwards.
  - **The audit log:**
    - DENY for every attempted connection and every DNS name, from a
      loopback DNS sink;
    - ALERT for a canary read, a canary passed to a program or written to
      a socket, and a write into a startup or login path;
    - INFO for expected behaviour, such as npm reading its own `~/.npmrc`.

    Each event names the command and hook that caused it. Reports carry
    canary IDs, never values.
  - **The evidence tier is `sandbox-observed`:** it adds to static findings
    and never refutes them. Coverage is `partial` when dependencies were
    not installed (the network is off), a hook timed out, or a trace is
    missing.
  - It is opt-in, needs podman or docker and an image built once from
    `templates/detonate.Containerfile`, and never pulls an image or builds
    a repository's Dockerfile.
  - See `references/detonate.md`. New mutants M72 and M73.

## [2.9.4] — 2026-10-26

From mass-test batch b18.

### Fixed

- `JH101`: a form or validation message under a password or token key
  (`errors.password = "Password is required"`, `"Token must be 32
  characters"`) is text, not a credential.
- `JH124` to `JH126`: HTML set from a name written as a constant
  (`innerHTML = EYE_ICON_SVG`, `open ? EYE : EYE_OFF`,
  `__html: THEME_INIT_SCRIPT`) is minor. Such names usually hold fixed
  markup, but a name is a convention, not proof, so it is still shown.
  Markup from any other variable stays major.
- The skill description is 998 characters, so the skills-hub listing shows
  all of it; a test keeps it within 1000.

## [2.9.3] — 2026-10-26

### Changed

- The skill's description (`SKILL.md`, which agents read to decide when to
  use it, and the skills-hub listing) now leads with its purpose: catching
  the jank in software that citizen developers build with AI coding
  agents, and helping decide whether it can ship. It names when to use it:
  a non-engineer building with Claude Code, Cursor or Codex, an IT,
  security or engineering approver, or any repository.

### Fixed

- `JH701`: an override phrase passed to code, such as a string argument or
  a list item in a skill's code example
  (`jailbreak_score("Ignore previous instructions")`,
  `"excludes": ["ignore previous instructions"]`), is minor: the file hands
  the phrase to a detector rather than telling the agent to obey it. A bare
  quoted command in prose is still major. From mass-test batch b17.

## [2.9.2] — 2026-10-26

From the third agent's proposal A7, verified by the maintainer.

### Changed

- **Faster on large repositories, with identical results.** The tokenizer
  that splits each file into code, comment and string views now jumps
  straight to the next character that could open a string, comment or
  regular expression, instead of stepping through every character. On a
  1.3-million-line TypeScript repository, `scan` takes 12% less time
  (37.1 s to 32.6 s) and `passport` 10% less (75.8 s to 68.1 s), with
  byte-identical output.
  - The views are identical for all 70,386 files of the maintainer's test
    corpora (35 languages) and for 11,535 constructed cases, including
    unterminated strings, nested templates, heredocs, regular expressions
    and very long lines.
  - New `tests/test_tokenizer.py`; mutants M56 to M63.

## [2.9.1] — 2026-10-26

From mass-test batches b14 to b16 and the mass tester's verification pass.
The maintainer narrowed the tester's proposal before applying it.

### Fixed

- `JH702`: the approval-bypass flag inside a descriptive JSON field
  (`"description"`, `"title"`, `"summary"`, `"help"` and similar) is minor:
  a project catalogue that mentions the flag launches nothing. Only those
  keys are downgraded. The flag under any other key stays major, because a
  devcontainer's `postCreateCommand`, a task's `args` or an unknown key may
  be what a tool runs. New mutant M55.

## [2.9.0] — 2026-10-26

From the third agent's proposals A4 and A6, reviewed by the maintainer.

### Added

- **An operator network ceiling** for the sandbox policies jankhunt42
  writes. `passport --emit-sandbox-policy openshell|claude-code
  --sandbox-network-ceiling PATH` keeps only the destinations the code
  reaches **and** an external approved list allows, so IT can cap the
  policy a citizen developer's repository produces. The ceiling only
  removes destinations, never adds them; production assets stay excluded.
  - The file must sit outside the scanned repository and any enclosing Git
    repository, without symbolic or hard links. It is at most 64 KiB,
    with exactly the documented fields, and must not change while it is
    read.
  - Codex output refuses a ceiling, because Codex domain rules drop ports.
  - See `references/network-ceiling.md`. New mutants M39 to M54.
- **Claude Code policies can carry ports.** With a ceiling,
  `allowedDomains` entries are port-qualified (`api.openai.com:443`), one
  per host and port. Without one, output is unchanged (port-less entries
  allow every port). Port-qualified entries are verified on Claude Code
  2.1.310 only; earlier versions are unverified, and jankhunt42 says so
  when it writes them.

### Changed

- Reading a Claude Code allowlist back (`map`, `passport`): a port-qualified
  entry admits that port only, a port-less one every port. When the port
  the code uses is unknown, the endpoint is unassessed, not guessed. An
  entry jankhunt42 cannot parse (a URL with a path, say) makes that tool's
  coverage `unknown` instead of being read loosely. Egress rows carry
  `port` where it is known.

## [2.8.1] — 2026-10-26

From mass-test batch b16, verified by the maintainer against invented
probes and the test corpora (eight findings dropped, none added).

### Fixed

- `JH102`: a TypeScript method declaration named `eval`, with a return type
  (`eval(script: string, ...args: unknown[]): Promise<unknown>;` in an
  interface), declares a method; it does not call one. A real `eval(code);`
  is still reported.
- `JH104`: SQL made of fixed strings joined with `+`
  (`"DELETE FROM t " + "WHERE id = ?"`), up to the end of the argument, is
  not dynamic. Any f-string, template, interpolated (`$"..."`) string, `%`
  formatting or variable in the chain is still reported.
- `JH105`: `insecure: true` inside a test expectation
  (`expect(...).toMatchObject({ insecure: true })`) describes a result; it
  turns nothing off.
- `JH210`: creating, binding or listening on a socket in an `async def` does
  not block (asyncio's `loop.sock_*` functions need exactly that).
  `socket.create_connection` still does.

## [2.8.0] — 2026-10-26

From the third agent's adversarial review (finding A2), revised by the
maintainer.

### Changed

- **Egress coverage no longer credits a declaration that does not apply.**
  The map and passport compare the hosts an app reaches with the network
  allowlists the repository commits. Until now every allowlist in the
  repository counted, even an inactive Codex permission profile, a disabled
  sandbox or proxy, or another tool's file.
  - Codex permission profiles are read separately, and only the one that
    `default_permissions` selects counts. A disabled proxy or profile
    network, a string such as `"true"` where a Boolean belongs, a legacy
    `sandbox_mode` selector, unmodeled inheritance, or syntax this reader
    does not fully understand makes coverage `unknown` rather than guessing.
  - A Claude Code allowlist counts only when `sandbox.enabled` is `true`
    and no custom proxy port replaces the built-in filtering.
  - Each tool is assessed on its own. When every tool's selected
    declaration resolves, the result is `declared`, and a host is outside
    when any one tool does not admit it; each outside host names those
    tools. The three policies `--emit-sandbox-policy` writes therefore
    still read back as `declared` when committed together. Two settings
    scopes of one tool make coverage `unknown`, because their merge is not
    modeled.
  - When coverage is `unknown`, `egress.unassessed` lists the reached hosts
    whose coverage could not be decided, and the Markdown, terminal and
    HTML views say so instead of leaving the section out.
  - New fields: `egress.contexts`, `egress.unassessed`, boundary
    `profile`, `selected` and `enabled`, and `contexts` on each outside
    host. `--redact` keeps counts only. New mutants M35 to M38.

### Fixed

- `JH103` now covers JavaScript and TypeScript. Its Node patterns
  (`child_process.exec`, `execSync`) existed since 0.2.0 but never ran,
  because the rule's language list left those languages out. A command
  built with a template literal (`execSync(\`git tag ${name}\`)`) or passed
  in a variable is major. Found while checking mass-test batch b15.
- `JH103`: a fixed command string for `os.system`, `os.popen`,
  `commands.getoutput`, `execSync`, `child_process.exec` or `IO.popen`
  (`os.popen("git rev-parse HEAD")`) is minor, as `shell=True` with a fixed
  literal has been since 2.7.4. An f-string, a `${...}` template, Ruby's
  `#{...}`, `%` or `.format()` formatting, concatenation or a variable stays
  major.
- `JH101`: a value written in a non-Latin script, such as a translated
  label under `api_key:` in a locale file, is text, not a credential.

## [2.7.5] — 2026-10-26

From mass-test batches b08 to b13 and the third agent's adversarial
review. Each fix arrived as a tested proposal and was verified, and where
needed corrected, by the maintainer.

### Security

- `passport --emit-sandbox-policy`: the Claude Code policy's own output
  gate now also requires `failIfUnavailable: true`,
  `allowUnsandboxedCommands: false` and every credential read-deny the
  emitter writes. Today's output already has them; the gate stops a future
  change from handing over a weaker policy. Extra denies are still
  accepted. New mutant M34.

### Fixed

- `JH107`: two digests that guard nothing are not reported: the hashing
  trick `int(<digest>, 16) % n`, which reduces a digest to a bucket
  number, and Git's object hash `sha1(b"blob %d\0" ...)`. If the same
  statement names a security use (a password, token, signature, one-time
  code), it stays major, so an MD5 one-time code built with the same trick
  is still reported.
- `JH212`: a test double defined with the matched name
  (`def urlopen(req, timeout):`) is not an HTTP call.
- `JH415`: the `kind: Secret` check is made per document. A ConfigMap's
  `data:` in a file that also holds a Secret is plain configuration, not a
  committed secret; the Secret document's values are still reported.
- `JH424`: `"*"` or `"latest"` inside `peerDependencies` is info, not
  minor. An open peer range is the usual way to accept the host app's
  version, but npm 7 and later install a missing peer themselves, at the
  newest release, so it is still reported, at info (shown with
  `--min-severity info`). Direct and dev dependencies are unchanged.
- `JH426`: `npm install -g` and `npm install --global` install a tool,
  not the project's dependencies, so the "use npm ci" advice does not
  apply. A plain `npm install`, with or without package names, is still
  reported.

## [2.7.4] — 2026-10-26

From mass-test batch b08 and an adversarial review by a third agent (Codex
CLI). Each change was verified, and where needed corrected, by the
maintainer.

### Security

- **Static commands no longer run code that a repository's own Git
  configuration names.** With a repository-local setting, 2.7.3 ran it:
  even `scan` ran a `core.fsmonitor` hook through `git ls-files`, and
  `review` ran a `diff.<driver>.textconv` converter. Normal clones do not
  copy `.git/config`, but a shared folder or archive that includes `.git/`
  does.
  - Every Git call now goes through one runner. It overrides, on the
    command line, fsmonitor, hooks, external diff, pager,
    `log.showSignature`/`gpg.program`, credential helpers, network
    transport and submodule recursion.
  - It blanks every configured clean, smudge and process filter by name,
    including names containing `=`.
  - It adds `--no-ext-diff --no-textconv` to diffs.
  - It never writes the index (`GIT_OPTIONAL_LOCKS=0`), so index hooks
    cannot fire.
  - It drops inherited variables that name a program (`GIT_EXTERNAL_DIFF`,
    `GIT_SSH_COMMAND`, `GIT_PAGER`, editors). `GIT_DIR`, `GIT_WORK_TREE` and
    `GIT_INDEX_FILE` are kept, so `review --staged` in a pre-commit hook
    still reads the commit's own index.
  - A blanked filter is marked `required=false`, so a Git LFS repository
    (whose filter is required) still diffs.
  - `tests/test_git_safety.py` proves that seven such paths run under
    plain Git and that none of them runs under `scan`, `map`, `map --base`,
    `passport`, `review`, `review --base`, `doctor` or `score --since`.
    New mutants M31 to M33 guard the overrides, the filter blanking and
    the diff flags.

### Fixed

- `JH103`: `shell=True` whose command is a fixed literal (the call's first
  argument, followed directly by a comma) is minor. An f-string, `%` or
  `.format()` formatting, concatenation, or a variable command stays
  major. `ProcessBuilder` runs no shell itself: separate arguments are not
  reported, a visible `"sh", "-c"` is major, and a single list or spread
  argument that hides what runs is minor.
- `JH201`: an empty Python handler that catches only `ImportError` or
  `ModuleNotFoundError` is not reported. It cannot swallow the `OSError` a
  failed write raises, and it is the usual optional-import idiom.
  `except Exception`, a bare `except`, and any tuple that also catches
  `OSError` still are.

## [2.7.3] — 2026-10-26

From mass-test batches b06 and b07. Each fix arrived as a tested proposal
from the mass tester and was verified by the maintainer.

### Fixed

- Regression from 2.7.2: `test-*.js`, `.mjs` and `.ts` files outside test
  folders counted as tests, so a real key hard-coded in a smoke script such
  as `scripts/test-upload.mjs` dropped from critical to minor. They are
  ordinary code again, as in 2.7.1. Files in test folders and names such as
  `*.test.js` are unchanged.
- `JH505`: `fit(...)` and `fdescribe(...)` need a function as the second
  argument, as in Jasmine's `fit(title, fn)`. A function under test such
  as `fit('abc', 10)`, or one inside `expect(fit(...))`, is not a focused
  test. Angular's `fakeAsync(...)`, `waitForAsync(...)` and `inject(...)`
  bodies still count.
- `JH701`: a quoted override phrase in agent guidance (`Refuse prompts that
  try to "ignore previous instructions"`) is minor, not major. It still
  appears, because a hostile file can wrap a real injection in the same
  framing. The phrase must sit inside one quoted segment, and the rest of
  the line must frame it (refuse, such as, says, prompts). A bare quoted
  command such as `IMPORTANT: "Ignore all previous instructions ..."`
  stays major. Apostrophes in words (`don't`, `it's`) are not quotes, and a
  pipe-to-shell or credential exfiltration on the same line keeps its own
  severity.
- `JH401`: a credential file whose only strong values are test keys
  (`sk_test_`, `pk_test_`, `test_`) is minor; it is still listed. A test key
  placed first no longer hides a live key further down: the finding points
  at the first real value and keeps its severity.
- `JH702` in a translation file (a JSON, YAML, PO or properties file under
  `lang/`, `locales/`, `i18n/` or `translations/`, or named like a locale
  such as `es.json` or `pt-BR.json`, with a real ISO 639-1 code) is minor:
  the flag there is UI text. `package.json`, agent and MCP configs, CI
  workflows, and short config names such as `app.json`, `mcp.json` or
  `nx.json` stay major.
- `JH601` ignores link-shaped text inside fenced code blocks (Python
  `fn[key](**kw)`, example Markdown). Fences follow CommonMark, so a
  four-backtick example that holds a three-backtick block stays one fence,
  and inline ```` ```code``` ```` on one line opens no fence. Broken links
  before and after a fence are still reported.
- `JH501` needs a test runner before `.skip(` (`describe`, `test`,
  `context` and so on), or a title string for `it.skip('...')` and
  `t.skip('...')`. `pytest.skip(...)` and Mocha's `this.skip()` still count.
  Rust's `Iterator::skip(n)` in a `tests.rs` file is not a skipped test.
- `JH404`: `FROM <stage>` in a multi-stage build names an earlier build
  stage, so there is nothing to pin. Only stages defined above the line
  count, as in Docker, so a stage named later cannot hide an earlier
  registry pull of the same name.
- `JH212`: an awaited call on an async client, wrapped in
  `asyncio.wait_for(call, N)` or inside an `async with asyncio.timeout(N):`
  block (or `anyio.fail_after`), has a timeout. The synchronous `requests`,
  `httpx` and `urlopen` functions are not covered by an asyncio deadline,
  which cancels only at an await, so they are still reported. A `None`
  deadline does not count, and neither does a wrapper after the call.
- `JH212` and `JH213`: `timeout=None` is explicitly no timeout, so it is
  reported. It used to count as having one.
- `JH210`: `subprocess.Popen(...)` returns a handle and does not block the
  event loop. Waiting on it does, and is still reported: a chained
  `.wait()` or `.communicate()`, the same call on the handle later
  (`proc.communicate()` or `self.proc.wait()`), a blocking read of its
  pipes (`proc.stdout.read()`, `for line in proc.stdout`), and leaving a
  `with subprocess.Popen(...)` block.

## [2.7.2] — 2026-10-25

From the fifth mass-test batch (40 vibe-coded repositories, claims verified
by the maintainer), and one gap it pointed to.

### Added

- `JH101` reads credentials written as a quoted key (`"db_password": "..."`
  in JSON or a Python dict) or a prefixed name (`DB_PASSWORD = "..."`,
  `AWS_SECRET_ACCESS_KEY = "..."`, `SERVICE_API_KEY: '...'`). Neither form
  matched before. The value must look like a credential: no spaces, a
  letter and a digit, and no words such as "test", "fake", "e2e" or
  "secret". UI text such as `"password": "Mot de passe"` therefore stays out.
- Redaction covers the same forms in every rule's evidence (JSON, SARIF,
  Markdown, HTML and terminal), so a report never repeats the credential
  it found.

### Fixed

- `JH505` needs a test runner before `.only(` (`describe`, `it`, `test`,
  `context`, `suite`, `test.describe.serial`, `Deno.test`, `QUnit.module`,
  `tap`, `.only.each` and so on). A builder method such as Go's
  `picker.only(t)` is not a focused test.
- `JH504`: `expect(true)` counts only with a matcher that passes
  (`toBe(true)`, `toBeTruthy()`, chai `.to.be.true` or `.to.be.equal(true)`).
  `expect(true).toBe(false)` is an always-failing guard, not a tautology,
  including when the matcher is on the next line.
- `JH104`: SQL in a quoted literal that closes before a `${...}` is
  parameterized. The interpolation is a later bound argument
  (`.query("... ?2").run(id, \`u:${id}\`)`).
- `JH111`: `echo "curl ... | sh" | sh` used to be skipped as printed text,
  but it pipes the text into a shell, so it is now reported. In a shell
  script, a pipeline inside a quoted argument of a command that only
  reports it (`echo`, `warn`, `require_tool zz "... (curl ... | sh)"`) is
  minor, with an install-hint note. Any other command word (`retry`,
  `trap`, `alias`), a `$(...)` inside the quotes, or a pipe or redirect
  after them keeps it critical, as do `sh -c`, `ssh`, `eval` and CI YAML.
- Test-path detection also covers test-support folders (`testutil/`,
  `test_support/`, `apitest/`, `test-vectors/`, Jest's `__mocks__/`) and
  `test-*.js`/`.ts` scripts.

## [2.7.1] — 2026-10-25

From the third and fourth mass-test batches (160 vibe-coded repositories,
claims verified by the maintainer).

### Fixed

- **A JavaScript or TypeScript regular expression containing `//`**
  (`/^https:\/\//i`) was read as the start of a line comment. The rest of
  the line went missing from the code view, which every pattern rule reads,
  and turned up as "commented-out code". Regex literals are now skipped
  whole; division is still division, and so is a slash after a JSX closing
  tag (`</div>`) or a postfix `i++`. A regex holding a quote or backtick
  (``/[`'"]/``) could also open a phantom string that hid many lines, so
  real `innerHTML` and `dangerouslySetInnerHTML` sinks after one now show.
- **Minified bundles** are recognised by a build-output name or path
  (`.min.js`, `dist/`, `assets/`, `vendor/`, hashed chunk names) together
  with their shape, so one long string cannot turn a hand-written file into
  a "bundle". Secret, hidden-Unicode and agent rules still read them; other
  code rules do not, because findings there are noise. Every such file is
  listed (`minified` in `--json`, a line in the report), so the skip is
  never silent.
- `JH101` and other rules with ignore words: on a long line, an ignore word
  counts only near the match. A single `<b>` in a one-line bundle no longer
  hides every key in it. A generic `password = '...'` inside a long row of a
  dataset (`.jsonl`, `.ndjson`, `.csv`, `.tsv`) is minor, because it is
  usually sample text. A single-line JSON config stays critical, and so do
  provider-shaped keys everywhere.
- `JH132`: a public-prefix name inside a plain string (a rule's
  documentation example) is text, not an environment read. A read inside a
  template literal's `${...}` still counts, and so does a CI workflow that
  binds a secret into a `NEXT_PUBLIC_` variable for the build, which bakes
  the secret into the public bundle. A Svelte or Vue `{...}` attribute is
  code.
- `JH502`: a test runner's own definition (`async function test(name, fn)`)
  is not a test, and calls to assertion helpers defined in the same file
  (`near(a, b)`, `close(x, y)`) count as assertions when the helper's own
  body asserts. Testing Library queries (`getBy*`, `findBy*`) throw when
  nothing matches, so they count too.
- `JH601`: documentation macros (`:git:repo:path`), placeholder targets with
  no Latin letters, digits, dots or slashes (`链接`), and links in template
  files (`page_template.md`, `templates/`) are not broken links. GitHub's
  pull request and issue templates are still checked.
- `JH203`: a lowercase `todo:` counts only right after a comment marker, so
  "para todo: un enlace" in a Spanish comment is prose.
- `JH107`: a hash assigned to an identifier-like name (`cache_key`, `etag`,
  `user_id`), with a cache or checksum comment just above, or used as a
  cache key on the next line is minor. Security words in the statement
  (`password`, `token`, `api_key`) keep it major.
- `JH109`: FastAPI/Starlette `allow_origins=["*"]` without
  `allow_credentials` is minor; Starlette then sends a literal `*`.
- `JH210` uses the innermost enclosing function. A blocking call inside a
  sync helper nested in an `async def` is not on the event loop, and a
  nested async function reports its own lines once. It is minor in tests.
- `JH701` needs a real pipeline (a URL, a flag or a variable after `curl` or
  `wget`, or a bare host such as `curl get.example.dev/i.sh | sh`). A table
  cell describing "curl|bash of unpinned URL" is prose.
- `JH702` is minor in test code, where the flag is usually fixture text.
- `JH124` to `JH126`: a value sanitized a few lines up (`const html =
  useMemo(() => DOMPurify.sanitize(md))`) is minor, only when the sanitizer
  is that assignment's whole right-hand side.
- `JH131`: bidi characters inside a detector's own regex character class
  (`BIDI_OVERRIDE = /[...]/`) are minor when every bidi character on the
  line sits inside a class. They are still reported, and stay critical in
  agent files.

## [2.7.0] — 2026-10-25

Fence the agent. An AI coding agent runs commands with the developer's
network; jankhunt42 now writes the least-privilege fence from what the code
actually reaches.

### Added

- **`passport --emit-sandbox-policy {claude-code,codex,openshell}`:** a
  default-deny network allowlist for an AI coding agent in the tool's native
  format: Claude Code settings JSON, a Codex permission profile, or an
  OpenShell policy.
  - **In:** the hosts the code reaches, the public endpoints of services it
    names without a host, and its package registries.
  - **Out**, listed for a decision: production assets (give the agent a
    non-production endpoint), unresolved endpoints, local services, and
    host names that are not plain DNS names (a hostile name cannot become a
    rule).
  - Each tool's enforcement limits are stated with the policy. For example,
    a Claude Code project file only pre-allows hosts until
    `strictAllowlist` is set in user or managed settings.
  - Ports come from the code. Map nodes now carry the `port` they were
    parsed with, an additive attribute; plain `http` defaults to 80.
  - Only jankhunt42's own table of well-known services adds wildcard hosts;
    a wildcard read from the repository is excluded.
  - Every YAML scalar is quoted, so a host named `true` stays a host.
  - The output is deterministic, checked against the documented subset
    before it is printed, and reads back through jankhunt42's own boundary
    readers as the same allowlist. It is a review artefact that is never
    applied. Mutants `M29` (unchecked host) and `M30` (production in the
    fence) are killed.

### Fixed

- The egress boundary reader dropped Codex domain rules with a trailing
  comment (`"api.example.com" = "allow"  # why`), so a commented boundary
  read as missing.
- The map read prose starting with "merge into ..." as an SQL write; `MERGE
  INTO` now needs its `USING` clause, on the same line or the next (T-SQL
  table hints allowed).
- The TOML comment stripper let an escaped `\"` end a quoted string.
- From the first two mass-test batches of vibe-coded repositories (80
  repositories, findings verified):
  - **`JH101`:** a CSS selector (`password: "#login-password"`) or a
    capitalised label (`apiKey: 'Client ID'`) is not a secret. Password
    keys keep the stricter reading.
  - **`JH203`:** markers are case-sensitive words, so Spanish *todo* and a
    phone format (`XX XXX XX`) no longer count.
  - **`JH205`:** a trailing brace in prose ("the slug inside {}") is not
    commented-out code.
  - **`JH124`:** joins the constant-HTML check (a print template with no
    interpolation).
  - **`JH124` to `JH126`:** a value passed through a sanitizer is minor, and
    so is the shadcn/ui chart theme block.
  - **`JH502`:** recognises assertion helpers by name (`self.rejected(...)`)
    and an arrow-function body on the next line.
  - **`JH102`:** a JS method named `eval` (`async eval(expr) {`) is a
    definition, and a constant string passed to `setTimeout` or
    `setInterval` is constant code.
  - **`JH101`:** a match that runs from one string argument into the next
    (`log("secret:", token ? "yes" : "no")`) is not a literal.
  - **`JH125`:** a translation looked up by a constant key (`t("help.body")`)
    is minor.
  - **`JH107`:** MD5 or SHA-1 for an identifier, cache key or checksum is
    minor; `usedforsecurity=False` is skipped. A digest near passwords,
    tokens, signatures or sessions stays major.

## [2.6.2] — 2026-10-25

Precision for what a user sees. A second labelled sample took every critical
finding and 120 random majors from three corpora of public repositories, so
rules appear as often as they fire. On that sample, 2.6.1's majors were a
true lead only 12% of the time; most were best-effort error handling,
bearer-token CORS and SQL that is already parameterised. With 2.6.2, 78% of
the criticals and 29% of the majors that remain are true leads, and no true
lead in the sample changed.

### Changed

- `JH201` (empty error handler) is minor unless the swallowed call decides an
  outcome (verify, authenticate, save, commit, pay, publish, deploy, a
  database update or delete, an API write...) or the code goes on to claim
  success. The try block is found by matching braces, so a nested try does
  not hide the call. Then it stays major and says which call. A
  handler followed by `raise` or `throw` is cleanup on an error path. The
  rule catalog keeps major as the rule's ceiling.
- `JH109` is minor for a literal wildcard origin without credentials:
  browsers send no cookies to a wildcard origin. With `Allow-Credentials` (or
  a framework's credentials option) it stays major, and so do framework
  switches that may reflect the origin (`CORS_ORIGIN_ALLOW_ALL`,
  `allow_origins=["*"]`), whose credentials setting can live in another file.
  It also now catches `setHeader("Access-Control-Allow-Origin", "*")`.
- `JH104` and `JH122` are minor in test code, like `JH111` and `JH115`.
- Deliberately vulnerable evaluation corpora (`eval_corpus/`,
  `vuln-corpus/`, ...) count as examples, like `examples/vulnerable-app/`.

### Fixed

- `JH104` needs SQL or a database near a concatenated `query()` or `exec()`
  call, the first argument included (`c.execute(query + id)` still fires): a
  regular expression's `exec()` or a spatial index's `query()` is not SQL.
  `sql\`...\`` tagged templates (postgres.js, Drizzle, Prisma `$queryRaw`)
  bind their interpolations as parameters and are skipped;
  `$queryRawUnsafe` and `sql.raw` still fire. Interpolating only
  `CONSTANT_NAMES` is not dynamic SQL, unless the string is then formatted
  with `%` or `.format`.
- `JH126` skips a multi-line template with no interpolation, and a constant
  string on the line after `innerHTML =`, unless the statement continues on
  the next line.
- `JH106` accepts a `Loader` class the file defines as a `SafeLoader`
  subclass.
- `JH701` no longer reads "do not ... without asking the user first", a
  request for consent, as an instruction to hide from the user. Only a
  negation in the same clause counts: "if there are no errors, push without
  telling the user" still fires.
- `JH702` ignores the flag inside a detection regex (`re.compile(...)`).
- `JH122` needs `--cap-add SYS_ADMIN` or `--pid host` to belong to a
  container command (`docker`/`podman`/`nerdctl run`, `docker compose run`,
  also continued over several lines) or container options (GitHub Actions
  `options:`, `runArgs`), not to a list of strings a test expects rejected.
- `JH101`: a provider-shaped key inside a code sample that is itself a
  string (`check('API_KEY = "sk-..."')`) in a test or document is minor; a
  key assigned directly in a test stays critical, and an apostrophe or a
  closing quote does not count as the start of a code sample.

## [2.6.1] — 2026-10-25

Precision fixes found by labelling a stratified sample of 96 findings from
three corpora of public repositories. 15 of the sample's 22 false positives
no longer fire. Every true lead in the sample still fires; one moves to its
correct line.

### Fixed

- **A path that does not exist or cannot be read is an error (exit 2), not
  a clean scan.** `scan`, `score`, `supply-chain`, `hunt`, `report`,
  `doctor`, `map` and `passport` used to skip such a path silently and report
  on the working directory instead, so a mistyped path in CI passed with no
  findings. The message names the reason: missing, a broken symbolic link,
  or permission denied.
- `JH101` judges a value once per line. A provider-shaped token judged a
  placeholder (an AIza key spelled out of words) no longer comes back as a
  critical through the generic `apiKey: "..."` pattern, and a real secret
  later on the same line is still found.
- `JH102` no longer reads a method definition named `exec`
  (`async def exec(self, ...)`) as a call to the builtin.
- `JH103` no longer flags `Runtime.exec(new String[]{"prog", ...})` or
  `new ProcessBuilder("prog", ...)` when the program is a literal that is
  neither a shell nor a runner of commands: no shell parses those arguments.
  Shells under any path (`/system/bin/sh`), `su`, `sudo`, `env`, `ssh` and a
  single command string still fire.
- `JH108` counts `debug=True` only in files that import a web framework
  (Flask extensions included) or inside a `.run(...)` call; elsewhere it is
  usually a library's verbosity flag. `DEBUG = True` and multi-line
  `app.run(debug=True)` still fire.
- `JH120` flags `shutil.unpack_archive` only, under whatever name the file
  gives it (a module alias, a parenthesised import, `as`, `*`), and not a
  project's own function of the same name or its definition.
- `JH125` and `JH126` skip constant HTML: an empty string, a literal with no
  interpolation, or a template that interpolates only `CONSTANT_NAMES`. A
  statement that goes on to the next line (`+ message`) is not constant.
  Files that used to reach the per-file limit of five now show leads it hid.
- `JH505` needs a title string (quotes or backticks) after `fit(` or
  `fdescribe(`, reads the code view so text inside a test title is not a
  call, and ignores `model.fit(...)`.
- `JH703` reports the `"Bash"` entry of the allow list, not an earlier hook
  matcher with the same text.
- `JH122` is downgraded in test code like `JH111` and `JH115`.

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
- `map --base`: a capability that becomes unknown goes in its own list,
  `authority_became_unknown` (possibly read, write or destroy), never among
  reductions. An unknown capability that becomes known is an escalation
  marked `was_unknown`. Before, read to unknown counted as less authority.
- `passport --branch-rules` accepts JSON lists (a list of rulesets, or the
  `rules/branches` export), as documented.
- Change control and package sources, from a review of the first 2.6.0
  commit:
  - Bypass visibility is judged per ruleset, and a `GET /rulesets`
    summary list is unknown, not an unprotected branch.
  - Terraform declared for another repository does not count.
  - The gate template passes the repository's default branch.
  - Maven `distributionManagement` targets are not package sources, and
    PyPI's file host counts as PyPI.
  - Credentials in registry URLs never reach a report.
  - Lockfiles in test, fixture and excluded paths are skipped.
  - `P-SUP-001` honours `off`.
- Under the citizen profile, every `insufficient-evidence` reason says that
  the citizen pull-request gate stops the merge until the evidence is
  supplied.
- Committed secrets keep their severity inside deliberately vulnerable
  examples. `JH432` treats only one exact-branch `if:` as pinned
  (`startsWith(github.ref, 'refs/heads/claude/')` is not).
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
