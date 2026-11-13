# Citizen developers and AI agents: governing the blast radius

People who are not software engineers now build and ship software with AI
coding agents. They become custodians of software without an engineer's
habits, and their software inherits the reach of whatever it is wired to:
their own credentials, the tools their agent connects to, and production
data. jankhunt42 governs that reach in three steps. All three are offline
and static, and none of them infers who wrote the code.

```sh
jankhunt42 scan . --category agent          # what an AI agent would do when it opens or works in this repository
jankhunt42 map .                            # what the software and its agent tooling can reach
jankhunt42 passport . --profile citizen     # a strict release decision, explained in plain terms
```

## The failure classes this targets

| Class | Public example | What jankhunt42 checks |
|---|---|---|
| Data store left open to the internet | Lovable-generated apps without row-level security (CVE-2025-48757, reported May 2025); the Tea app's open Firebase storage (July 2025) | `JH134`: open Firebase/Firestore rules, disabled row-level security, `USING (true)` write policies, public buckets, and Supabase tables that the migrations, read together, leave without row-level security (critical when granted to `anon`); `JH154`: policies that trust `user_metadata`; `JH155`: views that bypass row-level security or expose `auth.users` |
| Secret shipped to every visitor | a payments secret key in client-side JavaScript of an AI-built app (reported February 2026) | `JH132`: secrets under `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` and similar prefixes, including Supabase `service_role` keys; `JH133`: `dangerouslyAllowBrowser` LLM clients |
| Agent runs without asking | the s1ngularity npm malware (August 2025) ran installed AI CLIs with their permission-bypass flags | `JH702`: agent CLIs started with approvals disabled in scripts, CI, and package scripts |
| Repository config that disables approvals or runs code on open | VS Code agent auto-approve written by prompt injection (CVE-2025-53773); project settings that rerouted Claude Code's API traffic before the trust prompt (CVE-2026-21852); a trusted Cursor MCP config swapped after approval (MCPoison, CVE-2025-54136) | `JH703`: auto-approve and bypass settings, the Cursor CLI's project permissions ([`.cursor/cli.json`](https://cursor.com/docs/cli/reference/permissions): `Shell(bash)`, `Mcp(*:*)`, `WebFetch(*)`), and `skipDangerousModePermissionPrompt` in a committed local file; `JH704`: plugin marketplaces a project registers and turns plugins on from (`extraKnownMarketplaces` with `enabledPlugins`), a marketplace over plain HTTP, or an https one with a `headersHelper`, tasks that run on folder open, dev container `initializeCommand` (runs on the host), project hooks, credential helpers, base-URL and proxy overrides |
| Agent tools that change under you | MCP servers started with `npx -y package` with no version | `JH705`: unpinned `npx`/`uvx`/`docker` launchers; `JH706`: credentials written into MCP config; `JH707`: plaintext remote MCP |
| Instructions the reader cannot see | hidden instructions in agent skills and rules files (2026 skill-ecosystem studies) | `JH701`: hidden HTML comments with commands or credential references, instruction overrides, "do not tell the user", pipe-to-shell, credential exfiltration; `JH131`: Unicode tag characters (decoded for the reviewer), bidi controls, invisible characters |
| A skill that turns off the prompt | agent skills that pre-approve `Bash` in `allowed-tools`: Claude Code then runs any shell command without asking during the turn that invokes the skill ([docs](https://code.claude.com/docs/en/skills)) | `JH712`: `allowed-tools` in a `SKILL.md` or a `.claude/commands/` file that names bare `Bash`, `Bash(*)`, or a shell or interpreter followed only by a wildcard (`Bash(python3:*)`, `Bash(sh -c *)`) |
| Untrusted text, private data and a way out in one agent | Invariant Labs (May 2025): an issue on a public repository steered an agent with a GitHub MCP server into copying a private repository into a public pull request | `JH714`: one agent configuration (MCP servers with their Claude Code or VS Code settings, or an n8n AI Agent node) that grants untrusted input, sensitive data and a way to act, with nothing approving the step that acts ([impact-model.md](impact-model.md)) |
| Untrusted text steering a CI agent | PromptPwnd (December 2025): issue and PR text fed to AI steps that hold write tokens | `JH708`: AI agent steps that receive issue, PR, or comment fields under outsider-triggered events |
| Agent code running with power before review | an agent pushes a branch, and a `push` workflow on every branch runs it with deploy secrets | `JH432`: workflows on a push to any branch (or to `claude/`, `copilot/`, `codex/`... branches) whose jobs hold secrets or a write-scoped token, unless the job is pinned to a branch or guarded by an environment |
| A sandbox that does not contain | sandbox settings that allow every host, the Docker socket, credential paths, or log-only enforcement | `JH709`: [Codex](https://developers.openai.com/codex/config-reference) `network_access = true`, `mode = "full"`, wildcard proxy domains; [Claude Code](https://code.claude.com/docs/en/settings-reference) `allowedDomains` wildcards, `allowAllUnixSockets`, escape-hatch `excludedCommands`, `allowWrite`, `allowRead` or `additionalDirectories` on home or credential paths, `allowLocalBinding`; Codex network proxy `dangerously_allow_all_unix_sockets`, `dangerously_allow_non_loopback_proxy`, `allow_local_binding` and a container engine socket in `unix_sockets`; [OpenShell](https://docs.nvidia.com/openshell/latest/how-it-works/policies/schema) `/**` binaries, wildcard hosts on shared cloud domains, private `allowed_ips`, `access: full` on wildcards; [Agent Substrate](https://github.com/agent-substrate/substrate) egress rules for `"*"` or a shared domain, and `tlsPassthrough` on every port. `JH710` (Claude Code): `httpProxyPort` or `socksProxyPort` (another program decides what is reached), `enableWeakerNetworkIsolation`; (OpenShell): `enforcement: audit` (also the default), Landlock `best_effort`, `tls: skip`, `allow_uninspected_credentials`, fail-open middleware; (Agent Substrate) `tlsPassthrough` to an API the agent signs in to, where the gateway cannot inject the key, and `replaceHeaders` on cleartext `http` |
| A sandbox that holds the key | an agent sandbox started with its API key in the environment, as in demos that render `${ANTHROPIC_API_KEY}` into the template | `JH713`: an [Agent Substrate](https://github.com/agent-substrate/substrate) actor template whose credential-named env var is a literal or a `${VAR}` substitution; placeholders, file paths and plain URLs are not reported. The agent, anything it runs, and the actor's memory snapshots hold the key |
| A dev container that owns the host | [dev container](https://containers.dev/implementors/json_reference/) `runArgs` with `--privileged`, host networking or PID, added capabilities, or a mounted Docker socket | `JH711` |
| An automation anyone can start, feeding a shell or a database | n8n's own SQL editor warns to use query parameters against injection, and n8n 2.0 (December 2025) turned the Execute Command node off by default | `JH156`: n8n Webhooks, public chats and forms with no authentication; `JH157`: shell commands built from workflow data or written by an AI agent; `JH158`: SQL with values spliced in; both critical when an open trigger's data reaches them; `JH159`: personal fields sent to an AI model. Power Automate: `JH144`, `JH147` |

Each rule's message names the exact line. A finding is a lead: confirm it
in context, then fix it or suppress it with a reason.

### Which file a setting counts in

Claude Code ignores some settings when a repository's own files set them, so jankhunt42 reports each setting only
where it takes effect ([settings reference](https://code.claude.com/docs/en/settings-reference)):

| File | What counts |
|---|---|
| `.claude/settings.json` (shared) | everything a project may set: permissions, sandbox scope, proxy ports, hooks, plugins, MCP approvals. One exception is kept as a minor note: `defaultMode: bypassPermissions`, ignored since Claude Code 2.1.257 and honoured by older versions |
| `.claude/settings.local.json` (committed by mistake or on purpose) | the same, plus `skipDangerousModePermissionPrompt` |
| `managed-settings.json`, `managed-settings.d/*.json` (an administrator's policy, when you scan the repository that holds it) | every key, including `sandbox.filesystem.disabled`, `sandbox.allowNestedUserNamespaces`, `sandbox.allowAppleEvents`, `sandbox.credentials.allowPlaintextInject` and `defaultMode: bypassPermissions` |

Not reported from a repository's own files, because Claude Code ignores them there: `sandbox.network.strictAllowlist`,
`sandbox.network.tlsTerminate`, `autoMode`, `skipAutoPermissionPrompt`, and the managed-only keys above. A subagent
file's `permissionMode: bypassPermissions` is not reported either: a subagent runs in that mode only when the main
conversation already does.

### Supabase migrations

A Supabase project's `supabase/migrations/*.sql` files are replayed in name
order as one database, so row-level security turned on in a later file counts.
What is tracked:

- tables, renames and drops, and row-level security turned on or off (also
  inside a `DO` block);
- grants and revokes to `anon`, `authenticated` and `PUBLIC`, including
  `on all tables in schema` and `alter default privileges`;
- policies and views.

The API schemas come from `[api] schemas` in `supabase/config.toml`, or are
just `public`.

- **JH134:** reports a served table with no row-level security at the line
  that creates it. Severity depends on what the migrations grant:
  - critical when granted to `anon` or `PUBLIC`;
  - major when granted only to `authenticated`;
  - a medium-confidence major when nothing grants it, because projects made
    before May 30, 2026 served new public tables automatically.

  A table whose row-level security is enabled by a loop (`execute format(...)`)
  cannot be told apart, so a folder with such a loop reports no tables. Inside
  a migration folder, a grant to `anon` is not reported on its own: with
  row-level security it is how Supabase serves a table.
- **JH154:** reports a policy that reads `user_metadata` (or
  `raw_user_meta_data`). Signed-in users can change those fields themselves.
- **JH155:** reports a view in a served schema that reads a table protected by
  row-level security, without `security_invoker`. It also reports a
  materialized view of such a table. A view of `auth.users` is critical.

Nothing is run, and the live database may differ from what the migrations
say.

## Fix with your coding agent (`scan --prompt`)

A citizen developer fixes things by asking their coding agent, not by
reading remediation advice. Every finding carries a short instruction for
that agent (`prompt` in `scan --json`, a "Fix it with your coding agent"
box in `--html`), and `jankhunt42 scan . --prompt` prints one prompt for all
of them, most serious first (20 at most; the rest wait for the next scan).
The Markdown and HTML reports end with the same text.

**Each prompt:**
- names the file and line, what is wrong and what to change;
- says how to check the fix: `jankhunt42 scan . --rule JHxxx`;
- forbids silencing the finding (a suppression comment, a deleted check or a
  skipped test);
- for a secret, says never to print or commit the value, to move it to the
  environment or a secret store, and that it must be rotated.

**What a prompt never carries:** the finding's evidence, so never a secret's
value. Names from the project (file paths, node or step names) are quoted,
invisible characters are shown as `<U+XXXX>`, and the prompt tells the agent
to treat those names as data, not instructions: a project can name a file
or a workflow step to steer an agent.

## What the agent can reach (`map`)

`map` reads MCP server definitions from `.mcp.json`, `.cursor/mcp.json`,
`.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml` (MCP
tables), `opencode.json(c)`, `claude_desktop_config.json`, and any JSON file
with an `mcpServers` object. Each config file becomes an **AI agent**
principal (`platform: ai-agent`) with:

- a `calls` edge to every enabled server: a local process for stdio
  servers (with its launcher, package, and whether it is pinned), or the
  remote endpoint for HTTP servers;
- `connects` edges from a server to endpoints in its arguments or
  environment, such as a Postgres URL handed to a database server. A
  `${PASSWORD}` placeholder in the URL does not hide the host;
- `authenticates-as` edges to identity nodes named after the credentials
  the server is given. Only the names are recorded; values are never read
  into the graph.

Each remote server is its own node, so two servers on one host stay
distinct and the application's own endpoints are never relabelled. A JSON
config or manifest that also defines `mcpServers` keeps its own adapter and
gets an extra MCP pass.

Every capability is `unknown` and every edge is `declared`: what a server's
tools can read, write, or run is decided by the server at runtime, and the
map says so in the `agent-tool-capability` unknown. Because unknown
capability counts as possibly anything, an agent whose database server
points at a production host lands in **High** exposure, exactly like
application code with the same reach.

The map also recognizes the stack AI app builders reach for: Supabase,
Firebase/Firestore, Neon, Upstash, Turso, Airtable, and Google Sheets
clients and hosts are data stores, and Stripe, Twilio, SendGrid, Resend,
Slack, Notion, and the model APIs are external services.

## The citizen profile (`passport --profile citizen`)

The profile is a governance choice, not a guess about authorship. An
operator chooses it with `--profile citizen` or `"profile": "citizen"` in an
operator policy, and a repository can opt in with `passport.profile:
"citizen"`. A repository can never opt out: a profile only ever tightens.

| Rule | Standard profile | Citizen profile |
|---|---|---|
| `P-OWN-001` owner | review at High exposure | **required**; block without one |
| `P-CUS-001` engineering custodian | not required | **required**: block until the operator policy names one (a repository declaration alone does not count) |
| `P-DAT-002` authority over production/critical/restricted data | review for static leads | **block** until an operator inventory verifies the grants |
| `P-DAT-001` sensitive external export | review | **block** |
| `P-DAT-003` data classification | not required | every reachable data store needs a declared sensitivity (insufficient-evidence) |
| `P-SEC-001` secrets or data exposed to the public | review | **block** |
| `P-AGT-001` agent guardrails bypassed, agent tooling unpinned | review | **block** |
| `P-AGT-002` an agent holds untrusted input, private data and a way to act | review | **block** (K3); review when every acting step asks a person (K4) |
| `P-AI-001` sensitive data reachable alongside an external AI service | review | **block** until the provider's data handling is decided and recorded (an operator exception) |
| `P-OPS-001` tests and CI | not required | must be **observed**; a declaration is not enough |
| `P-JNK-001` Jank Score policy fail | review | **block** |
| `P-EXP-001` exposure ceiling | none | above **Moderate** blocks |
| `P-CHG-001` change control on the default branch | not required | **required**: block on no review or an app bypass; insufficient-evidence when unknown or only declared in the repository |
| `P-SUP-001` package sources | only when `allowed_registries` is set | **block** on a source outside `allowed_registries`; insufficient-evidence when a package manager has no committed registry config |
| `P-RUN-001` sandbox run (`--sandbox-run`) | review on an ALERT | **block** on an ALERT |
| `P-RUN-002` sandbox run tried undeclared destinations | review | **block** |
| `P-RUN-003` agent sandbox log (`--sandbox-log`) shows undeclared destinations | review | **block** |
| `P-ENV-001` non-production meets production (a dev config pointing at the production database) | review | **block** |

Coverage (`P-COV-001`) and supply-chain evidence (`P-EVD-001`) keep their
usual meaning.

`insufficient-evidence` and `block` mean different things: missing evidence
is not proven harm, so the passport keeps them apart. The citizen
pull-request gate (`templates/citizen-gate.yml`) fails on both, so an
unclassified data store, unknown change control, or an unconfigured registry
stops the merge until the evidence is supplied. Under the citizen profile
every `insufficient-evidence` reason says so in its message. The profile is applied after the operator's ordinary
settings (`actions`, `require`, `max_exposure`, `static_leads`), so a
baseline organization policy cannot silently weaken it; a warning names
every operator setting the profile overrode. To relax the profile
deliberately, the operator policy lists the relaxation under
`profile_exceptions`: a rule action (`"P-OPS-001": "review"` when CI lives
outside the repository), a requirement (`"require.tests": false`), or a
ceiling (`"max_exposure": "High"`, `"static_leads": "review"`). Each
exception is warned and recorded in the policy hash. A repository cannot
grant exceptions, and a repository that also declares the profile
re-tightens them.

Under the citizen profile, the leads behind `P-SEC-001` and `P-AGT-001`
include a scan of the shipped rules that ignores repository scan config
(rule toggles, severity overrides, ignore globs) and inline `jankhunt42:
ignore` pragmas, joined with the repository-tuned scan: the repository can
add or raise leads but never remove them. The passport reports exactly how
many leads repository tuning would have hidden
(`governance.repository_suppressed_leads`), under either profile. If that
untuned scan reaches `--max-files`, the citizen passport is
`insufficient-evidence` (coverage) rather than quietly scanning less.

### The custodian

A custodian is the engineer, or engineering team, who answers for the
software: they review it, own its incidents, and sign its acceptance.

- `custodians` in the operator policy (outside the repository; reported as
  `operator-policy`) is what lets `P-CUS-001` pass.
- `passport.custodians` in `.jankhunt42.json` is recorded as a declaration
  (`repository`), but the software's author could name anyone, including
  themselves, so it does not satisfy `P-CUS-001`.
- An operator who deliberately does not want the rule can relax it with
  `profile_exceptions` (`"require.custodian": false`, or `"P-CUS-001": "off"`).

Under the citizen profile an acceptance record must be signed by a
custodian named in the operator policy (`accepted_by` matches one of
them), otherwise it is `rejected`. A `block` or `insufficient-evidence`
decision can never be accepted.

### In plain terms

Citizen passports lead with a plain-language brief, in the terminal, the
Markdown, the HTML, and `governance.brief` in JSON:

```text
Not ready to ship. Fix every blocking item below; then an engineering custodian must review and sign off.
- No engineer is named as its custodian, so nobody with engineering responsibility answers for it.
- Secret keys or data are exposed to the public.
- The AI agent set-up can act without asking, or pulls tools that can change without notice.
Its AI agent set-up connects to 2 tool server(s): postgres (unpinned), reaching postgresql crm-db.prod.internal; github with GITHUB_PERSONAL_ACCESS_TOKEN.
Custodian: not named.
```

`governance` in the JSON also lists the public-exposure and agent leads that
drove `P-SEC-001` and `P-AGT-001`, and the agent tooling (servers,
transports, pinning, credential names, what each server reaches).
`--redact` replaces server names, credentials, endpoints, and custodians
with ordinals, and strips the hostnames, paths, and names that rule
messages quote.

## Fence the agent (`passport --emit-sandbox-policy`)

An AI coding agent runs commands with the developer's network and
credentials. A fence limits that to what the work needs:

```sh
jankhunt42 passport . --emit-sandbox-policy claude-code   # settings JSON for .claude/settings.json
jankhunt42 passport . --emit-sandbox-policy codex         # a config.toml permission profile
jankhunt42 passport . --emit-sandbox-policy openshell     # an OpenShell policy (version 1)
jankhunt42 passport . --emit-sandbox-policy substrate     # an Agent Substrate egress policy for kubectl ate
```

**What goes in:**
- the hosts the map shows the code reaching;
- the public endpoints of services it uses without naming a host;
- the package registries it installs from, or the ecosystem's default when
  nothing is configured.

**What stays out**, listed on stderr for a decision:
- **Production assets.** An agent editing code should get a non-production
  endpoint, not the production database.
- **Endpoints the map could not resolve.** An environment variable or a
  secret is never guessed.
- **Local services.**
- **Host names that are not plain DNS names.** A name read from the
  repository can never become a rule.

The policy is a review artefact. jankhunt42 never applies it, and checks its
own output against the subset of each format it writes before printing it.
The output is deterministic for a given repository and version.

**What each tool enforces:**
- **Claude Code.** A project file only pre-allows the hosts, and other hosts
  still prompt. Hosts are denied only when
  `sandbox.network.strictAllowlist` is `true` in user or managed settings,
  which a project file cannot set. The policy also sets `failIfUnavailable`
  and `allowUnsandboxedCommands: false`, and denies reads of common
  credential stores.
- **Codex.** Domain rules apply only with `features.network_proxy = true`,
  which the profile sets. Permission profiles are a Codex beta feature.
- **OpenShell.** A rule with no binaries matches nothing. The interpreter
  paths are the usual Debian and Ubuntu locations; replace them with the
  image's real paths, because OpenShell does not follow symlinks. Endpoints
  without `access` or `rules` allow any request to that host and port.
- **Agent Substrate.** The egress gateway signs requests to the AI APIs
  it knows (Anthropic, OpenAI, Gemini, Mistral, Groq, OpenRouter) with a key
  from a Secret, through an `https` rule with `replaceHeaders`, so the key
  never enters the sandbox. Create the Secret and put its namespace in the
  `credentialUri`; the actor sends a placeholder in that header and trusts
  the gateway's CA. Other APIs that need a key get an `https` rule, where
  you can add the same effect. Plain HTTP hosts get an `http` rule, and
  everything else is `tlsPassthrough` on its port, which the gateway does
  not decrypt. Databases and brokers are left
  out, because the gateway passes only HTTP and TLS with a server name.


- Use the citizen profile when the person says they are not a software
  engineer, or asks you to build and ship software without engineering
  review. Explain the result with the plain-language brief.
- Never weaken a guardrail to make progress: do not disable agent
  approvals, add permission-bypass flags, commit auto-approve settings,
  put a secret behind a public prefix, or open a data store.
- Ask who the engineering custodian is. Do not invent one, do not name the
  user or yourself, and never write an acceptance record.
- Before opening or running an unfamiliar repository with an agent, run
  `jankhunt42 scan . --category agent` and read the findings first.
- Run the agent inside a fence. Emit one with
  `jankhunt42 passport . --emit-sandbox-policy <tool>`, review what it
  excluded, and turn on the tool's strict mode. Never add production hosts
  to it to make a task work.

## Limits

- **Vendor settings move.** The agent rules follow the vendors' documentation as read on 2026-11-13 (Claude Code
  2.1.323, the Codex approvals and security page, the Cursor CLI permissions page). Not read yet, because their
  documentation was confirmed too late for this release: Cursor's `sandbox.json` (`type: "insecure_none"`) and
  project hooks, Codex granular approval policies and `approvals_reviewer = "auto_review"` (a reviewing model, not
  a person, approves). The configuration folders of Antigravity, Amp and OpenClaw are unconfirmed.
- **A managed-settings finding describes the file**, not a machine: it does not show the policy is installed
  anywhere.

- Static evidence only: rules read text; they do not run the agent, the MCP
  servers, or the app. Agent settings change between versions (for
  example, current Claude Code ignores `bypassPermissions` in project files
  while older versions honour it); messages say so where it matters.
- `JH701` uses phrase and pattern heuristics. A determined author can word
  around them, so they complement review of agent instruction files, they
  do not replace it.
- The citizen profile governs the release decision. It is not a sandbox and
  does not stop an agent at runtime.

### Agent policy context for findings

Citizen-profile passports show repository instruction and configuration files
near scan findings as candidate context. Directory proximity helps a reviewer
find material to investigate; clients differ in discovery, file precedence,
scope, and version. The passport does not infer that the agent which produced a
finding read or followed a file. It reports the original agent identity,
policy loading, enterprise-managed policy, and causal link as unknown. A file
not shown may have been excluded or outside the collected scan scope. This
section recognizes `AGENTS.md`, `AGENTS.override.md`, `CLAUDE.md`,
`CLAUDE.local.md`, Claude and Codex project settings, and `opencode.json` or
`opencode.jsonc`. It does not interpret those files, Cursor team rules,
other instruction formats, or managed settings outside the repository.

A supplied sandbox run describes that run; it does not establish what policy
or guardrails were in effect when earlier repository changes were made. The
policy-context section does not include policy file contents. Shareable
passports replace the candidate file and finding paths with aliases.
