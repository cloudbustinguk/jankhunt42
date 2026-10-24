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
| Data store left open to the internet | Lovable-generated apps without row-level security (CVE-2025-48757, reported May 2025); the Tea app's open Firebase storage (July 2025) | `JH134`: open Firebase/Firestore rules, disabled row-level security, `USING (true)` write policies, writes granted to `anon`, public buckets |
| Secret shipped to every visitor | a payments secret key in client-side JavaScript of an AI-built app (reported February 2026) | `JH132`: secrets under `NEXT_PUBLIC_`, `VITE_`, `REACT_APP_` and similar prefixes, including Supabase `service_role` keys; `JH133`: `dangerouslyAllowBrowser` LLM clients |
| Agent runs without asking | the s1ngularity npm malware (August 2025) ran installed AI CLIs with their permission-bypass flags | `JH702`: agent CLIs started with approvals disabled in scripts, CI, and package scripts |
| Repository config that disables approvals or runs code on open | VS Code agent auto-approve written by prompt injection (CVE-2025-53773); project settings that rerouted Claude Code's API traffic before the trust prompt (CVE-2026-21852); a trusted Cursor MCP config swapped after approval (MCPoison, CVE-2025-54136) | `JH703`: auto-approve and bypass settings; `JH704`: tasks that run on folder open, dev container `initializeCommand` (runs on the host), project hooks, credential helpers, base-URL and proxy overrides |
| Agent tools that change under you | MCP servers started with `npx -y package` with no version | `JH705`: unpinned `npx`/`uvx`/`docker` launchers; `JH706`: credentials written into MCP config; `JH707`: plaintext remote MCP |
| Instructions the reader cannot see | hidden instructions in agent skills and rules files (2026 skill-ecosystem studies) | `JH701`: hidden HTML comments with commands or credential references, instruction overrides, "do not tell the user", pipe-to-shell, credential exfiltration; `JH131`: Unicode tag characters (decoded for the reviewer), bidi controls, invisible characters |
| Untrusted text steering a CI agent | PromptPwnd (December 2025): issue and PR text fed to AI steps that hold write tokens | `JH708`: AI agent steps that receive issue, PR, or comment fields under outsider-triggered events |

Each rule's message names the exact line. A finding is a lead: confirm it
in context, then fix it or suppress it with a reason.

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
| `P-AI-001` sensitive data reachable alongside an external AI service | review | **block** until the provider's data handling is decided and recorded (an operator exception) |
| `P-OPS-001` tests and CI | not required | must be **observed**; a declaration is not enough |
| `P-JNK-001` Jank Score policy fail | review | **block** |
| `P-EXP-001` exposure ceiling | none | above **Moderate** blocks |

Coverage (`P-COV-001`) and supply-chain evidence (`P-EVD-001`) keep their
usual meaning. The profile is applied after the operator's ordinary
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

## Doctrine for agents working with citizen developers

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

## Limits

- Static evidence only: rules read text; they do not run the agent, the MCP
  servers, or the app. Agent settings change between versions (for
  example, current Claude Code ignores `bypassPermissions` in project files
  while older versions honour it); messages say so where it matters.
- `JH701` uses phrase and pattern heuristics. A determined author can word
  around them, so they complement review of agent instruction files, they
  do not replace it.
- The citizen profile governs the release decision. It is not a sandbox and
  does not stop an agent at runtime.
