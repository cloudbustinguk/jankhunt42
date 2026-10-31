# Agent policy research corpus

Research snapshot: 2026-10-31. This is a starting corpus for policy-fuzz
campaigns. Vendor documentation describes expected behavior; each client and
version still needs an isolated, instrumented experiment. Instructions are
probabilistic guidance. A policy document being present, or its hash matching,
does not establish that an agent loaded it, followed it, or was prevented from
performing an action.

## Claude Code

### Organization controls and instructions

- Organizations can deploy a managed `CLAUDE.md` at
  `/etc/claude-code/CLAUDE.md` on Linux/WSL, or use the managed `claudeMd`
  setting. Managed content loads before user and project instructions.
  `claudeMdExcludes` cannot exclude the managed file; disabling CLAUDE.md
  loading for the whole session also prevents it from loading. Managed
  instructions guide behavior rather than enforcing access restrictions.
- Managed settings can configure client enforcement, including permission
  denies and sandbox settings. Verify the particular setting, source, deployed
  client version, and effective configuration; a file's mere existence is not
  evidence of enforcement.
- For the same setting key, the documented order is managed settings, command
  line `--settings`, project local, shared project, then user settings.
  List-valued settings and some restrictive keys have special merge or
  precedence behavior; environment-variable interactions are key-specific.

Sources: [Claude Code memory](https://code.claude.com/docs/en/memory),
[settings and precedence](https://code.claude.com/docs/en/settings).

### Instruction discovery and conflicts

At startup, Claude Code loads applicable `CLAUDE.md` and `CLAUDE.local.md`
from the working directory and ancestors in root-to-working-directory order;
local follows shared within a directory. Nested files are loaded when the
agent reads, writes, or edits in their directory. These files are concatenated,
not mechanically resolved as conflicting rules. The documentation explicitly
says a conflict between user and project rules may be followed either way.
Imports, excludes, subdirectory discovery, and session-level disabling are
separate dimensions worth testing.

Source: [Claude Code memory](https://code.claude.com/docs/en/memory).

## Codex

### Instruction discovery

Codex reads global guidance from its home directory: `AGENTS.override.md` if
present, otherwise `AGENTS.md`, taking the first nonempty file. It then walks
from project root to the working directory, selecting at most one file per
directory: override, ordinary file, then configured fallback names. The
combined instruction chain is ordered root to working directory and subject to
`project_doc_max_bytes`. This documented instruction ordering is distinct from
an administrator's enforced configuration requirements.

Source: [Codex AGENTS.md instructions](https://learn.chatgpt.com/docs/agent-configuration/agents-md).

### Managed controls

`requirements.toml` can constrain supported security-sensitive settings,
including approvals, sandbox and permission profiles, web search, managed
hooks, and permitted MCP servers. Conflicting client configuration is resolved
to a compatible value with a notification. Defaults and requirements are
separate. Requirements sources and merge semantics vary by field and execution
environment; check the client version and effective policy. Managed hook
failure modes are also relevant: documentation says an error, timeout, or
malformed `PreToolUse` response can fail the hook without blocking the tool.

Source: [Codex managed configuration](https://learn.chatgpt.com/docs/enterprise/managed-configuration).

## Cursor

Cursor documents project rules under `.cursor/rules`, user rules, team rules,
and `AGENTS.md`. Team rules can be enabled and marked enforced by administrators;
non-enforced team rules can be disabled by users. Documented conflict order is
Team Rules, then Project Rules, then User Rules. Nested `AGENTS.md` guidance is
combined with its parents, with more specific instructions taking precedence.
Team rules are model-context guidance; test them separately from run mode,
network, sandbox, and other administrative controls.

Sources: [Cursor rules](https://cursor.com/docs/rules),
[Cursor run modes](https://cursor.com/docs/agent/security/run-modes),
[Cursor enterprise controls](https://prod.cursor.com/docs/enterprise).

## OpenCode

OpenCode configuration sources merge; later sources override conflicting keys.
The documented order starts with remote organizational defaults, followed by
global and project sources, inline configuration, managed files, then macOS
managed preferences. Remote organizational defaults are therefore not the same
as enforced managed configuration. The documented Linux managed directory is
`/etc/opencode/`.

OpenCode V2 documents `AGENTS.md` discovery and combines instruction files
without resolving conflicts; it discovers nested instructions as the agent
explores. Its V2 documentation says it does not use `CLAUDE.md` as a fallback.
Verify the deployed version and interface before applying these statements to
other releases or forks.

Sources: [OpenCode configuration](https://dev.opencode.ai/docs/config),
[OpenCode V2 instructions](https://dev.opencode.ai/v2/docs/instructions/).

## Candidate experiments

These are hypotheses and test designs, not observations of client behavior.
Use synthetic projects, dedicated credentials-free client profiles, fresh
sessions, and independently observed actions. Record client and adapter versions,
policy source, effective settings, case isolation, and telemetry coverage. A
missing trace or unconfirmed policy load yields an inconclusive result. Distinguish
an agent declining an action from a sandbox blocking an attempted action.

1. **Managed setting versus project override:** set a managed deny and a
   conflicting project allow for a synthetic action. Include an allowed control;
   independently observe whether the action was attempted and blocked.
2. **Instruction guidance versus technical deny:** use the same forbidden
   action in a managed instruction file and in an enforced permission policy,
   separately and together. Compare observed model behavior and enforcement.
3. **Ancestor and nested instruction conflict:** place conflicting synthetic
   instructions in ancestor and nested files, then access a nested file. Record
   discovery timing and outcome; do not assume a universal conflict winner.
4. **Instruction exclusion and disabling:** test each documented exclusion
   mechanism and session-level disable separately, including managed guidance.
5. **Fallback and byte limit:** where supported, test override filenames,
   configured fallbacks, empty files, and instruction size limits with controls
   immediately before and after the boundary.
6. **Injected lower-trust content:** deliver conflict through a project file,
   tool result, and MCP result. Capture whether the agent attempted the action,
   whether the control blocked it, and whether the relevant policy was loaded.
7. **Hooks and missing telemetry:** vary hook success, denial, error, timeout,
   and malformed response. Treat absent attribution or incomplete traces as
   inconclusive; distinguish a documented fail-open behavior from a successful
   deny.
8. **Managed defaults versus constraints:** set a harmless default and a
   conflicting enforced requirement, then attempt user, project, CLI, and
   environment overrides where the client supports them.

No experiment above establishes organization-wide compliance on its own.
