# Operator network ceiling

`passport --emit-sandbox-policy` writes a network policy for an AI coding
agent from what the code reaches. A network ceiling lets someone other
than the repository, such as IT or a platform team, cap that policy: the
written policy keeps only the destinations the code reaches **and** the
ceiling approves.

```sh
jankhunt42 passport . --emit-sandbox-policy claude-code \
  --sandbox-network-ceiling /etc/jankhunt42/approved-network.json
```

The ceiling can only remove destinations, never add them:
- an approved destination the code does not reach stays out;
- production assets stay excluded, as without a ceiling;
- a wildcard the code reaches is not widened into exact approved hosts;
  resolve it in the code or the ceiling instead.

jankhunt42 still only writes the policy for review. It does not apply it or
run a sandbox.

## The ceiling file

```json
{"schema": "jankhunt.network-ceiling.v1",
 "allow": [{"host": "api.openai.com", "port": 443},
           {"host": "registry.npmjs.org", "port": 443}]}
```

| Field | Rule |
|---|---|
| `schema` | exactly `jankhunt.network-ceiling.v1` |
| `allow` | at most 512 entries, each with only `host` and `port` |
| `host` | an exact lowercase DNS name or IPv4 address: no URL, port suffix or wildcard |
| `port` | an integer from 1 to 65535 (not `true`) |

An empty `allow` list is valid and allows no network destinations at all.

The file must come from outside the repository, so a repository cannot
approve its own destinations. jankhunt42 refuses a ceiling file:
- inside the scanned folder, or inside any enclosing folder that holds Git
  metadata (scanning a subfolder does not help);
- reached through a symbolic link, or with hard links;
- larger than 64 KiB;
- that changes while it is read;
- with a duplicate, unknown or missing field.

A path outside the repository is not proof of who wrote the file. Keep the
file and its folders writable only by the people who approve network
access. This is not a signed approval system.

## Which formats it covers

| Format | With a ceiling |
|---|---|
| `openshell` | host and port rules |
| `claude-code` | port-qualified `allowedDomains` entries such as `api.openai.com:443`, one per host and port |
| `codex` | refused: Codex domain rules drop ports, so a host approved for one port would be allowed on every port |

Without a ceiling, Claude Code output is unchanged: port-less entries,
which allow every port of each host.

**Claude Code version:** port-qualified entries are verified on Claude Code
2.1.310. Earlier versions are unverified. The Claude Code sandbox runtime
before July 2026 rejected port suffixes
([sandbox-runtime PR 426](https://github.com/anthropics/sandbox-runtime/pull/426)),
and which Claude Code release first included the change is not known.
Check the version your agents run before relying on this output.
jankhunt42 prints the same caution when it writes one. See Claude Code's
[network isolation](https://code.claude.com/docs/en/sandboxing#network-isolation)
documentation.

When jankhunt42 reads a Claude Code policy back (`map`, `passport`), it
accepts both forms. A port-less entry admits every port, and a qualified
entry admits that port only. When the port the code uses is not known, the
endpoint is reported as unassessed rather than guessed.

## What it does not cover

The ceiling limits host and destination port only. It does not approve an
HTTP method, a program, a credential, a mount or a lifecycle step.
OpenShell rules still list the programs allowed to connect, so review
them; a rule with no programs matches nothing. Whether the agent's sandbox
accepts the policy, how it merges settings, how it resolves names and
whether it enforces the policy at run time are not verified. The ceiling
does not change the passport's release decision.
