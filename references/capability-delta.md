# What new access does this change ask for?

Citizen development scales when IT approves *changes*, not whole apps.
`passport --base REF` compares two commits and lists the access the newer
one asks for that the older one did not.

```sh
jankhunt42 passport . --base main --md        # what this branch adds over main
jankhunt42 passport . --base main --json      # the same, as capability_delta
jankhunt42 passport . --base main --sandbox-network-ceiling /etc/it/approved.json   # and check hosts against IT's list
```

It reads both commits from Git objects only. Uncommitted and untracked files
are left out (the passport says so), and no repository code runs. In CI,
compare against a trusted base, such as the target branch.

## What counts as new access

| Kind | Example |
|---|---|
| `network` | the app now connects to `api.example.com:443` |
| `credential` | it now reads `STRIPE_SECRET_KEY`, or passes a credential to an MCP server (names only, never values) |
| `authority` | it can now write, delete or administer a database, bucket, queue or cloud service, or one more scope of it |
| `production` | it now reaches a production asset, or an asset it reached is now marked production |
| `agent` | a new MCP server, an approval bypass, a hook, or another agent control |

Requests are compared by *who* does *what* to *which* target, not by file or
line. So moving code to another file adds nothing, but a new `delete` is
reported even where `write` already existed.

**Unresolved items** are where the code reaches something whose target or
authority cannot be read statically, such as a URL built at run time:
- **newly unresolved in the change:** reported, and needs review;
- **unresolved at the base and apparently resolved now:** reported, and
  needs review, because a resolution can hide new authority;
- **unresolved in both:** listed as unchanged, and does not force review
  for this change.

## The decision

- **`P-CAP-001`:** any new request, or any newly unresolved or newly
  resolved item, needs at least review. Stronger outcomes stay stronger.
- **The network ceiling:** with `--sandbox-network-ceiling`, a new host and
  port is marked *within* or *outside* IT's approved list. Within the list
  is not an approval of the change, and an unknown port never counts as
  within.
- **An incomplete comparison** falls to the coverage floor, `P-COV-001`.
  Incomplete means a parse failure, a limit reached, or an oversized file.
  Its counts are then lower bounds.
- **What cannot hide new access:** repository ignore globs, inline
  suppressions and disabled rules do not apply to this comparison.
- **What must come from outside the repository** under `--base`: the
  operator's policy, inventory and branch-rule files.
- **Ranking:** production writes rank first, so a flood of harmless hosts
  cannot bury them. Policy counts every request, even past the display
  limits:
  - JSON shows up to 100 requests and 100 unknowns, with counts of the
    rest;
  - Markdown and the terminal show ten requests.

## Limits

These are static possibilities, not verified grants. Languages without a
connectivity reader, and resources without a stable name, stay unresolved.
Not yet covered:
- registry changes;
- downgrades other than to and from production;
- renamed principals;
- recorded approvals of a delta (a file IT keeps outside the repository,
  so a re-run of an approved change passes).

A passport acceptance record is separate from approving a change.
