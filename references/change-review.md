# Change review

Citizen development scales when IT approves each *change*, not the whole
app again. This page has two parts:
1. **What a change asks for:** `passport --base REF` lists the new access.
2. **Approving it:** a record that lets that exact change pass next time.

## What new access does this change ask for?

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

### What counts as new access

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
- **unresolved in both, with the same definition:** listed as unchanged,
  and does not force review for this change;
- **unresolved in both, but its definition changed:** for example a hook
  whose command was replaced, or an MCP server whose arguments changed.
  It needs review. For an MCP server the comparison covers the command,
  arguments, environment and header names, URL and transport. A changed
  credential value alone does not count.

### The decision

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

### Limits

These are static possibilities, not verified grants. Languages without a
connectivity reader, and resources without a stable name, stay unresolved.
Not yet covered:
- registry changes;
- downgrades other than to and from production;
- renamed principals;
- (recorded approvals of a change are below, in [Approve one access change](#approve-one-access-change)).

A passport acceptance record is separate from approving a change.


**n8n triggers:** a Webhook or Schedule Trigger in an n8n workflow is a
`trigger` request, separate from outbound network access. A new or changed
trigger needs review under `P-CAP-001`, even when the export marks it
inactive or disabled. Routes and schedules are compared in full, but never
published. See [n8n triggers](n8n.md#inbound-and-unattended-triggers).

## Approve one access change

`passport --base` lists the new access a change asks for (above), and
`P-CAP-001` sends it to review. Once IT
has reviewed a specific change, an **approval record** lets the same exact
comparison pass `P-CAP-001` on later runs. That way a CI job does not stop
again for a change that was already approved.

The record approves that access change only. It is not an acceptance of the
application: every other rule, and every stronger outcome, still applies.

### 1. Set up the operator policy (once)

Add this to the operator policy, which is kept outside the repository:

```json
{"capability_approvals": {
  "subject_id": "app-1",
  "approvers": ["reviewer-1"],
  "max_lifetime_seconds": 86400
}}
```

- **`subject_id`:** an opaque name for the application, up to 128 ASCII
  characters (letters, digits and `_ . : -`). It comes from this policy,
  never from the repository or its Git remote.
- **`approvers`:** who may approve.
- **`max_lifetime_seconds`:** from 1 to 2592000, which is 30 days.

A policy inside the repository can only narrow these: fewer approvers or a
shorter lifetime. It can never set the subject.

### 2. Make a record for a change

```sh
jankhunt42 passport . --base main --policy /etc/it/policy.json --emit-capability-approval > change.json
```

This prints a template with every binding filled in:
- the model and subject;
- both commits;
- the comparison, context and policy hashes;
- the exact request IDs;
- the issue time.

Review the full comparison, then fill in `approved_by`, `expires_at`
(`YYYY-MM-DDTHH:MM:SSZ`) and `rationale`, and store the file outside the
repository. A blank field approves nothing.

The template is refused when the comparison cannot be approved: it is
incomplete or truncated, it has active unknowns, a request is not concrete,
or more rows exist than are shown. An approval can only cover what was fully
visible.

### 3. Use it in CI

```sh
jankhunt42 passport . --base main --policy /etc/it/policy.json --capability-approval /etc/it/change.json --fail-on review
```

**A matching, current record** marks `P-CAP-001` as covered "by a
declared-by-operator record", with its approver and expiry.

**What invalidates a record:**
- a different commit, application, analyzer, policy, inventory or network
  ceiling;
- any request ID that is missing, extra, duplicated or a wildcard;
- an approver not in the policy;
- an issue time in the future, or a record that has expired, or a lifetime
  over the maximum;
- a missing rationale.

An invalid record is reported with its reasons and gives no relief. A
malformed record is an error, and so is one that is linked, oversized
(more than 64 KiB), or stored inside the repository, including the
enclosing repository when a subfolder is scanned. Validity uses the real
clock, whatever `SOURCE_DATE_EPOCH` says.

### Trust

The record is a local JSON file, and nothing proves who wrote it. Its
assurance is therefore always `declared-by-operator`, never signature- or
provider-verified. IT must keep the policy, the record and the CI invocation
out of reach of the agent and the repository.

A record can be reused for the same exact comparison until it expires.

### Output

- **JSON:** `capability_approval`, with its state and reasons.
- **Markdown and terminal:** the record's assurance and expiry.
- **`--redact`:** removes the approver, subject, rationale and file name.
- **Values:** no credential values or value fingerprints enter a record.
- **Schema:** `templates/capability-approval.schema.json`.

Not yet covered: one-use approvals, signatures, revocation, accepting risk
from unresolved items, and approving more than the displayed 100 rows.
