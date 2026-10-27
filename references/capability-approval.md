# Approve one access change

`passport --base` lists the new access a change asks for (see
`references/capability-delta.md`), and `P-CAP-001` sends it to review. Once IT
has reviewed a specific change, an **approval record** lets the same exact
comparison pass `P-CAP-001` on later runs. That way a CI job does not stop
again for a change that was already approved.

The record approves that access change only. It is not an acceptance of the
application: every other rule, and every stronger outcome, still applies.

## 1. Set up the operator policy (once)

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

## 2. Make a record for a change

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

## 3. Use it in CI

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

## Trust

The record is a local JSON file, and nothing proves who wrote it. Its
assurance is therefore always `declared-by-operator`, never signature- or
provider-verified. IT must keep the policy, the record and the CI invocation
out of reach of the agent and the repository.

A record can be reused for the same exact comparison until it expires.

## Output

- **JSON:** `capability_approval`, with its state and reasons.
- **Markdown and terminal:** the record's assurance and expiry.
- **`--redact`:** removes the approver, subject, rationale and file name.
- **Values:** no credential values or value fingerprints enter a record.
- **Schema:** `templates/capability-approval.schema.json`.

Not yet covered: one-use approvals, signatures, revocation, accepting risk
from unresolved items, and approving more than the displayed 100 rows.
