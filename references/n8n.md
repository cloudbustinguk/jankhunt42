# n8n workflows

Citizen developers often build automations in n8n. `map` and `passport` read
exported n8n workflows (JSON) and show what each one can reach: the HTTP
services it calls, the databases and spreadsheets it reads, writes or
deletes, and the credentials it uses. With `passport --base`, new access in a
workflow shows up as a change for IT to review, the same as new access in
code.

jankhunt42 only reads the export. It never runs a workflow, evaluates an
expression, runs a Code node, loads a package, fetches a URL, or opens a
file named in a parameter. Execution samples (`pinData`, `staticData`) and
the UI layout are ignored.

## Which files are workflows

These count as workflows:
- an export from the [official exporter](https://github.com/n8n-io/n8n/blob/master/packages/cli/src/commands/export/workflow.ts),
  either one workflow object or an array of them;
- any JSON with `nodes` and an n8n node type, or with n8n's
  `connections`/`typeVersion`/`parameters`/`position` structure (community
  node exports included);
- files under test folders too, so moving a workflow there does not hide
  it.

Ordinary graph JSON with only `nodes` is not a workflow. An n8n-looking file
that fails validation makes coverage partial; it is never read as an empty
map.

## What you see

Each workflow, and each node in it, is a workload in the map. Identity comes
from the n8n IDs, not the display names or the file's location. A workflow
without an ID uses its sorted node IDs. Connections between nodes become
`depends-on` links, which transfer no authority. A disabled node still counts:
it describes access that could be switched on. Nothing in an export proves a
workflow is deployed or active.

| Node | Versions read | Operations mapped |
|---|---|---|
| HTTP Request | 1, 2, 3, 4 to 4.5 | GET and HEAD read; POST, PUT and PATCH write; DELETE deletes; GET by default |
| Postgres | 2 to 2.8 | select; insert, update, upsert; deleteTable |
| MySQL | 2 to 2.5 | select; insert, update, upsert; deleteTable |
| MongoDB | 1 to 1.5 | find; insert, update, findOneAndReplace, findOneAndUpdate; delete |
| Google Sheets | 3, 4 to 4.7 | read; append, appendOrUpdate, update, create; clear, delete, remove (sheet resource) |
| Airtable | 1 | read, list; append, update; delete |
| Airtable | 2 to 2.2 | get, search; create, update, upsert; deleteRecord (record resource) |

**How to read the table:**
- **Versions are exact:** a version not listed, such as 4.6 for HTTP
  Request, is not read.
- **Operations must be explicit:** a data node needs its operation written
  in the export.
- **Where the names come from:** the upstream node descriptions
  ([HTTP](https://github.com/n8n-io/n8n/tree/master/packages/nodes-base/nodes/HttpRequest),
  [Postgres](https://github.com/n8n-io/n8n/tree/master/packages/nodes-base/nodes/Postgres),
  [MySQL](https://github.com/n8n-io/n8n/tree/master/packages/nodes-base/nodes/MySql),
  [MongoDB](https://github.com/n8n-io/n8n/tree/master/packages/nodes-base/nodes/MongoDb),
  [Sheets](https://github.com/n8n-io/n8n/tree/master/packages/nodes-base/nodes/Google/Sheet),
  [Airtable](https://github.com/n8n-io/n8n/tree/master/packages/nodes-base/nodes/Airtable)).
- **What a node reaches:** an HTTP node with a literal URL keeps its host
  and port. A data node keeps its logical resource (the document, table or
  collection), but which server or account backs it is outside the export.

**What stays unresolved,** shown as an explicit unknown for review:
- expressions (`={{ ... }}`);
- Code and Function nodes;
- arbitrary SQL and aggregates;
- unknown versions and community nodes;
- HTTP options beyond the URL and method, such as a proxy;
- Webhook and Schedule triggers, for now.

## Credentials and secrets

An export [names the credentials its nodes use, and can keep imported
authentication headers](https://docs.n8n.io/build/manage-workflows/export-and-import.md).
jankhunt42 shows credentials by type and name only.

A secret-shaped literal in a node's parameters (a token in a header, say) is
reported as a JH101 lead that points at the parameter (a JSON pointer) but
never contains the value or a fingerprint of it. Normal scan suppressions
apply; `passport --base` compares the unsuppressed requests. Shareable
outputs strip graph attributes and access labels.

## Comparing two versions (`passport --base`)

**How the comparison works:** for unresolved nodes, jankhunt42 compares the
whole normalized workflow in memory. That covers connections, settings and
upstream nodes, but not credential values. So:
- **A late edit or a rewiring** of an unresolved node needs review.
- **An identical move** to another file keeps the comparison intact.
- **Rotating** the value behind a credential reference changes nothing.

**When a workflow keeps needing review:**
- **A secret written inline:** if hiding a parameter's value could also hide
  behaviour, equivalence cannot be proven. The unknown then stays active,
  even when nothing changed. This stops a hostile node from naming an
  executable parameter `token` or `password` to slip past review.
- **An unrelated change in the same workflow** can also reactivate its
  unresolved nodes.

## Limits

**Per file:**
- 2 MiB;
- 100 workflows;
- 1000 nodes;
- 5000 links.

**Per workflow:**
- 20000 fields;
- a depth of 32;
- strings of 16384 characters.

The map's usual limits also apply. Reaching any limit makes coverage
partial; nothing is truncated silently.

**What needs manual review:**
- malformed exports;
- partial clipboard exports without IDs;
- unsupported versions;
- ordinary graph JSON that only looks like n8n, which can still be read as
  a candidate.

This is a static inventory of what a workflow declares, not a runtime
check.
