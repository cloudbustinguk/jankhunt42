# n8n workflows

Citizen developers often build automations in n8n. `map` and `passport` read
exported n8n workflows (JSON) and show what each one can reach: the HTTP
services it calls, the databases and spreadsheets it reads, writes or
deletes, and the credentials it uses. With `passport --base`, new access in a
workflow shows up as a change for IT to review, the same as new access in
code. `scan` checks the same exports for the mistakes that make a workflow
dangerous ([JH156-JH159](#checks-jh156-jh159)).

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

**Older exports** are read as n8n reads them:
- **Without node IDs** (before mid-2022): n8n gives each node a new random ID
  on import, so the node's name is its identity. Renaming it reads as a new
  node.
- **Credentials named, not numbered:** a node that names its credential (or
  gives it no ID) still uses it; n8n finds it by name. The map keeps one
  identity per name.
- **An output with nothing connected** may be written as `null`.

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
- arbitrary behaviour inside Code and Function nodes, even when literal calls map;
- arbitrary SQL and aggregates;
- unknown versions and community nodes;
- HTTP options beyond the URL and method, such as a proxy;

## JavaScript inside Code nodes

A Code node runs JavaScript the citizen developer wrote, and that's where
a workflow can quietly call out. jankhunt42 reads that JavaScript with its
usual reader. The n8n node, not the repository, is the code's owner.

**Which code is read:**
- **Code nodes:** versions 1 and 2, the `jsCode` parameter.
- **Function and FunctionItem nodes:** version 1, the `functionCode`
  parameter.
- **The `language` field:** version 2 defaults to JavaScript. Python
  (`python`, `pythonNative`, read from `pythonCode`) is not read yet and
  stays unknown.
- **`mode`** (once for all items, or once per item) changes how often the
  code runs, not what it can reach.

**What becomes a call:**
- `fetch`, `axios` and `axios.get/post/...` with a literal URL;
- `this.helpers.httpRequest` and `$http` with a literal options object
  (`url`, and `method`, GET by default).

A method in any letter case maps (`post` and `POST`). `$http` is matched
as a call shape only; whether a deployment provides it is not checked.

**What stays unknown:**
- dynamic URLs or methods, spreads, `${}` interpolation, and syntax the
  reader can't follow;
- **the code itself.** Even when its literal calls map, a Code node keeps
  an "arbitrary behaviour" unknown, because code can do things a reader
  cannot see.

**Receipts:** each call keeps the export file and the JSON line, plus a
`json_pointer` to the code parameter and a `code_line` within the code.
**Isolation:** each node's code is read on its own, so another node's code,
or the repository's own config, can't supply its values.
**Comparison:** `passport --base` compares the whole workflow, code and
language and mode included, so an edit to code needs review. An inactive or
disabled flag waives nothing, and hitting the reader's limits makes
coverage partial.

These are what the code declares, not proven runtime access. n8n can
restrict what Code nodes may do, depending on the deployment
([runtime restrictions](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.code#file-system-and-http-requests)).
The fields come from the
[upstream Code node](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Code/Code.node.ts)
and the
[helper options](https://github.com/n8n-io/n8n-docs/blob/main/docs/connect/create-nodes/build-your-node/reference/http-request-helpers.md),
where the legacy `uri` option is not read as `url`.

## Credentials and secrets

An export [names the credentials its nodes use, and can keep imported
authentication headers](https://docs.n8n.io/build/manage-workflows/export-and-import.md).
jankhunt42 shows credentials by type and name only.

A secret-shaped literal in a node's parameters (a token in a header, say) is
reported as a JH101 lead that points at the parameter (a JSON pointer) but
never contains the value or a fingerprint of it. Normal scan suppressions
apply; `passport --base` compares the unsuppressed requests. Shareable
outputs strip graph attributes and access labels.

## Checks (JH156-JH159)

`scan` reads each workflow for four mistakes, the n8n forms of the Power
Automate checks. Expressions are read as text, never evaluated. An export
leaves out a setting at its default, so a trigger with no `authentication`
has none. A disabled node does not run and is not reported; the map still
lists it.

| Rule | Reports | Severity |
|---|---|---|
| `JH156` | A trigger anyone with the URL can use: a Webhook with authentication None and no IP allow-list, a Chat Trigger made public with no authentication, or a Form Trigger with none | major; minor for a form, which is often meant to be public |
| `JH157` | An Execute Command or SSH node (or an AI agent's command tool) whose command is built from workflow data or written by the AI (`$fromAI`) | major; **critical** when an open trigger's data reaches it |
| `JH158` | A Postgres, MySQL or Microsoft SQL query (or an AI agent's database tool) with workflow data or AI-chosen text spliced in, or the whole query taken from data or the AI | major; **critical** when an open trigger's data reaches it; minor when every value has its quotes escaped by hand |
| `JH159` | Personal fields (email, phone, birth date, passport, address, full or last name) sent to an AI agent, chain, model node, or an HTTP request to an AI API, with no redaction step | major |

**What counts as workflow data:** an expression that reads the current item
(`$json`, `$input`, `$binary`), another node's output (`$('Name')`,
`$node["Name"]`, `$items()`) or a value the AI chooses (`$fromAI`). These are
not data:
- `$env`, `$vars`, `$now`, `$execution` and `$workflow`;
- another node's settings (`$('Name').params`);
- a Set node field the author typed in, or filled only from those.

**Where data reaches:** along the workflow's connections from an open
trigger, and from an AI agent to the tools plugged into it. An agent behind
a public chat can be steered by anyone who reaches the chat.

**A check in the first step:** when every node a trigger starts is a Code
node that reads the request headers and throws (or raises) or verifies a
signature (an HMAC), or an If, Switch or Filter on a header, the trigger is
not treated as open. `JH156` still
reports it as minor: n8n's own authentication turns a caller away before the
workflow runs, while a check in a node runs it and lets everyone in if its
secret is ever unset.

**A command or query a Code node writes:** when the whole command or query
is one field (`{{ $json.script }}`) and every connection into the node comes
from a Code node, the finding names that Code node at medium confidence: the
code may quote what it takes from a request, and only reading it can tell.

**SQL:** the database nodes put `{{ }}` values into the query text before
it runs, so a quote in a value rewrites the query. Values passed as Query
Parameters (`$1`, `$2`) are not reported. **Commands:** n8n 2.0 and later
turn Execute Command off unless the instance turns it back on; the finding
says so.

**Personal data:** a field counts by its name: `email`, `customerEmail` and
`Phone Number` do, `email_subject` and `ip_address` do not. A field read from
a step named for redaction (redact, anonymise, pseudonymise, mask) or from a
Guardrails node is not reported. Local models (Ollama, Lemonade) are not
reported.

Sources: the upstream
[Execute Command](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/ExecuteCommand/ExecuteCommand.node.ts),
[SSH](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Ssh/Ssh.node.ts),
[Postgres query](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Postgres/v2/actions/database/executeQuery.operation.ts),
[Form Trigger](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Form/v2/FormTriggerV2.node.ts)
and [Chat Trigger](https://github.com/n8n-io/n8n/blob/master/packages/%40n8n/nodes-langchain/nodes/trigger/ChatTrigger/ChatTrigger.node.ts)
descriptions, and the
[default node exclusions](https://github.com/n8n-io/n8n/blob/master/packages/%40n8n/config/src/configs/nodes.config.ts).

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
- malformed exports, and exports n8n itself would not write, such as
  connections keyed by node ID (some template collections rewrite them);
  `scan` lists each one under its warnings as "n8n workflow the reader
  rejects (...), not checked";
- unsupported versions;
- ordinary graph JSON that only looks like n8n, which can still be read as
  a candidate.

This is a static inventory of what a workflow declares, not a runtime
check.


## Inbound and unattended triggers

A workflow can start without anyone running it. A **Webhook** node accepts
requests from outside, and a **Schedule Trigger** runs it unattended. Both
appear in the map and passport separately from what the workflow can reach.
A trigger is never counted as outbound network access.

**In `passport --base`,** each new or changed trigger is a `trigger` request
for IT to review under `P-CAP-001`.
- **Flags don't exempt it:** an export's `active` flag or a node's
  `disabled` flag is only a declaration.
- **What stays unverified:** whether the workflow is deployed, reachable
  from the internet, bound to its route, or effectively authenticated.
  Trigger requests therefore stay unresolved, and an approval record cannot
  cover them yet.
- **What needs review:** a change to the route, authentication, filters,
  schedule rules, activation, timezone or the rest of the workflow. An
  identical move to another file does not.

**What is reported:** facts, never values.
- **Webhooks:** the allowed methods, the authentication mode, whether the
  route is literal, an expression or missing, and whether an IP or request
  filter is declared.
- **Schedules:** how many rules there are, their units, and where the
  timezone comes from.

Routes, cron text, filter text, trusted-source IDs and timezone values are
withheld, with no fingerprint of them. The map's JSON lists up to 100
triggers with their receipts; the passport and shared copies carry counts
only. Counts and policy see every trigger, past the display limit.
Conflicting declarations for the same node across exports make coverage
partial.

**Versions read:** only the exact `n8n-nodes-base.webhook` (versions 1,
1.1, 2, 2.1 and 2.2) and `n8n-nodes-base.scheduleTrigger` (1 to 1.4). For
any other version, the trigger is still declared, but its methods,
authentication and intervals are not guessed. Expressions are never
evaluated.

### Exact parameter checklist

| Input matched | Interpretation |
|---|---|
| Node `type`, `typeVersion`; node `disabled`; workflow `active` | Exact node family/version and declared state only |
| Webhook `httpMethod`, `multipleMethods` (also node setting) | Allowed method enums; known-version defaults GET or GET/POST |
| Webhook `authentication` | none/basicAuth/headerAuth/jwtAuth/n8nOAuth2 selector; unknown otherwise |
| Webhook `path` | Missing/expression/literal-withheld state, never the value |
| Webhook `options.ipWhitelist`, `options.onlyRunIf` | A filter is declared; no claim that it is effective |
| Webhook `requireExecuteAccess`, `trustedSource` | Declared OAuth execution-permission toggle and source presence only |
| Schedule `rule.interval[]`, its `field` | Rule count and seconds/minutes/hours/days/weeks/months/cronExpression enums |
| Workflow `settings.timezone` | Workflow-specified/expression/instance-unverified source, no zone value |

Timing values, cron `expression`, `misfirePolicy`, `misfireGraceSeconds` and
other fields remain private comparison context; they are not scheduled or
interpreted. No new secret-name pattern was added. Credential-type selectors
such as `nodeCredentialType` and `genericAuthType` remain metadata; a neighboring
literal Authorization header still creates its value-free lead.

Sources checked against the actual upstream descriptions:
[Webhook](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Webhook/Webhook.node.ts),
[Webhook properties](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Webhook/description.ts),
[Schedule](https://github.com/n8n-io/n8n/blob/master/packages/nodes-base/nodes/Schedule/ScheduleTrigger.node.ts).
[Schedule publication/timezone documentation](https://docs.n8n.io/integrations/builtin/core-nodes/n8n-nodes-base.scheduletrigger)
confirms that a schedule declaration alone does not establish deployment.
