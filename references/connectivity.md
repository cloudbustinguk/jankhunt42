# Connectivity map and blast radius (`jankhunt42 map`)

`map` answers **what can it hurt?** It reads repository text offline, builds
a typed, directed connectivity graph with a receipt for every claim, and
computes what each principal (the repository's code, a Kubernetes workload,
a CI workflow) could reach, read, change, or break. It never connects to,
resolves, probes, or executes anything.

> A path in this graph is a **possibility**, not proof of access and not an
> exploit. A connection string is not a grant. An SDK import is not a data
> flow. Unknown is never treated as safe, and never as proven dangerous.

## Commands

```sh
jankhunt42 map .                              # TTY: blast radius explorer; piped: Markdown
jankhunt42 map . --json                       # jankhunt.map.v1 (stdout carries only JSON)
jankhunt42 map . --html > map.html            # offline explorer: graph, inspector, filters
jankhunt42 map . --redact --json              # shareable: pseudonymous labels, no hosts/snippets
jankhunt42 map . --base HEAD~1 --json         # graph delta from committed git objects only
jankhunt42 map . --inventory ../inventory.json --json   # operator inventory (see below)
jankhunt42 map . --max-depth 6                # reachability bound (1-8, default 4)
jankhunt42 map . --mermaid > map.mmd          # Mermaid flowchart (documentation view)
jankhunt42 map . --csv map-csv                # nodes.csv + edges.csv for diagram tools
jankhunt42 map . --what-if scenario.json      # hypothetical mutations on a copy of the graph
jankhunt42 map . --drift stored-map.json      # stored map vs the current repository
```

Exit codes: `0` success, `2` usage error (bad path, unresolvable `--base`,
unreadable inventory). `map` never gates; gating belongs to `passport --fail-on`.

## Evidence states

Every edge records how it was learned, separately from its confidence and
from the trust of its source:

| `verification` | Meaning | Example |
|---|---|---|
| `observed` | The artifact directly contains the statement | `psycopg.connect("postgresql://db/x")`, `requests.post("https://…")`, `"DELETE FROM t"` in a string |
| `declared` | Configuration or a manifest says so | `.env` value, Kubernetes env/RBAC, workflow `permissions:`, Terraform role assignment |
| `inferred` | Heuristic only | an SDK import, a manifest dependency, an endpoint resolved by environment-variable name |
| `provider-verified` | An operator inventory outside the scanned repository says so | effective grant exported by your platform team |
| `unknown` | Not established | |
| `refuted` | An operator inventory explicitly refutes the edge | excluded from reachability |

Paths take the evidence tier of their **weakest** edge: `verified` (3,
provider-verified only) > `supported` (2, observed or declared) > `inferred` (1)
> `unknown` (0). "Known" reach in the terminal view means verified; everything
else is potential.

`provider-verified` can only come from `--inventory PATH` where `PATH` is
outside the scanned repository. A repository-controlled inventory, or one
inside the tree, is downgraded to `declared` with a warning. jankhunt42 does
not verify inventory signatures; it records who claimed what.

## Graph model

Nodes: `application` (the repository's code), `workload` (Kubernetes
workload, compose service, CI workflow), `identity` (service account,
`GITHUB_TOKEN`, OIDC federation, cloud deploy identity, IaC principal),
`database`, `api`, `storage`, `queue`, `external`, and `unknown` (an
unresolved target; jankhunt42 never invents a host).

Each node carries `trust_domain` (`local`, `internal`, `external`, `unknown`),
`environment` (`production`, `non-production`, `unknown`), `sensitivity`
(`public`, `internal`, `confidential`, `restricted`, `unknown`), and
`criticality` (`low`…`critical`, `unknown`). Trust domain is an attribute
rather than a node: a boundary crossing is any edge whose endpoints sit in
different known domains or environments. Sensitivity and criticality come only
from declarations (`.jankhunt42.json` `passport.assets`) or an operator
inventory, never from guessing at names; environment may be *inferred* from
tokens such as `prod`/`staging` in hostnames, namespaces, or file names. The
one exception is a credential store: Kubernetes Secrets and Azure Key Vault
are `restricted` by resource type (`classification_source: resource-type:
credentials`). Names that suggest personal, health or financial data
(`payroll`, `patient`, `ledger`, `customer`…) on a data store add a
`sensitivity_hint` attribute and the `sensitive-by-name` unknown, never a
sensitivity.

Edges: `connects`, `authenticates-as`, `reads`, `writes`, `deletes`,
`administers`, `calls`, `publishes`, `exports`, `depends-on`, each with a
`capability` (`none`, `read`, `write`, `delete`, `admin`, `unknown`). Parallel
edges are kept (the same app can have an observed `reads` and an unknown
`connects` to one database). Repeated receipts merge into one edge: duplicate
evidence never creates a second asset or inflates any count.

IDs are `kind:` plus a hash of the sanitized canonical key (credentials are
removed before hashing), so they are stable across runs, file order, and
machines. Output is sorted; with `SOURCE_DATE_EPOCH` set, repeated runs are
byte-identical (`generated_at` is the only volatile field and is excluded from
`scan_id`).

## Propagation semantics

Direction convention: `A -> B` means **A acts on B**. Blast radius walks
forward from each principal, separately per impact:

| Edge | Confidentiality | Integrity | Availability |
|---|---|---|---|
| `authenticates-as` | yes | yes | yes |
| capability `read` | yes | — | — |
| capability `write` | via `calls`/`exports`/`publishes` only | yes | — |
| capability `delete` | via `calls`/`exports`/`publishes` only | yes | yes |
| capability `admin` | yes | yes | yes |
| `connects`/`calls` with capability `unknown` | potential (≤ inferred) | potential | potential |
| `exports`/`publishes` with capability `unknown` | potential | — | — |
| `depends-on` | never | never | never |
| `refuted` | never | never | never |

Availability also lists the principals that directly use anything the
principal could disrupt (one reverse hop), because they break with it.

Each reachable asset appears once with its best tier and a deterministic
witness path (every edge on it carries receipts). Traversal is a bounded BFS
per tier, so cycles terminate; hitting `--max-depth` with admissible edges
left is reported as truncation, never as a clean result. An independent
brute-force oracle (`tests/oracle.py`) enumerates every simple path on
thousands of seeded small graphs and must agree exactly.

## Exposure class

One qualitative class per principal, and the worst across principals:
**Low**, **Moderate**, **High**, **Critical**, or **Unknown**. It is a
separate axis from the numeric Jank Score and from the passport decision.

| Class | When (any of) |
|---|---|
| Critical | verified write/delete/admin over a `critical` or `restricted` asset; verified export of sensitive data to an external destination |
| High | possible write/delete/admin over a production, high/critical, or sensitive asset; supported read of `restricted` data; a sensitive source and an external destination reachable from the same principal (co-reachability, explicitly not a data flow) |
| Moderate | any possible reach to a non-local system whose capability or classification is not established |
| Low | only local assets reached, or nothing reached with coverage (`0 observed`, not "none possible") |
| Unknown | no supported files were inspected |

Every condition is upward-closed, so adding authority, sensitivity,
criticality, evidence strength, or reach can never lower the class (tested
exhaustively). The breadth indicator `1 + 0.5·(1 − e^(−(n−1)/4))` over distinct
trust domains is shown for context only; it saturates at 1.5 and never blocks
or lowers anything. These are explainable heuristics, not calibrated
probabilities of compromise.

## Credential blast radius

The exposure class asks what each principal can hurt. The credential blast
radius asks the same question from the credential's side: for every
`identity` node (a managed identity, service principal, deploy identity,
`GITHUB_TOKEN`, Databricks secret, Kubernetes service account), what it
unlocks if it is misused or leaks, and which principals hold it. It walks the
same edges with the same admissibility table, starting at the identity.

Each entry (`assessment.credential_blast_radius.identities`) lists `holders`,
`unlocks` (asset, impacts, best tier, witness path), the `mutating` subset,
whether the identity is `secretless` (managed or workload identity), and flags:

| Flag | Meaning |
|---|---|
| `shared` | two or more principals hold an identity with mutating authority, so one leak or misuse reaches every holder's authority |
| `secret-store-pivot` | it can read a credential store; the secrets inside may unlock systems that are not in the graph (also the `secret-store-pivot` unknown) |
| `broad-scope` | it holds a role on a subscription, resource group, or other scope wider than the mapped assets |
| `holder-not-visible` | grants are declared for it, but nothing in the repository runs as it |

Entries are ordered by mutating reach, then total reach, then holders. The
section is informational: it never changes the exposure class, so the
monotonicity guarantee above still holds.

## Adapters

| Adapter | Reads | Emits |
|---|---|---|
| python | imports, client constructors, literal DB/queue URLs, HTTP calls (literal or URL constant), `os.environ`/`getenv`, SQL verbs in string literals, S3/Blob/queue and Key Vault secret operations, boto3 service clients, Spark/Unity Catalog tables, `dbutils.secrets`/`dbutils.fs`, Azure credentials | connects/calls/reads/writes/deletes/administers/publishes/authenticates-as |
| javascript | `require`/`import` of DB, cloud, queue, LLM SDKs; `fetch`/axios calls; `process.env`; Azure credentials | same |
| dotnet | `SqlConnection`, `UseNpgsql`, `ConnectionMultiplexer`, Azure clients and credentials, `HttpClient`, `GetConnectionString`, `Configuration[...]` | same |
| go, rust, jvm | Go imports, Rust `use`, Java/Kotlin imports of database, cloud, queue, and model SDKs; JDBC URLs; `os.Getenv`/`env::var`/`System.getenv`; SQL verbs; Azure credentials | same |
| notebook | Jupyter and Databricks `.ipynb` code cells (read by the python adapter); `%sql` cells count as `spark.sql`; other magics are skipped | same |
| config / appsettings | `.env*`, `*.properties`, `*.ini`, `*.toml`, config/settings JSON, `appsettings*.json` `ConnectionStrings` | declared endpoints (definitions for the env-var join) |
| kubernetes | workloads, `serviceAccountName`, env values, `secretKeyRef` (name only, never dereferenced), `envFrom`, Role/ClusterRole + bindings | workloads, identities, RBAC authority over the Kubernetes API and Secrets |
| compose | services, data-store images, `depends_on`, environment | workloads, data stores, dependencies |
| github-actions | `permissions:` (top-level and per job), `environment:`, cloud login actions, `secrets.*` names | workflow, `GITHUB_TOKEN` scopes, OIDC and deploy identities |
| terraform | `resource` blocks for data stores; Owner/Contributor/`roles/owner`/`Action: "*"` grants. `azurerm`/`azuread` in depth: data stores, Key Vault, Databricks, Synapse, Service Bus and AI accounts (also `data` blocks for existing ones); compute with `identity {}` blocks; user-assigned identities; `azurerm_role_assignment` (role by name, built-in GUID, or a custom `azurerm_role_definition` whose actions set the capability; scope and principal resolved by reference, including `<resource>.identity` and AKS `kubelet_identity`); Key Vault access policies | assets, workloads, managed identities, and declared grants with capabilities from the role (best effort; no HCL evaluation) |
| manifest | `requirements*.txt`, `pyproject.toml`, `package.json`, `*.csproj`, `go.mod`, `Cargo.toml`, `pom.xml`, `build.gradle(.kts)` | weak `inferred` evidence, only when code shows nothing for that family |
| openapi | OpenAPI 3 / Swagger 2 documents (YAML or JSON): servers and operations | **no edges**: enriches an `api`/`external` node the code already calls (`openapi_operations`), otherwise records the operations the application `exposes` |
| mcp | MCP server definitions: `.mcp.json`, `.cursor/mcp.json`, `.vscode/mcp.json`, `.gemini/settings.json`, `.codex/config.toml` MCP tables, `opencode.json(c)`, `claude_desktop_config.json`, and any JSON with `mcpServers` | an **AI agent** principal per file (`platform: ai-agent`), `calls` to each enabled server (local process or remote endpoint), `connects` from a server to endpoints in its args/env, `authenticates-as` to credentials by name; every capability `unknown`, every edge `declared` |

The code adapters also know the stack AI app builders use: Supabase,
Firebase/Firestore, Neon/Vercel Postgres, Upstash, Turso, Airtable, and
Google Sheets clients and hosts (`*.supabase.co`, `*.firebaseio.com`,
`firestore.googleapis.com`, `*.neon.tech`, `*.upstash.io`, `*.turso.io`,
`api.airtable.com`, `sheets.googleapis.com`) are data stores; Stripe, Twilio,
SendGrid, Resend, Slack, Notion, and model APIs (OpenAI, Anthropic, Gemini,
Groq, Mistral) are external services. A `${PASSWORD}` placeholder in a
connection string's userinfo no longer hides a concrete host.

**Cloud data platforms.** Hosts identify the service: Azure SQL
(`*.database.windows.net`), Azure Database for PostgreSQL/MySQL, Cosmos DB,
Storage (blob, dfs, file, queue, table), Service Bus, Azure Cache for Redis,
Key Vault, Databricks (`*.azuredatabricks.net`, `*.cloud.databricks.com`),
Synapse, Fabric/OneLake, Data Explorer, AI Search, Azure OpenAI and AI
services; AWS RDS, Redshift and S3; BigQuery and Cloud Storage; Snowflake;
MongoDB Atlas. A per-tenant host written as a bare string
(`server_hostname="adb-1.2.azuredatabricks.net"`) is a node; a shared global
endpoint named alone is not, because lookup tables and docs name those
without connecting. JDBC URLs are parsed with their `;property=value` tail
removed.

**Spark and Unity Catalog.** `spark.read.table`, `spark.table` and
`DeltaTable.forName` read; `saveAsTable`, `insertInto` and `toTable` write,
and a write with `mode("overwrite")` counts as delete. SQL text with
three-part names (`catalog.schema.table`) in a Spark file, and also
`schema.table` or `{table}` names inside a `spark.sql(...)` literal, reads
(`FROM`/`JOIN`/`USING`), writes (`INTO`/`UPDATE`, `CREATE TABLE/VIEW`),
deletes (`DELETE FROM`, `TRUNCATE`, `DROP`, `CREATE OR REPLACE TABLE`,
`INSERT OVERWRITE`), or administers (`ALTER TABLE`). Each catalog is one
`database` node; a two-part name is the workspace's `default` catalog.
f-string names are resolved through simple string assignments (the file's
own, then a name with one value anywhere in the repository); a catalog that
stays unresolved gets its own node. `dbutils.secrets.get(scope, key)`
becomes an identity named by scope and key; the value is never read.

**Azure identity.** `DefaultAzureCredential`, `ManagedIdentityCredential`,
`WorkloadIdentityCredential` (secretless) and `ClientSecretCredential`,
`ClientCertificateCredential` and similar (secret-bearing) in Python, .NET,
JavaScript and Go become identity nodes the application `authenticates-as`.
Their role assignments are not visible in code; in Terraform they are, and
the role name sets the capability: Owner, Contributor, User Access
Administrator and `* Data Owner` administer; `* Data Contributor`, writers
and senders write; Reader, `* Data Reader`, receivers and Key Vault Secrets
User read; custom roles stay `unknown`.

The **agent blast radius** from the mcp adapter is walked like any other
principal: unknown capability counts as possibly anything, so an agent
whose database server points at a production host is High exposure. The
`agent-tool-capability` unknown records that each server decides at runtime
what its tools can do. See `references/citizen.md`.

Endpoint resolution: a code-side environment read (`DATABASE_URL`) is joined
to a repository definition of the same name (`.env.example`, compose,
Kubernetes, appsettings) as `inferred`, with the assumption that the deployed
value may differ. A read with no definition becomes an `unknown`/unresolved
node. Placeholders such as `${DB_HOST}` or `{{ .Values.host }}` stay
unresolved.

Not inspected: test paths (they do not describe the deployed principal),
documentation, `.sql` migration files, binaries, lockfiles, generated and
vendored trees, files over `--max-file-bytes`, anything beyond `--max-files`,
and git symlinks/submodules. These appear in `coverage`. Malformed YAML/JSON
is recorded as a parse failure and makes coverage `partial`.

## Egress boundary (`egress`)

A committed, structured network allowlist for an AI agent's sandbox is read
as a **declared boundary**:

- Codex `config.toml`: `features.network_proxy.domains` and
  `permissions.<name>.network.domains` (`allow` / `deny`), with typed proxy
  activation and declared profile selection. Both the Boolean feature switch
  and nested `enabled` form are recognized. A legacy `sandbox_mode` selector
  makes applicability unknown because effective precedence is not resolved.
- Claude Code `.claude/settings*.json`: `sandbox.network.allowedDomains` and
  `deniedDomains`, including optional destination ports and bracketed IPv6.
  An unqualified entry matches every port. Known protocol defaults supply a
  missing mapped port; unknown ports that affect the decision remain unassessed.
  Malformed or unsupported domain patterns make applicability unknown.
  Custom proxy ports make built-in domain-filter applicability unknown; the
  external proxy's policy is not inspected.
- OpenShell policies: every `network_policies` endpoint `host` and
  `allowed_ips` (default deny).

It is compared with the resolved hosts the map reaches (any principal,
including AI agents and MCP servers), in both directions, with the evidence
tier of the best path: **outside** (a reached host no allowlist admits, or
one a deny list names), **unused** (an allowed entry nothing mapped reaches;
tooling such as package registries may still need it), and **wildcards**.
Permission profiles are inventoried separately. Only the repository's declared
selection counts; inactive profiles add no permissions, and disabled or
unresolved activation is not credited.

Each tool is assessed on its own (`egress.contexts`), and one tool's allowlist
never covers another tool's reach. When every tool's selected declaration is
resolved, `egress.state` is `declared` and `egress.outside` lists each reached
destination that at least one of them does not admit, with `contexts` naming
which. Different ports on the same host remain separate; known ports are in
the optional `port` field of `outside` and `unassessed` rows and are displayed
with the host in text and HTML views.
So a repository that commits the Claude Code, Codex and OpenShell policies from
`--emit-sandbox-policy` gets one answer for all three. Two settings scopes of
the same tool (for example `.claude/settings.json` and
`.claude/settings.local.json`) merge in ways this does not model, so they make
coverage unknown.

If selection, activation, inheritance or syntax is unresolved for any tool,
`egress.state` is `unknown` and `egress.unassessed` records the reached
endpoints whose coverage is unknown. An empty `outside` list in that state is
not evidence of containment. With no allowlist committed, reach is also unknown
rather than open or closed.

The boundary fields `profile`, `selected` and `enabled` describe declaration
applicability, not runtime verification. Policies without activation switches
are assessed as declarations when selected alone. Endpoint inventory does not
model every process, port or request constraint. Effective settings and runtime
enforcement are not verified; `--redact` keeps counts and preserves unknown state.

## Redaction and safety

- Before anything is hashed, displayed, or stored, URLs lose userinfo, query,
  fragment, and path; `.NET` connection strings lose `Password`/`User ID`/keys;
  private keys, JWTs, long opaque tokens, provider token formats, and email
  addresses are removed; control and bidi characters are neutralized.
- `--redact` (shareable): ordinal pseudonyms for every node, edge, and receipt;
  labels reduced to engine + ordinal; snippets and hashes dropped; repository
  name replaced. The graph itself is sensitive architecture: share the
  redacted form.
- The HTML explorer is one file with a `default-src 'none'` Content-Security-
  Policy: no network, fonts, or CDNs. Data is embedded as escaped JSON and
  rendered with `textContent` only.
- Paths in every artifact are relative to the scan root; absolute paths, home
  directories, and usernames are not emitted.

## `--base` graph delta

`map --base REF` builds both graphs from **committed git objects** (`REF` and
`HEAD`) via `git ls-tree`/`cat-file`; dirty or untracked files never leak in
(a warning says so). Declarations are read from each revision's own
`.jankhunt42.json`. The `delta` reports added/removed nodes and edges,
permission escalations and reductions grouped by source/target/identity,
newly reachable (and newly reachable sensitive) assets per principal and
impact, added/removed trust-boundary crossings, exposure change, and coverage
regression. A removed edge whose evidence file was skipped on the head side is
`not-observed`, not `removed`.

## Exports: Mermaid and CSV

Canonical JSON stays the evidence store; these are views.

- `--mermaid` prints a `flowchart LR`. Node IDs are ordinal aliases. Labels are quoted, and quotes, brackets, braces, parentheses, pipes, angle brackets, backticks and semicolons become Mermaid entity codes, so repository text cannot close a label or add `click`/`style` statements. Solid arrows mean observed, declared or verified evidence; dashed arrows mean inferred or unknown. Output is capped at 200 nodes, with an explicit `%% truncated` line when anything is cut. No Mermaid renderer ships with jankhunt42, so the output is checked against the grammar subset it uses, not rendered.
- `--csv DIR` writes `nodes.csv` and `edges.csv` with stable IDs, evidence state, evidence tier, trust boundary and `path:line` receipts. Cells starting with `=`, `+`, `-` or `@` are prefixed with `'` to block spreadsheet formula injection. This is the only `map` option that writes files, and only into `DIR`.

Both compose with `--redact`.

## Code-to-workload bindings

By default jankhunt42 does not guess which workload runs the repository code. Declare it instead:

```json
{"passport": {"bindings": [{"workload": "Deployment payments-prod/payments-api"}]}}
```

A binding adds two `declared` edges. The workload `authenticates-as` the application, so its blast radius includes everything the code reaches. The application `authenticates-as` each of the workload's identities, so the code inherits its RBAC paths. The `code-to-workload-binding` unknown then disappears. A binding that matches nothing produces a warning.

## Path strength (operator-weighted, optional)

A trusted operator inventory may weight a grant with `"attenuation": 0.0-1.0`. Repository inventories are ignored, with a warning. When any edge carries a weight, each reachable asset also gets `strength` and `strength_path`. This is the maximum product of weights over admissible paths within `--max-depth`, computed by exact bounded dynamic programming and checked against a brute-force oracle. Unweighted edges count as 1.0, and 0 removes an edge.

Strength orders presentation only. It is **not a probability**, and it never changes the exposure class or any passport rule.

## What-if scenarios (`--what-if`)

```json
{"name": "scope ledger access", "mutations": [
  {"op": "revoke", "source": "demo-app", "target": "ledger-db"},
  {"op": "block-egress", "principal": "demo-app"},
  {"op": "add-edge", "source": "demo-app", "target": "reports", "kind": "writes", "capability": "write"},
  {"op": "set-capability", "source": "demo-app", "target": "redis", "to": "read"},
  {"op": "remove-node", "match": "openai"},
  {"op": "remove-edge", "source": "payments-api", "kind": "connects"},
  {"op": "compromise-identity", "identity": "payments-api"}
]}
```

Mutations run on a copy of the graph, and nothing on disk, in git or on a network changes. `revoke` removes write, delete and admin edges between the matches. Edges with unknown capability remain, because unknown is still possible. Added edges are `declared` and labeled hypothetical. `compromise-identity` computes that identity's own blast radius, which expands only the grants the identity holds in the graph.

The result goes in `whatif`, containing:
- each mutation with its match count;
- the unmatched mutations;
- a full graph delta: exposure change, new and lost reach, boundaries;
- the radii of compromised identities.

## Drift (`--drift stored-map.json`)

Compares a stored `jankhunt.map.v1` report with the current working tree, using the same delta as `--base` and labeled `snapshot-drift`. This is a static repository comparison, not observed runtime drift. There is no daemon; schedule it from CI if you want it periodic. `--drift` and `--base` are mutually exclusive.

## Inventory file (`--inventory`)

```json
{
  "schema_version": "jankhunt.inventory.v1",
  "assets": [
    {"match": "ledger-db", "sensitivity": "restricted", "criticality": "critical", "environment": "production"}
  ],
  "grants": [
    {"principal": "payments-api", "target": "ledger-db", "capability": "write", "verification": "provider-verified"},
    {"principal": "demo-app", "target": "analytics-vendor", "target_kind": "external",
     "target_trust_domain": "external", "kind": "exports", "capability": "write", "data_sensitivity": "confidential",
     "verification": "provider-verified"}
  ],
  "refute": [{"principal": "demo-app", "target": "redis cache"}]
}
```

`match`, `principal`, and `target` match a node ID exactly or a display-label
substring, engine, or kind (case-insensitive). Unmatched entries are warnings.
Operator classifications override repository declarations; repository
declarations never override operator ones. `refute` applies only to a trusted
inventory.

## Limitations

- Static text only: no data-flow analysis, no evaluation of Helm/Kustomize/
  HCL/variables, no runtime reachability, firewall, or IAM evaluation.
  Helm and Go templates (YAML with `{{ ... }}` under `templates/` or
  `charts/`) are listed as the `unrendered-templates` unknown rather than
  failing to parse: render them (`helm template`) and map the output to see
  what they define.
- The YAML reader is a bounded subset: block mappings and sequences, flow
  collections (also across lines), block scalars, and `---` documents.
  Anchors and aliases are kept as text. `appsettings*.json` may carry
  comments and trailing commas, as .NET allows.
- Effective privileges cannot be proven from a connection string or an SQL
  verb; they are labeled as possibilities until an operator inventory says
  otherwise.
- Terraform is read block by block: modules, variables, `count`/`for_each`,
  inherited role assignments, conditions, and deny assignments are not
  evaluated. A principal given as a variable becomes an `azure principal`
  node with no visible holder.
- Spark tables are grouped by catalog, not by table. Notebook evidence line
  numbers count the notebook's joined code cells, not the JSON file's lines.
- Which workload runs the repository code is not inferred; declare it with a
  `passport.bindings` entry.
- Logical databases on one server are one node (`databases` attribute); a
  different host or environment is a different node.
- Monorepos map as one `application` node.
- MCP servers are mapped from their definitions only: the tools a server
  exposes, and what they do, are not visible statically. A server that is
  defined but never enabled in the user's client still appears.
- Adapter precision and recall are measured only on the synthetic fixtures in
  `tests/` and on the repository's own hand-maintained self-map ground truth;
  no broader accuracy claim is made.
