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
tokens such as `prod`/`staging` in hostnames, namespaces, or file names.

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

## Adapters

| Adapter | Reads | Emits |
|---|---|---|
| python | imports, client constructors, literal DB/queue URLs, HTTP calls (literal or URL constant), `os.environ`/`getenv`, SQL verbs in string literals, S3/Blob/queue operations, boto3 service clients | connects/calls/reads/writes/deletes/administers/publishes |
| javascript | `require`/`import` of DB, cloud, queue, LLM SDKs; `fetch`/axios calls; `process.env` | same |
| dotnet | `SqlConnection`, `UseNpgsql`, `ConnectionMultiplexer`, Azure clients, `HttpClient`, `GetConnectionString`, `Configuration[...]` | same |
| config / appsettings | `.env*`, `*.properties`, `*.ini`, `*.toml`, config/settings JSON, `appsettings*.json` `ConnectionStrings` | declared endpoints (definitions for the env-var join) |
| kubernetes | workloads, `serviceAccountName`, env values, `secretKeyRef` (name only, never dereferenced), `envFrom`, Role/ClusterRole + bindings | workloads, identities, RBAC authority over the Kubernetes API and Secrets |
| compose | services, data-store images, `depends_on`, environment | workloads, data stores, dependencies |
| github-actions | `permissions:` (top-level and per job), `environment:`, cloud login actions, `secrets.*` names | workflow, `GITHUB_TOKEN` scopes, OIDC and deploy identities |
| terraform | `resource` blocks for data stores; Owner/Contributor/`roles/owner`/`Action: "*"` grants | assets and privileged IaC principals (best effort; no HCL evaluation) |
| manifest | `requirements*.txt`, `pyproject.toml`, `package.json`, `*.csproj` | weak `inferred` evidence, only when code shows nothing for that family |
| openapi | OpenAPI 3 / Swagger 2 documents (YAML or JSON): servers and operations | **no edges**: enriches an `api`/`external` node the code already calls (`openapi_operations`), otherwise records the operations the application `exposes` |

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
- Effective privileges cannot be proven from a connection string or an SQL
  verb; they are labeled as possibilities until an operator inventory says
  otherwise.
- Which workload runs the repository code is not inferred; declare it with a
  `passport.bindings` entry.
- Logical databases on one server are one node (`databases` attribute); a
  different host or environment is a different node.
- Monorepos map as one `application` node.
- Adapter precision and recall are measured only on the synthetic fixtures in
  `tests/` and on the repository's own hand-maintained self-map ground truth;
  no broader accuracy claim is made.
