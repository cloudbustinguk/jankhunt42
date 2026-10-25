# Examples: the synthetic demo repository

Everything below is real output from the checked-in synthetic fixture
`tests/fixtures/demo-app`, a fictional payments service. It has:

- a Postgres ledger, a Redis cache, and an S3 report export;
- an LLM call;
- a Kubernetes deployment and a GitHub Actions deploy workflow;
- some Terraform.

The test suite regenerates these samples and fails if this page drifts from
them. Screenshots of the same fixture in the terminal and as HTML are in the
README gallery.

## `jankhunt42 map tests/fixtures/demo-app` at 100 columns

<!-- sample:map-100 -->
```text
╭────────────────────────────────────────────────────────────────────────────────────────────────╮
│   J A N K H U N T 4 2   // blast radius explorer                                               │
│ demo-app  ·  working-tree  ·  19 nodes  ·  19 edges                                            │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

╭─ what can it hurt? ────────────────────────────────────────────────────────────────────────────╮
│ EXPOSURE              High  qualitative; a path is a possibility, not proof                    │
│ evidence coverage     complete-for-supported-types  (11/13 files, 8 adapters)                  │
│ edge evidence         0 [verified]  17 [supported]  2 [inferred]  0 [unknown]                  │
│ reach                 0 known [verified]  ·  37 potential  ·  7 unknown-capability             │
│ breadth               1.264 over 4 trust domains (informational, never blocks)                 │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

connected systems
  2 api   1 application   3 database   3 external   5 identity   1 storage   1 unknown   3 workload

trust-boundary crossings
  internal→external

highest-impact admissible paths
  High integrity [supported] X-HIGH-AUTH
    possible mutating/destructive authority over a production, critical, or sensitive asset
    demo-app -[deletes/delete, observed]→ postgresql ledger-db.prod.internal
  High availability [supported] X-HIGH-AUTH
    possible mutating/destructive authority over a production, critical, or sensitive asset
    demo-app -[deletes/delete, observed]→ postgresql ledger-db.prod.internal
  High confidentiality [supported] X-HIGH-EGRESS
    sensitive source and external destination are reachable from the same principal (possible
    egress path; no data-flow evidence implied)
    demo-app -[reads/read, observed]→ postgresql ledger-db.prod.internal
  High integrity [supported] X-HIGH-AUTH
    possible mutating/destructive authority over a production, critical, or sensitive asset
    demo-app -[writes/write, observed]→ s3 bucket demo-reports-prod
  High confidentiality [supported] X-HIGH-READ
    supported read reach to restricted data
    k8s Deployment payments-prod/payments-api -[authenticates-as/unknown, declared]→ k8s service
      account payments-prod/payments-api -[reads/read, declared]→ kubernetes secrets
      (cluster)

credential blast radius  (what each identity unlocks; informational)
  ◆ GITHUB_TOKEN (deploy.yml)
    unlocks 1 (1 mutating): GitHub repository (this repo)  ·  held by CI workflow deploy.yml
  ◆ azure deploy identity (deploy.yml)
    unlocks 1 (1 mutating): azure cloud control plane  ·  held by CI workflow deploy.yml
  ◆ azure principal var.deployer_principal_id  holder-not-visible
    unlocks 1 (1 mutating): postgresql ledger-prod  ·  held by no visible holder
  ◆ k8s service account payments-prod/payments-api  secret-store-pivot
    unlocks 1 (0 mutating): kubernetes secrets (cluster)  ·  held by k8s Deployment
    payments-prod/payments-api

unknowns  (unknown is not safe, and not dangerous)
  ? effective-privileges: effective grants are not verified for 19 edge(s); static evidence
      cannot prove privileges
  ? unresolved-targets: 1 endpoint(s) are resolved only at runtime (environment, secrets, or SDK
      defaults)
  ? unknown-capability: 7 connection(s) have unknown capability; treated as possibly read,
      write, or destructive
  ? data-classification: 6 asset(s) have no declared data sensitivity
  ? sensitive-by-name: 1 unclassified asset(s) have names suggesting personal, health or
      financial data (ledger); declare their sensitivity in passport.assets
  ? environment: 6 asset(s) have unknown environment (production vs non-production)
  ? code-to-workload-binding: which workload runs the repository code is not inferred; declare
      it with passport.bindings if needed
  ? runtime-reachability: static analysis only: network reachability, firewalls, and live data
      movement were not tested

  explore: jankhunt42 map . --html > map.html   ·   data: --json   ·   shareable: --redact
```
<!-- /sample -->

## `jankhunt42 passport tests/fixtures/demo-app` at 100 columns

<!-- sample:passport-100 -->
```text
╭────────────────────────────────────────────────────────────────────────────────────────────────╮
│   J A N K H U N T 4 2   // software passport                                                   │
│ demo-app  ·  revision unknown                                                                  │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

╭─ can we responsibly ship it? ──────────────────────────────────────────────────────────────────╮
│ RELEASE ASSESSMENT    REVIEW  advisory                                                         │
│ technical jank score  67/100  grade E  policy fail                                             │
│ exposure              High  separate from the Jank Score                                       │
│ evidence coverage     4/10 areas observed, declared, or inferred                               │
│ lifecycle             assessed  ·  acceptance [not-supplied]                                   │
╰────────────────────────────────────────────────────────────────────────────────────────────────╯

why  (rule outcomes, not a weighted score)
  REVIEW P-DAT-002 possible mutating, destructive, or unknown authority over a production,
      critical, or restricted asset; verify effective grants
  REVIEW P-AI-001 2 confidential or restricted data store(s) are reachable alongside an external
      AI service; confirm what data reaches the provider and how it is handled (retention,
      training use, region) before release: openai api.openai.com with postgresql
      ledger-db.prod.internal, s3 bucket demo-reports-prod
  REVIEW P-JNK-001 Jank Score policy fail; 0 blocker-severity lead(s) (leads, not confirmed
      defects)

evidence
  ownership [observed]   provenance [not-observed]   data inventory [observed]   ci [observed]
  tests [not-observed]   observability [not-observed]   health checks [observed]
  runbook [not-observed]   security policy [not-observed]   change control [not-observed]
  owners: @demo-org/payments-team
  change control: [unknown]  review unknown  app bypass unknown
  package sources: npm unknown, pypi unknown

ai use  (static inventory, not proof of use)
  services: openai api.openai.com [inferred]
  agents: 0 tool server(s) · 0 instruction file(s) · no agent tooling observed
  frameworks: NIST AI RMF GOVERN 6.1, MAP 4.1, MAP 5.1, MEASURE 2.5, MEASURE 2.7, MEASURE 2.10,
              MANAGE 1.3, MANAGE 3.1  (orientation, not conformity)

next steps
  1. Verify effective grants for the flagged connections and scope them to least privilege;
     record the result in an operator inventory to turn leads into verified evidence.
  2. Check what data reaches the AI provider and its terms (retention, training use, region),
     record the decision, or keep restricted data away from AI calls.
  3. Work down the weakest Jank Score dimension first (`jankhunt42 score`), then the
     highest-severity leads (`jankhunt42 scan --min-severity critical`).
  4. Add or declare observability evidence (currently not observed).
  5. Add or declare runbook evidence (currently not observed).

  export: jankhunt42 passport . --json | --html > passport.html   ·   shareable: --redact
```
<!-- /sample -->

## Reading it the way the tool means it

- The exposure is **High** because of *possible* destructive authority: an observed `DELETE` statement against a database declared `restricted`/`critical`. The edge is `observed`, not `verified`, which is why the reach reads "0 known".
- The decision is **review**, not **block**. Static leads ask for grant verification; they never block on their own.
- The co-reachability of the restricted ledger and an external endpoint raises exposure, but it is reported as a *possible* egress path, not a data flow.
- `P-AI-001` asks for a decision because the restricted ledger and the confidential report bucket are reachable alongside an external AI service (OpenAI). It claims no data flow; it asks someone to check what reaches the provider and how the provider handles it, then record that decision.
- Runbook and observability are **not-observed**, which means unknown, not absent.
