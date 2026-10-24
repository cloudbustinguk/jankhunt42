# Supply-chain evidence

jankhunt42 treats SBOMs, provenance attestations, and AppTrust evidence as
review context. It parses evidence that is already on disk, correlates subjects
and provenance, and reports gaps. By default it is offline and read-only.

The core rule is simple: **never fabricate cryptographic verification**.
jankhunt42's stdlib-only runtime has no X.509, ECDSA, or transparency-log code,
and it will not grow home-made cryptography. Signatures are checked only by the
native verifiers (`gh`, `cosign`, `jf`), which jankhunt42 can run for you in
[verification mode](#verification-mode---verify). Labels:

| Label | Meaning |
|---|---|
| `tool-verified` | A native verifier run by `--verify` checked the signature, the transparency-log entry, and the signer identity named in the plan. |
| `signature-only` | A verifier checked the signature but not who signed it (for example JFrog using the key embedded in a Sigstore bundle). Not counted as verified. |
| `provider-verified` | The exporter recorded a successful verification result, for example JFrog's `verificationResult`. This is the exporter's claim. |
| `unverified` | A signature or DSSE envelope is present, but nothing has verified it. |
| `unsigned` | No signature material was found in the evidence. |
| `failed` | The exporter or a verifier recorded a failed verification. |

When evidence is `unverified` or `unsigned`, the report includes a verification
hint such as `gh attestation verify`, `cosign verify-attestation`, or
`jf evd verify`.

### Where the evidence usually lives

Release evidence is rarely committed. It sits in services, so getting it onto
disk takes the network:

| Evidence | Where | Access | Signed? |
|---|---|---|---|
| GitHub artifact attestation (`actions/attest`, `attest-build-provenance`) | GitHub attestations API, by artifact digest | no token for public repositories; `GH_TOKEN` for private | yes (Sigstore bundle) |
| SBOM uploaded with `actions/upload-artifact` (for example syft SPDX) | GitHub Actions artifacts | `GH_TOKEN` always, even for public repositories; expires with the retention period | **no**: only GitHub's recorded zip digest |
| SBOM attested with `actions/attest` and `sbom-path` | GitHub attestations API | as attestations | yes |
| JFrog evidence | JFrog Platform | JFrog credentials | yes (DSSE or Sigstore bundle) |

Attest SBOMs rather than only uploading them as artifacts: an attested SBOM is
signed, fetchable by digest, and verifiable offline after download.

## Supported inputs

| Input | Forms |
|---|---|
| SPDX 2.x | JSON (`spdxVersion`, `packages`) and tag-value (`SPDXVersion:`, `PackageName:`) |
| SPDX 3 | JSON-LD `@graph` with SPDX 3.0.1 elements: `software_Package` (`software_packageVersion`, `software_packageUrl`, `suppliedBy`, `verifiedUsing`, `externalIdentifier`), `CreationInfo`, `software_Sbom`, licence and dependency `Relationship`s |
| CycloneDX | JSON (`bomFormat: CycloneDX`) and XML `<bom>` |
| GitHub artifact attestations | Raw Sigstore bundle / DSSE JSON, JSONL from `gh attestation download` |
| Sigstore / in-toto | DSSE envelope, direct in-toto statement, SLSA provenance v0.2/v1 |
| JFrog AppTrust / `jf evd verify` | JSON with `evidenceVerifications`, `sigstoreBundle`, `verificationResult`, optional `predicate` and `downloadPath` |

Discovery is heuristic and filename/content based. Explicit paths are stronger:

```bash
jankhunt42 supply-chain . --sbom build/app.spdx.json
jankhunt42 supply-chain . --attestation sha256:abc123.jsonl
jankhunt42 supply-chain . --jfrog-evidence apptrust-evidence.json
```

Explicit categories are forced. A file named `artifact.dat` can be supplied as
an SBOM; the parser does not have to guess from the extension. Use
`--no-discover` when you want to inspect only the files you named.

## Normalized report

```json
{
  "root": "/repo",
  "summary": {
    "sboms": 1,
    "attestations": 2,
    "jfrog_bundles": 1,
    "packages": 87,
    "unique_components": 84,
    "verified_attestations": 1,
    "unverified_attestations": 1,
    "unsigned_attestations": 0,
    "failed_attestations": 0,
    "warnings": 0
  },
  "sboms": [
    {
      "path": "build/app.spdx.json",
      "format": "spdx-json",
      "name": "app",
      "spec_version": "SPDX-2.3",
      "created": "2026-10-23T00:00:00Z",
      "package_count": 87,
      "unique_components": 84,
      "licenses": {"Apache-2.0": 40, "MIT": 31},
      "packages": []
    }
  ],
  "attestations": [
    {
      "path": "sha256:abc123.jsonl",
      "source": "github",
      "predicate_kind": "slsa-provenance-v1",
      "subjects": [{"name": "app.tar.gz", "digest": {"sha256": "abc123"}}],
      "builder": "https://github.com/actions/runner/github-hosted",
      "source_repo": "https://github.com/example/app",
      "source_revision": "deadbeef",
      "verification": "unverified",
      "verify_hint": "gh attestation verify <artifact> --repo <owner/repo>",
      "warnings": ["signature material present but not cryptographically verified"]
    }
  ],
  "jfrog": [
    {
      "path": "apptrust-evidence.json",
      "application": "app",
      "version": "1.2.3",
      "release_bundle": "app-rb",
      "evidence_count": 4,
      "verified": 4,
      "failed": 0
    }
  ],
  "requirements": {"sbom": true, "attestation": true, "verified_attestation": false},
  "gate": {"result": "pass", "reasons": []},
  "warnings": []
}
```

The `sboms[].packages` array is capped at 5,000 components to keep output
bounded. Counts are computed from the parsed list; a file larger than 24 MB is
skipped with a warning.

## Attestation extraction

For a DSSE/Sigstore bundle, the parser base64-decodes the envelope payload and
extracts the in-toto statement. It reports:

* subjects and digest algorithms,
* predicate type and a short kind (`slsa-provenance-v1`,
  `slsa-provenance-v0.2`, `spdx-sbom`, `cyclonedx-sbom`, or the predicate tail),
* builder ID,
* source repository and workflow for SLSA v1 `buildDefinition`, or
  config source for SLSA v0.2,
* source revision from `resolvedDependencies` / `materials`,
* material count,
* signature material presence,
* verification status and hint.

A GitHub attestation downloaded with `gh attestation download` is usually a
JSONL file named after the artifact digest, with one bundle per line. jankhunt42
reads each line independently. A JSON object with an `attestations` array or a
single bundle/attestation wrapper is also accepted.

If an attestation predicate is itself an SPDX or CycloneDX document, the parser
adds an embedded SBOM record with path suffix `#predicate`. Embedded SBOMs are
not re-signed; they are evidence inside the signed statement.

## JFrog evidence

JFrog AppTrust exports and `jf evd verify --format json` output can contain:

* top-level application, version, release bundle, and subject metadata,
* `evidenceVerifications` entries with `mediaType`, `predicateType`,
  `createdBy`, `createdAt`, and `verificationResult`,
* a nested `sigstoreBundle` / DSSE envelope,
* a direct `predicate` for evidence types that are not in-toto statements,
* a `downloadPath` pointing at a separately stored evidence payload.

jankhunt42 parses the nested bundle, records the JFrog verification result, and
attempts to load a relative `downloadPath` from the evidence file's directory
or the current directory. It does not follow remote URLs.

A JFrog `verificationResult` containing successful statuses is reported as
`provider-verified`. A failed status is reported as `failed`. A bundle with
signature material but no recorded result is `unverified`.

`verificationResult.keySource` is kept as `key_source`. JFrog reports
`User Provided Key`, `Artifactory Key`, or `Sigstore Bundle Key`. The last
means the key came from the bundle itself, which proves the bundle is
internally consistent but not who signed it; such a record carries a warning
and shows as `provider-verified (bundle key)`. In verification mode it is
`signature-only` unless cosign re-checks the signer identity (below).

## SBOM quality: minimum elements

An SBOM that names packages but not who supplies them, how to identify them,
or how they depend on each other cannot answer the questions it exists for.
Every parsed SBOM carries a `quality` block that counts, per component and
per document, the NTIA minimum elements (*The Minimum Elements for a Software
Bill of Materials*, July 2021):

| Element | Where jankhunt42 reads it |
|---|---|
| supplier | SPDX `supplier` / `PackageSupplier` / 3.0.1 `suppliedBy`; CycloneDX `supplier`, `manufacturer`, `publisher`, `author` (never `group`, which is a namespace) |
| component name and version | package name and version fields |
| unique identifier | a purl or a CPE (SPDX external references or identifiers, CycloneDX `purl`, `cpe`, SWID tag) |
| dependency relationships | SPDX `DEPENDS_ON`/`CONTAINS`-style relationships, 3.0.1 `dependsOn`/`contains`; CycloneDX `dependencies` with `dependsOn` |
| author of the SBOM data | SPDX `Person:`/`Organization:` creators (a `Tool:` creator also counts), 3.0.1 `createdBy`; CycloneDX `metadata.authors`, `manufacturer`, `supplier` |
| timestamp | SPDX `created`; CycloneDX `metadata.timestamp` |

`minimum_elements` is `met` when every element is present for every
component, `partial` when some are missing (the `missing` list names them,
with counts), and `not-met` when the SBOM lists no components. The CISA 2025
draft additions (component hash, licence, tool name, generation context) are
listed separately as `cisa_2025_draft_missing`: they are reported, never
required, until that guidance is final. A field is present or it is not;
this is counting, not a judgement of the SBOM's accuracy.

The report summary carries `sbom_minimum_elements` for the most complete SBOM,
the Markdown view adds a column and a line per SBOM naming what is missing,
and the passport records the same in `provenance`.

## Requirements and gates

```bash
# Fail if no SBOM is present.
jankhunt42 supply-chain . --require-sbom

# Fail unless an SBOM covers the NTIA minimum elements.
jankhunt42 supply-chain . --require-sbom-minimum

# Fail if no attestation is present.
jankhunt42 supply-chain . --require-attestation

# Fail unless the exporter recorded a successful verification.
jankhunt42 supply-chain . --require-verified-attestation

# The same requirements participate in a review gate.
jankhunt42 review . --base origin/main --require-sbom --require-attestation --fail-on major
```

Missing evidence is otherwise a warning, not a source-code finding. This is
intentional: a missing SBOM is a process gap, not a line-level jank score input.

## Verification mode (`--verify`)

```bash
jankhunt42 supply-chain . --verify ../verify-plan.json            # offline: bundle + trusted root
jankhunt42 supply-chain . --verify ../verify-plan.json --online   # may fetch from GitHub; verifiers may go online
jankhunt42 supply-chain . --verify ../verify-plan.json --online --fetch-dir ../evidence
jankhunt42 passport . --verify ../verify-plan.json
```

A verification plan names what to verify and **which signer to trust**, so it
must live outside the scanned repository (a plan inside it is refused: the
repository must not choose its own verifier policy). Unknown keys are errors,
so a misspelt identity constraint cannot silently weaken verification.

```json
{
  "schema_version": "jankhunt.verify.v1",
  "identity": {
    "repo": "example-org/app",
    "repo_id": 123456,
    "signer_workflow": "example-org/app/.github/workflows/release.yml",
    "certificate_identity_regexp": "^https://github.com/example-org/app/",
    "oidc_issuer": "https://token.actions.githubusercontent.com"
  },
  "trusted_root": "trusted_root.jsonl",
  "subjects": [
    {"path": "../app/dist/app.tar.gz", "predicate_type": "https://slsa.dev/provenance/v1"},
    {"path": "../app/dist/app.tar.gz", "bundle": "app.sigstore.json", "verifier": "cosign"}
  ],
  "fetch": {"github_attestations": true, "actions_artifacts": [{"name": "sbom"}]},
  "jfrog": [{"subject_repo_path": "release-local/app/1.2.3/app.tar.gz", "use_artifactory_keys": true}],
  "tools": {"gh": "gh", "cosign": "cosign", "jf": "jf"},
  "timeout_seconds": 120
}
```

Paths are relative to the plan file. Schema: `templates/verify.schema.json`.

**Verifiers** (run as subprocesses, never through a shell):

| Verifier | Command | Identity checked |
|---|---|---|
| `gh` (default) | `gh attestation verify SUBJECT --repo/--owner … [ONE SIGNER FLAG] [--bundle B] [--custom-trusted-root R] --format json` | yes: repository, OIDC issuer, and one signer constraint (gh allows only one; the most specific is used: `certificate_identity`, then `certificate_identity_regexp`, `signer_workflow`, `signer_repo`, recorded as `signer_constraint`); `repo_id` is compared with the certificate's repository ID, which survives renames |
| `cosign` | `cosign verify-blob-attestation --bundle B --type T --certificate-identity[-regexp] … --certificate-oidc-issuer … [--trusted-root R]` | yes: certificate identity and issuer (cosign 3.x flags; `tools.cosign_args` adds flags for older versions) |
| `jf` | `jf evd verify --subject-repo-path P (--public-keys K \| --use-artifactory-keys) --format json` | by key source: a key you supplied or an Artifactory key is identity; a Sigstore bundle key is re-checked with cosign when the plan names a certificate identity, otherwise `signature-only` |

**Offline unless `--online`.** Without `--online`, jankhunt42 opens no
connection itself and runs a verifier only when its inputs allow offline
verification:

* `gh` and `cosign` need a bundle (in the plan, or fetched) **and** a
  `trusted_root` (for example from `gh attestation trusted-root >
  trusted_root.jsonl`, refreshed whenever you import new signed material);
* `jf` always reads from the JFrog Platform, so it needs `--online`.

Anything that cannot run is `not-run` with the reason. jankhunt42 cannot
sandbox a third-party binary; it withholds the inputs that make it go online.
A pinned trusted root has no built-in expiry: offline verification cannot
learn about key revocation or rotation since the root was fetched, or about
newer attestations for the same artifact.

**Fetching (only with `--online`).**

* `fetch.github_attestations` downloads the bundles for each subject's
  SHA-256 from the GitHub attestations API into a JSONL file, which is then
  passed to `gh --bundle`. The API returns only attestations from that
  repository.
* `fetch.actions_artifacts` downloads the newest unexpired artifact with that
  name (optionally `run_id`), checks the zip against the digest GitHub
  recorded, and extracts SBOM/attestation files (bounded size and member
  count; names are flattened). These records are marked
  `origin: github-actions-artifact` and **unsigned**. A warning names the
  commit the artifact was built from when it differs from the repository's
  `HEAD`.
* A token is read only from `GH_TOKEN` or `GITHUB_TOKEN`, sent only to
  `api.github.com`, and never to a redirect target (artifact downloads redirect
  to blob storage). Only HTTPS is followed. Tokens never appear in output.
* Fetched files go to a temporary directory that is removed afterwards, or to
  `--fetch-dir DIR` if you want to keep them. Nothing is written elsewhere.

**Outcomes.** Each result is `tool-verified`, `signature-only`, `failed`,
`not-run`, or `error`, with the verifier, its version, the command (local paths
reduced to file names), the mode, and the reason. A `tool-verified` result
upgrades the matching attestation (same subject digest and predicate type) and
keeps the earlier state as `exporter_verification`. Because you asked for
verification, anything other than `tool-verified` fails the supply-chain gate
(exit 1), and in a passport it triggers `P-EVD-001` (insufficient evidence by
default). `--require-verified-attestation` is satisfied by `provider-verified`
or `tool-verified`, never by `signature-only` or a verifier that did not run.

## What this layer does not do

* jankhunt42 never verifies signatures, transparency-log inclusion, or
  certificate chains itself. In verification mode those results come from the
  named verifier, and the report says which one.
* Without `--verify … --online` it does not contact GitHub, Sigstore, JFrog, or
  a vulnerability database (`scan --cve` is the separate opt-in OSV lookup).
* It does not prove that an SBOM describes the artifact being reviewed, that
  the artifact was built from the reviewed commit, or that every dependency is
  covered. A verified provenance attestation proves who built which digest from
  which source revision; compare that revision with the one you reviewed.
* It does not enforce license policy or compare SBOM components with manifests
  yet. Those are separate policy layers.
