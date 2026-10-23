# Supply-chain evidence

JankHunt42 treats SBOMs, provenance attestations, and AppTrust evidence as
review context. It parses evidence that is already on disk, correlates subjects
and provenance, and reports gaps. It is offline and read-only by default.

The core rule is simple: **never fabricate cryptographic verification**.
JankHunt42 has no Sigstore trust root, transparency-log client, or JFrog API
client in its stdlib-only runtime. Therefore:

| Label | Meaning |
|---|---|
| `provider-verified` | The exporter recorded a successful verification result, for example JFrog's `verificationResult`. This is the exporter's claim. |
| `unverified` | A signature or DSSE envelope is present, but JankHunt42 did not verify it. |
| `unsigned` | No signature material was found in the evidence. |
| `failed` | The exporter recorded a failed verification result. |

When evidence is `unverified` or `unsigned`, the report includes a verification
hint such as `gh attestation verify`, `cosign verify-attestation`, or
`jf evd verify`. Run that tool when an independent verification result matters.

## Supported inputs

| Input | Forms |
|---|---|
| SPDX 2.x | JSON (`spdxVersion`, `packages`) and tag-value (`SPDXVersion:`, `PackageName:`) |
| SPDX 3 | JSON-LD `@graph` with `software_Package` elements |
| CycloneDX | JSON (`bomFormat: CycloneDX`) and XML `<bom>` |
| GitHub artifact attestations | Raw Sigstore bundle / DSSE JSON, JSONL from `gh attestation download` |
| Sigstore / in-toto | DSSE envelope, direct in-toto statement, SLSA provenance v0.2/v1 |
| JFrog AppTrust / `jf evd verify` | JSON with `evidenceVerifications`, `sigstoreBundle`, `verificationResult`, optional `predicate` and `downloadPath` |

Discovery is heuristic and filename/content based. Explicit paths are stronger:

```bash
jankhunt supply-chain . --sbom build/app.spdx.json
jankhunt supply-chain . --attestation sha256:abc123.jsonl
jankhunt supply-chain . --jfrog-evidence apptrust-evidence.json
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
JSONL file named after the artifact digest, with one bundle per line. JankHunt42
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

JankHunt42 parses the nested bundle, records the JFrog verification result, and
attempts to load a relative `downloadPath` from the evidence file's directory
or the current directory. It does not follow remote URLs.

A JFrog `verificationResult` containing successful statuses is reported as
`provider-verified`. A failed status is reported as `failed`. A bundle with
signature material but no recorded result is `unverified`.

## Requirements and gates

```bash
# Fail if no SBOM is present.
jankhunt supply-chain . --require-sbom

# Fail if no attestation is present.
jankhunt supply-chain . --require-attestation

# Fail unless the exporter recorded a successful verification.
jankhunt supply-chain . --require-verified-attestation

# The same requirements participate in a review gate.
jankhunt review . --base origin/main --require-sbom --require-attestation --fail-on major
```

Missing evidence is otherwise a warning, not a source-code finding. This is
intentional: a missing SBOM is a process gap, not a line-level jank score input.

## What this layer does not do

* It does not verify signatures, transparency-log inclusion, or certificate
  chains.
* It does not contact GitHub, Sigstore, JFrog, or a vulnerability database.
* It does not prove that an SBOM describes the artifact being reviewed, that
  the artifact was built from the reviewed commit, or that every dependency is
  covered.
* It does not enforce license policy or compare SBOM components with manifests
  yet. Those are separate policy layers.

For a release gate, keep the parsed evidence as context and run the appropriate
native verifier (`gh attestation verify`, `cosign verify-attestation`, or
`jf evd verify`) in the trusted CI environment.
