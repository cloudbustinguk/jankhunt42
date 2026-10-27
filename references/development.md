# Development, architecture, and compatibility

## Development

```sh
export PYTHONDONTWRITEBYTECODE=1              # selftest.sh rejects stray __pycache__ in the skill dir
python3 -m unittest discover -s tests         # fast suite
bash scripts/selftest.sh                       # end-to-end regression
python3 scripts/jankhunt42 selftest --full     # everything, with a gate
JH_UPDATE_SNAPSHOTS=1 python3 -m unittest discover -s tests -p test_terminal.py   # accept an intended view change
```

To add a rule, add it to `RULES` in `jh_rules.py` (or a `check=` in `jh_checks.py`), add a fixture case to `selftest.sh`, and run the self-scan. To add a map adapter, add it to `jh_map.py` with positive *and* negative fixtures in `tests/test_map.py`. Keep every claim's `verification` honest, and update `tests/fixtures/self-expected.json` by hand if this repository's own connectivity changes. Fixtures must be synthetic.

## Self-assurance

```sh
jankhunt42 selftest           # the unit suite
jankhunt42 selftest --full    # everything below, with a pass/fail/insufficient-evidence gate
```

`selftest --full` runs:

- the unittest suite: an independent reference oracle for reachability, metamorphic and monotonicity properties, adapter fixtures, policy precedence, `--base` isolation, seeded fuzzing, golden terminal snapshots, schema checks, and cross-version compatibility against the previous local release tag;
- the end-to-end shell regression suite;
- a self-map compared with a hand-maintained ground truth;
- a self-scan and self-passport, reported but never self-approving;
- twenty mutants that the tests must kill, each with an unmutated control;
- a privacy scan of shipped files and generated artifacts;
- a stdlib byte-compile of every script, plus ruff, pyflakes, bandit and shellcheck when they are already installed (never installed for you);
- the suite on locally cached Python 3.9 to 3.14 container images (every minor version), which are never pulled.

Python 3.9 is past its upstream end of life. It stays the minimum only because some systems still ship it as their `python3` (for example macOS Command Line Tools and RHEL 9); use a current Python where you can. TOML config needs 3.11+; JSON config works everywhere.

Missing optional tools are reported as `skip`, never as a pass. A perfect self-score is not evidence of correctness; the independent checks are.

## Architecture

```text
SKILL.md                 routing doctrine for agents (three questions, permission gates)
references/              method, playbooks, toolbox, scoring, review, supply-chain, deep-hunt,
                         connectivity (map), passport (passport, exposure, policy), citizen,
                         ai-governance, examples, development
templates/               report templates; review-receipt, map, and passport JSON Schemas
scripts/jankhunt42       CLI entry point
scripts/jh_core.py       types, discovery, sanitizer, safe_text      scripts/jh_rules.py, jh_checks.py  scanner rules
scripts/jh_score.py      Jank Score 2.0                              scripts/jh_review.py   diff review and receipts
scripts/jh_supply.py     SBOM/attestation/JFrog parsers              scripts/jh_hunt.py     deep hunt and merge
scripts/jh_graph.py      graph model, sanitizing, reachability, exposure, diff, redaction
scripts/jh_map.py        discovery adapters, coverage, map views    scripts/jh_yaml.py     bounded YAML subset reader
scripts/jh_policy.py     passport rules, profiles, precedence       scripts/jh_passport.py passport assembly
scripts/jh_agent.py      MCP and agent workspace config parsing    scripts/jh_frameworks.py NIST AI RMF / AIGP crosswalk
scripts/jh_views.py      map/passport terminal views                scripts/jh_explorer.py offline HTML explorer
scripts/jh_selftest.py   self-assurance orchestrator                scripts/selftest.sh    shell regression suite
tests/                   unittest suite, oracle, fixtures (synthetic), golden snapshots
```

There is no circular dependency between scoring, the graph and the passport: they share only the canonical JSON shapes. `scan` never computes a passport.

## Compatibility and migration

- Every 1.x command, flag, exit code, JSON field and SARIF field is unchanged. The compatibility suite runs the 1.1.0 release and 2.0 side by side on the demo fixture and requires identical `scan`/`score`/`rules` JSON and SARIF (ignoring only version, timing, and absolute-root fields).
- 2.1.0 adds options only (`map --what-if/--drift/--mermaid/--csv`, `passport --acceptance/--compare/--against`), plus `passport.bindings`. It also narrows `JH104`, which no longer flags parameterized `%s`/`%(name)s` placeholders; this removes findings and never adds them.
- 2.2.0 adds options only (`supply-chain --verify/--online/--fetch-dir`, `passport --verify/--online`) and additive fields (`key_source`, `origin`, `verification`). JFrog records whose key came from the Sigstore bundle now carry a warning; their state is unchanged.
- 2.3.0 adds 17 rules (`JH131`-`JH134`, `JH427`-`JH431`, `JH701`-`JH708`, with the new `agent` category), `passport --profile`, `passport.profile` and `passport.custodians`, five passport rules, an additive `governance` section, and the map's `mcp` adapter. Every older rule's catalog entry and every existing JSON and SARIF field is unchanged. Under the standard profile, `P-SEC-001` and `P-AGT-001` add `review` reasons when their leads appear. The effective policy gained keys, so the policy hash changed: acceptance records bound to an earlier hash must be re-issued. Under the citizen profile, governance leads ignore repository scan config and inline pragmas, and only a custodian named in the operator policy lets `P-CUS-001` pass or signs an acceptance. `JH502` no longer fires on unittest-style assertions or on assertions made in helper methods, and `JH401` no longer treats a CI workflow named `secrets.yml` as a credential file.
- 2.4.0 adds `supply-chain --require-sbom-minimum`, policy `require.sbom_minimum`, the passport rule `P-AI-001`, and additive fields: SBOM `quality`, `hashes` and `cpe`; summary `sbom_minimum_elements`; passport `ai`, `alignment`, `provenance.sbom_minimum_elements` and `sbom_missing`. Under the standard profile, `P-AI-001` adds a `review` reason when sensitive data is reachable alongside an external AI service. The effective policy gained keys, so the policy hash changed again: re-issue acceptance records. SPDX 3.0.1 and tag-value SBOMs now yield versions, purls and suppliers that were missed before, and a CycloneDX `group` no longer counts as a supplier.
- 2.6.0 adds 4 rules (`JH432`, `JH709`-`JH711`), the passport rules `P-CHG-001` and `P-SUP-001`, `passport --branch-rules/--default-branch`, policy `require.change_control`, `require.registry_pinning` and `allowed_registries`, and additive fields: passport `change_control`, `package_sources` and `egress`; map `egress` and `assessment.credential_blast_radius` (2.5.0). Evidence coverage counts 10 areas instead of 9. Under the standard profile both new rules pass unless the policy asks for them; under the citizen profile `P-CHG-001` is `insufficient-evidence` until rulesets are supplied from outside the repository. The effective policy gained keys, so re-issue acceptance records.
- 2.6.1 changes no options or fields. A path argument that does not exist or cannot be read now exits 2 instead of scanning the working directory. It narrows `JH102`, `JH103`, `JH108`, `JH120`, `JH125`, `JH126` and `JH505`, downgrades `JH122` in test code, lets `JH101` find a secret after a placeholder on the same line, and moves `JH703` to the line of the allow entry. A baseline or SARIF history may show those findings as fixed or moved.
- 2.6.2 changes no options or fields. `JH201` and `JH109` findings are minor unless the call decides an outcome or credentials are allowed; `JH104` and `JH122` are minor in test code; several rules narrow (see CHANGELOG). Gates on `--fail-on major` see fewer failures; the rule catalog's severities are unchanged.
- 2.7.0 adds the map node attribute `port` (additive) and `passport --emit-sandbox-policy` (it prints a policy instead of a passport, and cannot be combined with `--json`, `--html`, `--md` or `--compare`). No fields change. `JH101`, `JH124`-`JH126`, `JH203`, `JH205` and `JH502` narrow (see CHANGELOG).
- 2.7.1 adds one field: scan `--json` lists files treated as minified bundles under `minified` (additive). JavaScript regex literals no longer end the code view early, so findings after one on the same line can appear; minified bundles need a build-output name or path; `JH107`, `JH109`, `JH124` to `JH126`, `JH131`, `JH132`, `JH203`, `JH210`, `JH502`, `JH601`, `JH701` and `JH702` narrow.
- 2.7.2 changes no options or fields. `JH101` reads quoted-key and prefixed-name credentials; test-support folders count as tests; `JH104`, `JH111`, `JH504` and `JH505` narrow.
- 2.7.3 changes no options or fields. `JH401`, `JH501`, `JH505`, `JH601`, `JH701` and `JH702` narrow; `JH212` and `JH213` now report `timeout=None`; `JH210` follows a waited `Popen` handle; `JH404` ignores earlier build stages; root `test-*.js` scripts are no longer test paths (2.7.2 regression).
- 2.7.4 changes no options or fields. Git calls drop inherited variables that name a program (`GIT_EXTERNAL_DIFF`, `GIT_SSH_COMMAND`, `GIT_PAGER`) and override the repository's hooks, fsmonitor, filters, diff drivers and signature checking; `JH103` and `JH201` narrow.
- 2.7.5 changes no options or fields. `JH107`, `JH212`, `JH415` and `JH426` narrow; `JH424` reports an open peer dependency range as info instead of minor; the sandbox-policy output gate also checks the fallback switches and credential read-denies.
- 2.8.0 changes how map and passport `egress` is assessed; options are unchanged. New fields: `egress.contexts` (one assessment per declaration), `egress.unassessed`, boundary `profile`, `selected` and `enabled`, and `contexts` on each `outside` row (all additive). `egress.state` is now `unknown` when a declaration is disabled, unselected or not fully modeled, where 2.7 credited it; consumers must treat `unknown` with an empty `outside` as no evidence. Redacted copies keep the new counts. `JH103` now also runs on JavaScript and TypeScript (new findings), and is minor for a fixed command string; `JH101` narrows.
- 2.8.1 changes no options or fields. `JH102`, `JH104`, `JH105` and `JH210` narrow.
- 2.9.0 adds `passport --sandbox-network-ceiling PATH` (with `--emit-sandbox-policy openshell` or `claude-code`; its input schema is `jankhunt.network-ceiling.v1`). Default policy output is unchanged. Egress `outside` and `unassessed` rows may now carry `port`, and one host reached on two ports gives two rows. A Claude Code allowlist entry jankhunt42 cannot parse makes that tool's coverage `unknown`.
- 2.9.1 changes no options or fields. `JH702` is minor inside a descriptive JSON field.
- 2.9.2 changes no options, fields or findings: the code/comment/string tokenizer is faster.
- 2.9.3 changes no options or fields. `JH701` is minor for an override phrase handed to code; the skill description leads with citizen developers.
- 2.9.4 changes no options or fields. `JH101` narrows; `JH124`-`JH126` are minor for HTML from a CONSTANT_NAME.
- 3.0.0 adds the opt-in command `detonate` (schema `jankhunt.detonate.v1`) and `templates/detonate.Containerfile`. No existing command, option or field changes. Exit codes for `detonate`: 0 no ALERT, 1 at least one ALERT, 2 the sandbox could not run.
- 3.1.0 adds `passport --base REF` and the passport field `capability_delta` (schema `jankhunt.capability-delta.v1`; `not-requested` without `--base`), the policy rule `P-CAP-001`, and `references/capability-delta.md`. Without `--base`, passports are unchanged apart from the additive field.
- 3.1.1 changes no options or fields: a changed hook or MCP definition behind an unchanged identity is reported (`change: definition-changed`) and needs review.
- 3.1.2 changes no options or fields. `JH101`, `JH104`, `JH109`, `JH124`-`JH126`, `JH131`, `JH203`, `JH205` and `JH502` narrow.
- New top-level commands: `map`, `passport`, `selftest`. The new payloads carry their own schema versions (`jankhunt.map.v1`, `jankhunt.passport.v1`).
- The product name is written `jankhunt42` everywhere, including the `SKILL.md` `name` and the human-readable Markdown and HTML titles (`# jankhunt42 scan`). If you grepped human output for the old capitalization, update the pattern; machine formats were already lowercase.
- Repository strings in terminal and Markdown output now have control and bidi characters replaced with `U+FFFD`, so a hostile repository cannot drive your terminal.

## Publishing checklist

- [ ] `jankhunt42 selftest --full` gate is `pass` on a clean checkout.
- [ ] The version is synchronized in `SKILL.md`, `scripts/jh_core.py`, `README.md`, and `CHANGELOG.md`.
- [ ] No `__pycache__`, generated reports, secrets, private prompts, or agent working files are committed.
- [ ] README and SKILL commands are exercised by `tests/test_docs.py`.
- [ ] The tag matches the version, and the release archive is built from the clean tree by `provenance.yml`.
