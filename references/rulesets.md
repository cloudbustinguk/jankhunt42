# Site rulesets and ignoring rules in CI

Two ways for a team to make the scan its own, both given on the command
line, so they belong to whoever runs the pipeline:

```sh
jankhunt42 scan . --ignore-rule JH417 --fail-on major          # set a shipped rule aside for this run
jankhunt42 scan . --ruleset /policy/acme.json --fail-on major  # your own rules and rule settings
jankhunt42 passport . --profile citizen --ruleset /policy/acme.json --ignore-rule JH417
```

Both work with `scan`, `review` and `passport`, and both can be repeated.

## `--ignore-rule`

`--ignore-rule JH417` sets a rule aside for one run. Comma-separated ids
(`--ignore-rule JH417,JH418`) and repeats both work, in any case. The
rule's findings are not reported, scored or gated on. Every output still
says it happened:

- **scan:** `ignored_rules` in the JSON, and no results in SARIF;
- **passport:** `scope.ignored_rules`. The citizen profile's governance
  scans honour it too, because the flag is the operator's own call, not
  the repository's.

An id that no rule has is refused (exit 2), so a typo cannot pass for an
ignore that took effect.

Use it for a rule your team owns the answer to. JH417 (an action not
pinned to a commit SHA) is the usual one: whether a tag from a publisher
you trust is good enough is a policy choice, not a defect.

## `--ruleset FILE.json`

A ruleset is your site policy in one file: rules of your own, and shipped
rules set aside or re-rated.

```json
{
  "schema_version": "jankhunt.ruleset.v1",
  "name": "acme-site-policy",
  "ignore": ["JH417"],
  "severity": {"JH213": "minor"},
  "rules": [
    {
      "id": "ACME001",
      "title": "Internal hostname in code",
      "severity": "major",
      "category": "security",
      "message": "An internal hostname is written into the code.",
      "fix": "Read it from configuration.",
      "patterns": ["\\b[a-z0-9-]+\\.corp\\.acme\\.internal\\b"],
      "target": "raw",
      "files": ["*.cs", "*.json", "*.py"],
      "examples": {
        "match": ["host = \"db1.corp.acme.internal\""],
        "no_match": ["see acme.com"]
      }
    }
  ]
}
```

`templates/site-ruleset.example.json` is a starting point.

| Rule field | Required | Means |
|---|---|---|
| `id` | yes | Upper-case letters and digits, optionally `-` and a suffix (`ACME001`, `SITE-12`). Ids starting with `JH` are reserved for shipped rules. |
| `title`, `message` | yes | Shown in every report. |
| `severity` | yes | `blocker`, `critical`, `major`, `minor` or `info`. |
| `patterns` | yes | Up to 10 Python regular expressions; a line that matches any is reported. |
| `examples` | yes | `match`: lines the rule must report (at least one). `no_match`: lines it must not. |
| `category` | no | Defaults to `site`. |
| `fix` | no | What to do instead. |
| `files` | no | Globs on the path or file name; default all files. |
| `langs` | no | Languages, as jankhunt42 names them (`python`, `js`, `ts`, `csharp`, ...). |
| `target` | no | Which view of each line the patterns see: `code` (the default: comments and string contents blanked), `raw`, `nocomment` or `comments`. |
| `exclude` | no | A regular expression: a line that matches it is never reported. |
| `confidence` | no | `high`, `medium` (default) or `low`. |

Site rules run on the same engine as the shipped ones. They appear in
JSON, SARIF (with their own rule descriptors), Markdown and the passport;
they count in the Jank Score; they gate with `--fail-on`; and inline
`jankhunt42: ignore ACME001` pragmas and `--ignore-rule ACME001` work on
them.

### Checks

A ruleset is refused (exit 2, with the reason) when:

- a rule misses one of its own `match` examples or reports a `no_match`
  one, checked against the patterns and `exclude` directly, so a site
  policy stays honest as people edit it;
- an id is reserved, repeated, or already a shipped rule;
- a pattern does not compile, or a field has the wrong type or an unknown
  name;
- `ignore` or `severity` names a rule that does not exist;
- the file is over 1 MB, is not JSON, or repeats a key.

### Trust

Trust follows where the file lives, as it does for every operator input:

- **Outside the scanned repository:** the operator's policy. It applies
  everywhere, including the citizen profile's governance scans.
- **Inside it:** the repository's own say, like `.jankhunt42.toml`. Its
  rules still run, but its `ignore` and `severity` do not reach the
  governance scans, so a repository cannot quietly switch off what the
  citizen profile must see.

Every report records each ruleset's name, sha256, and whether it was
trusted (`rulesets` in scan JSON, `scope.rulesets` in the passport), so a
reader can tell which policy was applied.
