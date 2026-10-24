#!/usr/bin/env bash
# Offline regression test for jankhunt42. Builds a fixture, runs every command,
# and asserts representative rules, redaction, scores, triage, and consensus.
set -euo pipefail
export PYTHONDONTWRITEBYTECODE=1

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SKILL="$(cd "$HERE/.." && pwd)"
JH="$SKILL/scripts/jankhunt42"
PY="${PYTHON:-python3}"
TMP="$(mktemp -d "${TMPDIR:-/tmp}/jankhunt42-selftest.XXXXXX")"
trap 'rm -rf "$TMP"' EXIT

# Build fake credentials from pieces so this test file itself does not look like
# a leaked secret to the scanner. The generated fixture still contains them.
FAKE_KEY="sk_""live_Tq9Lm2Xw7Rb4Nc8Vz3Kd"
FAKE_TOKEN="ghp_""Wq7Lz2Xm9Rt4Nb8Vc3Kd6Hj1Fs5Gp0Ya2Ue4Ti"
OS_SYSTEM="os.""system"
XSS_PAYLOAD="<scr""ipt>alert(1)</scr""ipt>"
export FAKE_KEY FAKE_TOKEN OS_SYSTEM XSS_PAYLOAD

fail() { printf 'selftest: FAIL: %s\n' "$*" >&2; exit 1; }
note() { printf 'selftest: %s\n' "$*"; }

[ -x "$JH" ] || fail "launcher is not executable: $JH"
"$PY" "$JH" --version >/dev/null || fail "--version failed"

# Version and release metadata must move together.
VERSION="$("$PY" "$JH" --version | awk '{print $NF}')"
[ -n "$VERSION" ] || fail "could not read CLI version"
grep -q "version: \"$VERSION\"" "$SKILL/SKILL.md" || fail "SKILL.md version is not $VERSION"
grep -q "^## \[$VERSION\]" "$SKILL/CHANGELOG.md" || fail "CHANGELOG.md has no $VERSION section"
grep -q "Version:.*$VERSION" "$SKILL/README.md" || fail "README.md version is not $VERSION"
"$PY" -m json.tool "$SKILL/templates/panel-finding.json" >/dev/null \
  || fail "panel-finding.json is not valid JSON"
note "version: $VERSION"

# ---------------------------------------------------------------------------
# Fixture
# ---------------------------------------------------------------------------
FIX="$TMP/fixture"
mkdir -p "$FIX/.github/workflows" "$FIX/tests" "$FIX/testing"

cat > "$FIX/app.py" <<'PY'
import os
import pickle
import sqlite3

API_KEY = "__FAKE_KEY__"
DB_PASSWORD = "correct-horse-battery-staple"


def run(cmd):
    __OS_SYSTEM__(cmd)


def load(data):
    return pickle.loads(data)


def query(db, name):
    return db.execute("SELECT * FROM users WHERE name = '" + name + "'")


def handler():
    try:
        risky()
    except Exception:
        pass


def mutable_default(items=[]):
    items.append("x")
    return items


def long_function():
    total = 0
PY
for i in $(seq 1 90); do printf '    total += %d\n' "$i" >> "$FIX/app.py"; done
cat >> "$FIX/app.py" <<'PY'
    return total


def deep(value):
    if value:
        if value > 1:
            if value > 2:
                if value > 3:
                    if value > 4:
                        if value > 5:
                            if value > 6:
                                return value
    return 0
PY
sed -i "s|__FAKE_KEY__|$FAKE_KEY|; s|__OS_SYSTEM__|$OS_SYSTEM|" "$FIX/app.py"

cat > "$FIX/space app.py" <<'PY'
import os


def run(cmd):
    __OS_SYSTEM__(cmd)
PY
sed -i "s|__OS_SYSTEM__|$OS_SYSTEM|" "$FIX/space app.py"

# A finding whose evidence contains markup: the HTML report must escape it.
cat > "$FIX/xss.py" <<'PY'
import os


def run():
    __OS_SYSTEM__("__XSS_PAYLOAD__")
PY
sed -i "s|__OS_SYSTEM__|$OS_SYSTEM|; s|__XSS_PAYLOAD__|$XSS_PAYLOAD|" "$FIX/xss.py"

# A symlink that escapes the scan root must not be followed.
printf 'API_KEY = "%s"\n' "$FAKE_KEY" > "$TMP/outside-secret.py"
ln -s "$TMP/outside-secret.py" "$FIX/external.py" 2>/dev/null || true

cat > "$FIX/tests/test_app.py" <<'PY'
import pytest


@pytest.mark.skip(reason="later")
def test_skipped():
    assert True


def test_without_assertion():
    do_something()


def test_tautology():
    assert True


def test_expected_warning():
    with pytest.warns(UserWarning):
        pass


def test_expected_no_warning():
    import warnings
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        pass


def test_sleep():
    import time
    time.sleep(1)


def test_multiline_signature(
    value: int = 1,
) -> None:
    assert value == 1
PY

# Root-level and testing/ Python tests are still tests: no JH315 there.
cat > "$FIX/test_root_level.py" <<'PY'
def test_root_level():
    assert 1 + 1 == 2
PY

cat > "$FIX/testing/test_helpers.py" <<'PY'
def test_helper():
    assert True
PY

cat > "$FIX/testing/benchmark_speed.py" <<'PY'
def test_speed(benchmark):
    benchmark(lambda: None)
PY

# Assert in production code must still be reported.
cat > "$FIX/assert_prod.py" <<'PY'
def require(value):
    assert value is not None
    return value
PY

# A return in finally is unsafe; a loop nested inside finally is not.
cat > "$FIX/finally_flow.py" <<'PY'
def real_return():
    try:
        return 1
    finally:
        return 2


def nested_loop():
    try:
        raise RuntimeError("x")
    finally:
        for item in (1,):
            if item:
                continue
PY

cat > "$FIX/.github/workflows/ci.yml" <<'YAML'
name: ci
on: pull_request_target
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          ref: ${{ github.event.pull_request.head.sha }}
      - uses: some/action@main
      - run: echo "${{ github.event.pull_request.title }}"
YAML

cat > "$FIX/deploy.yaml" <<'YAML'
apiVersion: extensions/v1beta1
kind: Deployment
metadata:
  name: bad
spec:
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: app
          image: nginx:latest
          securityContext:
            privileged: true
            allowPrivilegeEscalation: true
            runAsUser: 0
            seccompProfile: Unconfined
          env:
            - name: DB_PASSWORD
              value: "hunter2"
---
apiVersion: v1
kind: Secret
metadata:
  name: bad
stringData:
  password: hunter2
YAML

cat > "$FIX/Dockerfile" <<'DOCKER'
FROM ubuntu:latest
ADD https://example.com/tool.tar.gz /tmp/
USER root
DOCKER

cat > "$FIX/.gitlab-ci.yml" <<'YAML'
include:
  - remote: https://example.com/ci.yml
image: python:latest
job:
  script: echo hi
  allow_failure: true
YAML

cat > "$FIX/package.json" <<'JSON'
{
  "name": "jankhunt42-fixture",
  "version": "1.0.0",
  "dependencies": {
    "lodash": "*"
  }
}
JSON

cat > "$FIX/.env" <<'ENV'
API_TOKEN=__FAKE_TOKEN__
ENV
sed -i "s|__FAKE_TOKEN__|$FAKE_TOKEN|" "$FIX/.env"

cat > "$FIX/README.md" <<'MD'
# Fixture

[missing link](does-not-exist.md)
MD

cat > "$FIX/app.log" <<'LOG'
2026-01-01T00:00:00Z ERROR request 11111111-1111-1111-1111-111111111111 failed from 10.0.0.1
2026-01-01T00:00:01Z ERROR request 22222222-2222-2222-2222-222222222222 failed from 10.0.0.2
2026-01-01T00:00:02Z WARN slow request 33333333-3333-3333-3333-333333333333 took 1200ms
LOG

# AI-agent workspace and citizen-app mistakes (2.3.0 rules).
mkdir -p "$FIX/.vscode" "$FIX/web"
printf '{\n  "chat.tools.autoApprove": true\n}\n' > "$FIX/.vscode/settings.json"
printf '{"mcpServers": {"fs": {"command": "npx", "args": ["-y", "some-mcp-server"]}}}\n' > "$FIX/.mcp.json"
printf 'NEXT_PUBLIC_%s=%s\n' "STRIPE_SECRET_KEY" "$FAKE_KEY" > "$FIX/web/.env.production"
printf 'service cloud.firestore {\n  match /{d=**} { allow read, write: if true; }\n}\n' > "$FIX/firestore.rules"

cat > "$FIX/suppressed.py" <<'PY'
# jankhunt42: ignore-file JH303
VERY_LONG_LINE = "x" * 400


def suppressed():
    try:
        risky()
    except Exception:  # jankhunt42: ignore JH201
        pass
PY

# ---------------------------------------------------------------------------
# Scan: rules, redaction, JSON, Markdown, SARIF
# ---------------------------------------------------------------------------
cd "$TMP"
"$PY" "$JH" scan "$FIX" --min-severity info --json --no-progress > "$TMP/scan.json" \
  || fail "scan --json failed"

"$PY" - "$TMP/scan.json" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1]))
ids = {f["rule"] for f in d["findings"]}
required = {
    "JH101", "JH103", "JH104", "JH106", "JH201", "JH206", "JH208",
    "JH301", "JH302", "JH401", "JH402", "JH403", "JH404",
    "JH406", "JH407", "JH408", "JH409", "JH410", "JH412", "JH413", "JH415",
    "JH416", "JH417", "JH418", "JH419", "JH420", "JH421", "JH422", "JH424",
    "JH501", "JH502", "JH503", "JH504", "JH601",
    "JH132", "JH134", "JH703", "JH705",
}
missing = sorted(required - ids)
assert not missing, "missing rules: %s" % missing
blob = json.dumps(d)
assert os.environ["FAKE_KEY"] not in blob, "secret leaked into JSON"
assert os.environ["FAKE_TOKEN"] not in blob, "token leaked into JSON"
assert "***REDACTED***" in blob or "***REDACTED-TOKEN***" in blob, "no redaction marker"
assert not any(f["path"].endswith("external.py") for f in d["findings"]), "followed a symlink outside the scan root"
assert any(f["rule"] == "JH315" and f["path"] == "assert_prod.py" for f in d["findings"]), "JH315 missed production assert"
test_paths = {"test_root_level.py", "testing/test_helpers.py", "tests/test_app.py"}
assert not any(f["rule"] == "JH315" and f["path"] in test_paths for f in d["findings"]), "JH315 fired in a test file"
assert any(f["rule"] == "JH502" and "test_without_assertion" in f.get("message", "") for f in d["findings"]), "JH502 missed an assertion-free test"
assert not any(f["rule"] == "JH502" and "test_multiline_signature" in f.get("message", "") for f in d["findings"]), "JH502 missed a multi-line test body"
assert not any(f["rule"] == "JH502" and "test_expected_warning" in f.get("message", "") for f in d["findings"]), "JH502 missed pytest.warns"
assert not any(f["rule"] == "JH502" and "test_expected_no_warning" in f.get("message", "") for f in d["findings"]), "JH502 missed warnings.simplefilter('error')"
assert not any(f["rule"] == "JH502" and "test_speed" in f.get("message", "") for f in d["findings"]), "JH502 flagged a benchmark"
gh417 = [f for f in d["findings"] if f["rule"] == "JH417"]
assert any(f["severity"] == "minor" and "actions/checkout" in f["message"] for f in gh417), gh417
assert any(f["severity"] == "major" and "some/action" in f["message"] for f in gh417), gh417
j = d["summary"]["jank"]
assert j["version"] == "2.0", j
assert j["grade"] in "ABCDE", j
assert 0 <= j["score"] <= 100, j
assert set(j["dimensions"]) == {"security", "reliability", "maintainability", "tests"}, j
assert j["policy"] in ("pass", "warn", "fail"), j
assert j["dimensions"]["security"]["score"] > 0, j
print("scan JSON: %d findings, jank %s/%s" % (len(d["findings"]), j["score"], j["grade"]))
PY

"$PY" "$JH" scan "$FIX/finally_flow.py" --rule JH208 --min-severity info \
  --json --no-progress > "$TMP/finally.json"
"$PY" - "$TMP/finally.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
findings = d["findings"]
assert len(findings) == 1, findings
assert "return 2" in findings[0]["evidence"], findings[0]
print("finally check: nested loop ignored")
PY

"$PY" "$JH" scan "$FIX" --md --no-progress > "$TMP/scan.md"
grep -q "jankhunt42 scan" "$TMP/scan.md" || fail "scan --md missing title"
grep -q "Score by dimension" "$TMP/scan.md" || fail "scan --md missing scorecard"
grep -q "JH101" "$TMP/scan.md" || fail "scan --md missing secret finding"

"$PY" "$JH" scan "$FIX" --sarif --no-progress > "$TMP/scan.sarif"
"$PY" - "$TMP/scan.sarif" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["version"] == "2.1.0", d
assert d["runs"][0]["tool"]["driver"]["name"] == "jankhunt42"
assert d["runs"][0]["results"], "no SARIF results"
for r in d["runs"][0]["results"]:
    uri = r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert " " not in uri, "SARIF URI contains a space: %r" % uri
uris = [r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
        for r in d["runs"][0]["results"]]
assert any("%20" in u for u in uris), "SARIF URI was not percent-encoded"
print("SARIF: %d results" % len(d["runs"][0]["results"]))
PY

# Self-contained HTML: parseable, escaped, and no secret leakage.
"$PY" "$JH" scan "$FIX" --html --no-progress > "$TMP/scan.html" \
  || fail "scan --html failed"
"$PY" - "$TMP/scan.html" <<'PY'
from html.parser import HTMLParser
from pathlib import Path
import os, sys

text = Path(sys.argv[1]).read_text()
assert text.startswith("<!DOCTYPE html>"), text[:40]
assert "jankhunt42" in text, "missing product name"
assert "Hardcoded secret" in text, "missing expected finding"
assert 'data-filter="critical"' in text, "missing severity filter"
assert os.environ["FAKE_KEY"] not in text, "secret leaked into HTML"
assert os.environ["FAKE_TOKEN"] not in text, "token leaked into HTML"
assert "<script>alert(1)</script>" not in text, "HTML injection reached the document"
assert "&lt;script&gt;alert(1)&lt;/script&gt;" in text, "markup was not escaped"

class Parser(HTMLParser):
    void = {"area", "base", "br", "col", "embed", "hr", "img", "input",
            "link", "meta", "param", "source", "track", "wbr"}

    def __init__(self):
        super().__init__()
        self.stack = []
        self.errors = []

    def handle_starttag(self, tag, attrs):
        if tag not in self.void:
            self.stack.append(tag)

    def handle_endtag(self, tag):
        if tag not in self.stack:
            self.errors.append("stray </%s>" % tag)
            return
        while self.stack and self.stack[-1] != tag:
            self.errors.append("unclosed <%s>" % self.stack.pop())
        if self.stack:
            self.stack.pop()

parser = Parser()
parser.feed(text)
assert not parser.stack, "unclosed tags: %s" % parser.stack[:10]
assert not parser.errors, "tag errors: %s" % parser.errors[:10]
print("HTML: %d bytes, self-contained and escaped" % len(text))
PY

CLEAN="$TMP/clean"
mkdir -p "$CLEAN"
printf 'def clean():\n    return 1\n' > "$CLEAN/clean.py"
"$PY" "$JH" scan "$CLEAN" --html --no-progress > "$TMP/clean.html" \
  || fail "clean scan --html failed"
grep -q "No findings from the built-in rules" "$TMP/clean.html" \
  || fail "clean HTML missing empty state"
if grep -q 'id="empty"' "$TMP/clean.html"; then
  fail "clean HTML should not render the filter empty state"
fi

for other in --json --sarif --md; do
  if "$PY" "$JH" scan "$FIX" --html "$other" --no-progress >/dev/null 2>&1; then
    fail "scan --html $other should be rejected"
  fi
done

# Suppression must remove JH201 and JH303 for that file only.
"$PY" "$JH" scan "$FIX/suppressed.py" --min-severity info --json --no-progress > "$TMP/suppressed.json"
"$PY" - "$TMP/suppressed.json" <<'PY'
import json, sys
ids = {f["rule"] for f in json.load(open(sys.argv[1]))["findings"]}
assert "JH201" not in ids, ids
assert "JH303" not in ids, ids
print("suppressions: ok")
PY

# The pre-rename `jankhunt:` pragma prefix must still be honored so that
# existing suppressions in users' code keep working after the CLI rename.
LEGACY="$TMP/legacy-pragma"
mkdir -p "$LEGACY"
cat > "$LEGACY/legacy.py" <<'PY'
# jankhunt: ignore-file JH303
VERY_LONG_LINE = "x" * 400


def legacy():
    try:
        risky()
    except Exception:  # jankhunt: ignore JH201
        pass
PY
"$PY" "$JH" scan "$LEGACY" --min-severity info --json --no-progress > "$TMP/legacy.json"
"$PY" - "$TMP/legacy.json" <<'PY'
import json, sys
ids = {f["rule"] for f in json.load(open(sys.argv[1]))["findings"]}
assert "JH201" not in ids and "JH303" not in ids, ids
print("legacy pragma: ok")
PY

# Severity filter.
"$PY" "$JH" scan "$FIX" --min-severity major --json --no-progress > "$TMP/major.json"
"$PY" - "$TMP/major.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
bad = [f["rule"] for f in d["findings"] if f["severity"] in ("minor", "info")]
assert not bad, bad
assert d["findings"], "severity filter returned nothing"
print("severity filter: %d major+ findings" % len(d["findings"]))
PY

# Gate behavior.
if "$PY" "$JH" scan "$FIX" --fail-on critical --no-progress >/dev/null 2>&1; then
  fail "--fail-on critical should exit 1"
fi
if ! "$PY" "$JH" scan "$FIX" --fail-on blocker --no-progress >/dev/null 2>&1; then
  fail "--fail-on blocker should exit 0 for this fixture"
fi

# Parent-directory lockfile must satisfy a nested package.json.
LOCKREPO="$TMP/lockrepo"
mkdir -p "$LOCKREPO/pkg"
: > "$LOCKREPO/package-lock.json"
printf '{"name":"nested","version":"1.0.0","dependencies":{"left-pad":"1.3.0"}}\n' > "$LOCKREPO/pkg/package.json"
"$PY" "$JH" scan "$LOCKREPO/pkg" --json --no-progress > "$TMP/lock.json"
"$PY" - "$TMP/lock.json" <<'PY'
import json, sys
ids = {f["rule"] for f in json.load(open(sys.argv[1]))["findings"]}
assert "JH423" not in ids, ids
print("parent lockfile: ok")
PY

# ---------------------------------------------------------------------------
# Score + new-code view
# ---------------------------------------------------------------------------
"$PY" "$JH" score "$FIX" --json --no-progress > "$TMP/score.json"
"$PY" - "$TMP/score.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
j = d["jank"]
assert d["command"] == "score", d
assert j["version"] == "2.0", j
assert j["score"] > 0 and j["grade"] in "ABCDE", j
assert j["worst_dimension"] in ("security", "reliability", "maintainability", "tests"), j
assert j["policy"] in ("pass", "warn", "fail"), j
assert "formula" in j and "severity" in j["formula"], j
print("score: %s/%s policy=%s worst=%s" % (j["score"], j["grade"], j["policy"], j["worst_dimension"]))
PY

"$PY" "$JH" score "$FIX" --md --no-progress | grep -q "Score 2.0" \
  || fail "score --md missing methodology"

# Build a tiny git repo: clean commit, then a bad line on top.
REPO="$TMP/repo"
mkdir -p "$REPO"
cd "$REPO"
git init -q
git config user.email "selftest@example.invalid"
git config user.name "selftest"
printf 'def ok():\n    return 1\n' > app.py
git add app.py
git commit -qm "clean baseline"
printf 'def bad():\n    eval(input())\n' >> app.py
cd "$TMP"
"$PY" "$JH" score "$REPO" --since HEAD --json --no-progress > "$TMP/newcode.json"
"$PY" - "$TMP/newcode.json" <<'PY'
import json, sys
j = json.load(open(sys.argv[1]))["jank"]
nc = j["new_code"]
assert nc, j
assert nc["changed_lines"] >= 2, nc
assert nc["findings"] >= 1, nc
assert nc["score"] > 0, nc
print("new code: %d findings, %d lines, %s/%s" % (nc["findings"], nc["changed_lines"], nc["score"], nc["grade"]))
PY

# ---------------------------------------------------------------------------
# Diff-aware review, receipts, baseline, coverage, supply chain
# ---------------------------------------------------------------------------
REVIEW="$TMP/review-repo"
mkdir -p "$REVIEW/evidence"
cd "$REVIEW"
git init -q
git config user.email "selftest@example.invalid"
git config user.name "selftest"
printf 'def ok():\n    return 1\n' > app.py
git add app.py
git commit -qm "clean baseline"
printf 'def bad(value):\n    return eval(value)\n' > app.py
"$PY" - "$REVIEW/evidence" <<'PY'
import base64, json, os, sys
out = sys.argv[1]
spdx = {
    "spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "review-fixture",
    "documentNamespace": "https://example.invalid/spdx/review",
    "creationInfo": {"created": "2026-01-01T00:00:00Z"},
    "packages": [
        {"name": "requests", "versionInfo": "2.31.0", "SPDXID": "SPDXRef-Package-1",
         "licenseConcluded": "Apache-2.0"},
        {"name": "urllib3", "versionInfo": "2.0.0", "SPDXID": "SPDXRef-Package-2",
         "licenseConcluded": "MIT"},
    ],
}
open(os.path.join(out, "app.spdx.json"), "w").write(json.dumps(spdx, indent=2))
open(os.path.join(out, "deps.spdx"), "w").write(
    "SPDXVersion: SPDX-2.2\nDocumentName: review-tag\n"
    "PackageName: flask\nPackageVersion: 3.0.0\nPackageLicenseConcluded: BSD-3-Clause\n"
    "PackageName: click\nPackageVersion: 8.1.7\nPackageLicenseConcluded: BSD-3-Clause\n"
)
cdx = {
    "bomFormat": "CycloneDX", "specVersion": "1.5", "serialNumber": "urn:uuid:review",
    "metadata": {"timestamp": "2026-01-03T00:00:00Z", "component": {"name": "review", "version": "1.0.0"}},
    "components": [
        {"name": "requests", "version": "2.31.0", "licenses": [{"license": {"id": "Apache-2.0"}}]},
        {"name": "certifi", "version": "2024.2.2"},
    ],
}
open(os.path.join(out, "bom.cdx.json"), "w").write(json.dumps(cdx, indent=2))
statement = {
    "_type": "https://in-toto.io/Statement/v1",
    "subject": [{"name": "app.tar.gz", "digest": {"sha256": "abc123"}}],
    "predicateType": "https://slsa.dev/provenance/v1",
    "predicate": {
        "buildDefinition": {
            "buildType": "https://github.com/actions/runner",
            "externalParameters": {"workflow": {
                "repository": "https://github.com/example/review",
                "path": ".github/workflows/build.yml", "ref": "refs/heads/main"}},
            "resolvedDependencies": [{"digest": {"gitCommit": "deadbeef"}}],
        },
        "runDetails": {"builder": {"id": "https://github.com/actions/runner/github-hosted"},
                       "metadata": {"finishedOn": "2026-01-04T00:00:00Z"}},
    },
}
payload = base64.b64encode(json.dumps(statement).encode()).decode()
bundle = {
    "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
    "verificationMaterial": {"tlogEntries": [{"logIndex": "1"}]},
    "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": payload,
                     "signatures": [{"keyid": "", "sig": "dGVzdA=="}]},
}
open(os.path.join(out, "attestation.jsonl"), "w").write(json.dumps({"bundle": bundle}) + "\n")
direct_statement = json.loads(json.dumps(statement))
direct_statement["subject"][0]["digest"]["sha256"] = "aaa111"
direct_statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = "cafebabe"
open(os.path.join(out, "direct.intoto.json"), "w").write(json.dumps(direct_statement, indent=2))
jfrog_statement = json.loads(json.dumps(statement))
jfrog_statement["subject"][0]["digest"]["sha256"] = "def456"
jfrog_statement["predicate"]["buildDefinition"]["resolvedDependencies"][0]["digest"]["gitCommit"] = "feedface"
jfrog_payload = base64.b64encode(json.dumps(jfrog_statement).encode()).decode()
jfrog_bundle = {
    "mediaType": "application/vnd.dev.sigstore.bundle+json;version=0.2",
    "verificationMaterial": {"tlogEntries": [{"logIndex": "2"}]},
    "dsseEnvelope": {"payloadType": "application/vnd.in-toto+json", "payload": jfrog_payload,
                     "signatures": [{"keyid": "", "sig": "dGVzdA=="}]},
}
jfrog = {
    "schemaVersion": "1.0",
    "subject": {"name": "app.tar.gz", "sha256": "def456"},
    "application": {"name": "review-app"}, "applicationVersion": "1.2.3",
    "releaseBundle": {"name": "review-rb", "version": "9"},
    "evidenceVerifications": [{
        "mediaType": "application/vnd.dev.sigstore.bundle+json",
        "predicateType": "https://slsa.dev/provenance/v1",
        "createdBy": "jfrog", "createdAt": "2026-01-05T00:00:00Z",
        "verificationResult": {"sigstoreBundleVerificationStatus": "success",
                               "signaturesVerificationStatus": "success"},
        "sigstoreBundle": jfrog_bundle,
    }],
}
open(os.path.join(out, "jfrog-evidence.json"), "w").write(json.dumps(jfrog, indent=2))
open(os.path.join(out, "broken.json"), "w").write('{"dsseEnvelope": {"payload": "not-base64"}}')
PY
cd "$TMP"

"$PY" "$JH" review "$REVIEW" --json > "$TMP/review.json"
"$PY" - "$TMP/review.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["command"] == "review", d
r = d["review"]
assert r["mode"] == "working", r
assert d["summary"]["findings"] >= 1, d["summary"]
assert d["summary"]["changed_lines"] >= 2, d["summary"]
f = next(x for x in d["findings"] if x["rule"] == "JH102")
assert f["scope"] == "new" and f["verification"] == "supported", f
assert f["id"].startswith("JH-") and len(f["receipt_hash"]) == 64, f
assert f["repro"].startswith("jankhunt42 scan"), f
sc = r["supply_chain"]
assert sc["summary"]["sboms"] == 3, sc["summary"]
assert sc["summary"]["attestations"] >= 2, sc["summary"]
assert sc["summary"]["verified_attestations"] >= 1, sc["summary"]
assert any("broken.json" in w for w in sc["warnings"]), sc["warnings"]
print("review: %d findings, %d changed lines, jank %s/%s" %
      (d["summary"]["findings"], d["summary"]["changed_lines"],
       r["score"]["score"], r["score"]["grade"]))
PY

"$PY" "$JH" review "$REVIEW" --md > "$TMP/review.md"
grep -q "New-code Jank" "$TMP/review.md" || fail "review --md missing score"
grep -q "Counterevidence" "$TMP/review.md" || fail "review --md missing receipt evidence"
grep -q "Supply chain evidence" "$TMP/review.md" || fail "review --md missing supply chain"
"$PY" "$JH" review "$REVIEW" --brief | grep -q "Review brief" || fail "review --brief missing contract"
"$PY" "$JH" review "$REVIEW" --sarif > "$TMP/review.sarif"
"$PY" - "$TMP/review.sarif" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["version"] == "2.1.0" and d["runs"], d
res = d["runs"][0]["results"]
assert res and all("receipt_hash" in x["properties"] for x in res), res[:1]
print("review SARIF: %d results" % len(res))
PY
"$PY" "$JH" review "$REVIEW" --no-supply-chain --json > "$TMP/review-nosupply.json"
"$PY" - "$TMP/review-nosupply.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["review"]["supply_chain"] is None, d["review"]["supply_chain"]
PY

"$PY" "$JH" review "$REVIEW" --json --save-baseline "$TMP/review-baseline.json" >/dev/null
cat >> "$REVIEW/app.py" <<'PY'

def sql(cursor, name):
    return cursor.execute("SELECT * FROM users WHERE name = '%s'" % name)
PY
"$PY" "$JH" review "$REVIEW" --json --baseline "$TMP/review-baseline.json" \
  > "$TMP/review-delta.json"
"$PY" - "$TMP/review-delta.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
b = d["review"]["baseline"]
assert b is not None, d["review"]
assert b["new"] >= 1 and b["persisting"] >= 1, b
assert b["current_score"] >= b["baseline_score"], b
assert any(x["scope"] == "new" and x["rule"] == "JH104" for x in d["findings"]), d["findings"]
assert any(x["scope"] == "persisting" for x in d["findings"]), d["findings"]
print("baseline: new=%d persisting=%d resolved=%d delta=%s" %
      (b["new"], b["persisting"], b["resolved"], b["delta"]))
PY
if "$PY" "$JH" review "$REVIEW" --fail-on major --baseline "$TMP/review-baseline.json" >/dev/null; then
  fail "review --fail-on did not fail for a new major finding"
fi

git -C "$REVIEW" add app.py evidence
git -C "$REVIEW" commit -qm "review fixture"
"$PY" "$JH" review "$REVIEW" --commit HEAD --json > "$TMP/review-commit.json"
"$PY" "$JH" review "$REVIEW" --base HEAD~1 --json > "$TMP/review-base.json"
"$PY" - "$TMP/review-commit.json" "$TMP/review-base.json" <<'PY'
import json, sys
for path in sys.argv[1:]:
    d = json.load(open(path))
    assert d["review"]["mode"] in ("commit", "base"), d["review"]["mode"]
    assert any(x["rule"] in ("JH102", "JH104") for x in d["findings"]), d["findings"]
    assert d["review"]["revision"] in ("HEAD", d["review"]["commit"]), d["review"]
print("review refs: commit + base ok")
PY
printf '\n# staged only\n' >> "$REVIEW/app.py"
git -C "$REVIEW" add app.py
"$PY" "$JH" review "$REVIEW" --staged --json > "$TMP/review-staged.json"
"$PY" - "$TMP/review-staged.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["review"]["mode"] == "staged", d["review"]
assert d["review"]["revision"] == "INDEX", d["review"]
assert d["review"]["scope"]["files_reviewed"] == 1, d["review"]["scope"]
assert not d["findings"], d["findings"]
PY

SC="$TMP/supply-chain"
mkdir -p "$SC"
"$PY" "$JH" supply-chain "$REVIEW" --json > "$TMP/sc.json"
"$PY" - "$TMP/sc.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["command"] == "supply-chain", d
s = d["summary"]
assert s["sboms"] == 3 and s["attestations"] >= 2 and s["jfrog_bundles"] == 1, s
assert s["packages"] >= 6 and s["verified_attestations"] == 1, s
assert s["unverified_attestations"] >= 1 and s["unsigned_attestations"] >= 1, s
assert any("broken.json" in w for w in d["warnings"]), d["warnings"]
kinds = {x["predicate_kind"] for x in d["attestations"]}
assert "slsa-provenance-v1" in kinds, kinds
print("supply chain: %s" % s)
PY
cp "$REVIEW/evidence/deps.spdx" "$TMP/forced.dat"
cp "$REVIEW/evidence/direct.intoto.json" "$TMP/forced.attest"
cp "$REVIEW/evidence/jfrog-evidence.json" "$TMP/forced.jfrog"
"$PY" "$JH" supply-chain --no-discover --sbom "$TMP/forced.dat" \
  --attestation "$TMP/forced.attest" --jfrog-evidence "$TMP/forced.jfrog" \
  --json > "$TMP/sc-forced.json"
"$PY" - "$TMP/sc-forced.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert len(d["sboms"]) == 1 and d["sboms"][0]["format"] == "spdx-tag-value", d["sboms"]
assert len(d["attestations"]) == 2, d["attestations"]
assert len(d["jfrog"]) == 1, d["jfrog"]
assert any(a["verification"] == "provider-verified" for a in d["attestations"]), d["attestations"]
assert any(a["verification"] == "unsigned" for a in d["attestations"]), d["attestations"]
PY
"$PY" "$JH" supply-chain "$SC" --no-discover --require-sbom --json \
  > "$TMP/sc-require.json" 2>/dev/null && fail "supply-chain --require-sbom did not fail"
# The review SBOM names no suppliers, identifiers, dependencies or author.
"$PY" "$JH" supply-chain --no-discover --sbom "$REVIEW/evidence/app.spdx.json" --require-sbom-minimum \
  --json > "$TMP/sc-minimum.json" && fail "supply-chain --require-sbom-minimum passed an incomplete SBOM"
"$PY" - "$TMP/sc-minimum.json" "$TMP/complete.cdx.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["summary"]["sbom_minimum_elements"] == "partial", d["summary"]
assert "dependency relationships" in d["sboms"][0]["quality"]["missing"], d["sboms"][0]["quality"]
assert any("NTIA minimum elements" in r for r in d["gate"]["reasons"]), d["gate"]
json.dump({"bomFormat": "CycloneDX", "specVersion": "1.6",
           "metadata": {"timestamp": "2026-01-01T00:00:00Z", "authors": [{"name": "Example Org"}],
                        "component": {"bom-ref": "app", "name": "app", "version": "1.0.0",
                                      "supplier": {"name": "Example Org"}, "purl": "pkg:pypi/app@1.0.0"}},
           "components": [{"bom-ref": "lib", "name": "lib", "version": "2.0.0",
                           "supplier": {"name": "Example Org"}, "purl": "pkg:pypi/lib@2.0.0"}],
           "dependencies": [{"ref": "app", "dependsOn": ["lib"]}]}, open(sys.argv[2], "w"))
PY
"$PY" "$JH" supply-chain --no-discover --sbom "$TMP/complete.cdx.json" --require-sbom-minimum --json \
  >/dev/null || fail "supply-chain --require-sbom-minimum rejected a complete SBOM"
"$PY" "$JH" supply-chain --no-discover --sbom "$TMP/forced.dat" \
  --jfrog-evidence "$TMP/forced.jfrog" --require-verified-attestation --json \
  >/dev/null || fail "supply-chain --require-verified-attestation rejected JFrog proof"

# ---------------------------------------------------------------------------
# Triage
# ---------------------------------------------------------------------------
"$PY" "$JH" triage "$FIX/app.log" --json > "$TMP/triage.json"
"$PY" - "$TMP/triage.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["command"] == "triage", d
assert d["summary"]["events"] >= 3, d
assert d["summary"]["counts"].get("error", 0) >= 2, d
# Two UUID/IP variants must normalize into one cluster.
errors = [c for c in d["clusters"] if c["severity"] == "error"]
assert errors, d
assert errors[0]["count"] >= 2, errors[0]
print("triage: %d clusters, top error count=%d" % (len(d["clusters"]), errors[0]["count"]))
PY

# ---------------------------------------------------------------------------
# Doctor
# ---------------------------------------------------------------------------
"$PY" "$JH" doctor "$FIX" --json > "$TMP/doctor.json"
"$PY" - "$TMP/doctor.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d, d
print("doctor: ok")
PY

# ---------------------------------------------------------------------------
# Hunt plan + merge
# ---------------------------------------------------------------------------
"$PY" "$JH" hunt "$FIX" --json --no-progress > "$TMP/hunt.json"
"$PY" - "$TMP/hunt.json" <<'PY'
import json, os, sys
d = json.load(open(sys.argv[1]))
assert d["command"] == "hunt", d
assert len(d["roles"]) >= 3, d
assert d["roles"][-1]["id"] == "verifier", d
assert len(d["prompts"]) == len(d["roles"]), d
assert d["leads"], d
assert d["scenarios"], d
assert d["consensus"]["levels"]["confirmed"], d
blob = json.dumps(d)
assert os.environ["FAKE_KEY"] not in blob, "secret leaked into hunt plan"
assert os.environ["FAKE_TOKEN"] not in blob, "token leaked into hunt plan"
assert "Do not spawn subagents" in d["prompts"][0]["text"], "missing recursion guard"
print("hunt: %d roles, %d leads, %d scenarios" % (len(d["roles"]), len(d["leads"]), len(d["scenarios"])))
PY

cat > "$TMP/panel-a.json" <<'JSON'
{
  "agent": "red-team",
  "findings": [
    {
      "title": "SQL injection in user lookup",
      "rule": "JH104",
      "severity": "critical",
      "confidence": "high",
      "status": "supported",
      "path": "src/users.py",
      "line": 42,
      "evidence": "cursor.execute('...' + name)",
      "causal_chain": "name -> query -> impact",
      "repro": "not reproduced",
      "fix": "parameterize"
    },
    {
      "title": "Missing authz on export",
      "severity": "major",
      "confidence": "medium",
      "status": "unverified",
      "path": "src/export.py",
      "line": 10,
      "evidence": "no permission check"
    },
    {
      "title": "Path traversal in upload",
      "severity": "critical",
      "confidence": "high",
      "status": "confirmed",
      "path": "src/upload.py",
      "line": 5,
      "evidence": "Static trace only; no runtime check.",
      "repro": "not reproduced"
    }
  ],
  "rejected": [
    {
      "title": "XSS in admin",
      "reason": "React escapes the value",
      "evidence": "src/admin.tsx:9"
    }
  ]
}
JSON

cat > "$TMP/panel-b.json" <<'JSON'
{
  "agent": "verifier",
  "findings": [
    {
      "title": "SQL injection in user lookup",
      "rule": "JH104",
      "severity": "critical",
      "confidence": "high",
      "status": "confirmed",
      "path": "src/users.py",
      "line": 42,
      "evidence": "reproduced with payload",
      "repro": "pytest -q tests/test_users.py::test_lookup",
      "fix": "parameterize"
    },
    {
      "title": "SQL injection in user lookup",
      "rule": "JH104",
      "severity": "minor",
      "confidence": "low",
      "status": "rejected",
      "path": "src/users.py",
      "line": 42,
      "evidence": "ORM validates input"
    },
    {
      "title": "Race in token refresh",
      "severity": "major",
      "confidence": "high",
      "status": "confirmed",
      "path": "src/auth.py",
      "line": 20,
      "evidence": "Duplicate refresh requests observed.",
      "repro": "not reproduced",
      "runtime_evidence": "Load test produced two refresh requests for one session; logs attached."
    }
  ]
}
JSON

"$PY" "$JH" merge "$TMP/panel-a.json" "$TMP/panel-b.json" --json > "$TMP/merge.json"
"$PY" - "$TMP/merge.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["command"] == "merge", d
assert d["summary"]["sources"] == 2, d
by_title = {f["title"]: f for f in d["findings"]}
sql = by_title["SQL injection in user lookup"]
assert sql["status"] == "contested", sql
assert sql["conflict"] and sql["dissent"], sql
assert sql["votes"] == 2, sql
gated = by_title["Path traversal in upload"]
assert gated["status"] == "supported", gated
assert gated["status_requested"] == "confirmed", gated
assert "repro" in gated["status_note"] and "runtime" in gated["status_note"], gated
runtime = by_title["Race in token refresh"]
assert runtime["status"] == "confirmed", runtime
assert runtime["runtime"], runtime
assert any(f["status"] == "rejected" for f in d["findings"]), d
assert any(f["status"] == "unverified" for f in d["findings"]), d
print("merge: %d merged, %d conflicts" % (d["summary"]["merged_findings"], d["summary"]["conflicts"]))
PY

# A downgraded claim must not trip the confirmed-finding gate.
if ! "$PY" "$JH" merge "$TMP/panel-a.json" "$TMP/panel-b.json" --fail-on critical \
    --json > /dev/null; then
  fail "merge --fail-on critical should ignore an evidence-gated claim"
fi

"$PY" "$JH" merge "$TMP/panel-a.json" "$TMP/panel-b.json" --md > "$TMP/merge.md"
grep -q "panel consensus" "$TMP/merge.md" || fail "merge --md missing title"
grep -q "CONTESTED" "$TMP/merge.md" || fail "merge --md missing contested status"
grep -q "downgraded" "$TMP/merge.md" || fail "merge --md missing evidence-gate note"

# ---------------------------------------------------------------------------
# Report
# ---------------------------------------------------------------------------
"$PY" "$JH" report "$FIX" --logs "$FIX/app.log" --out "$TMP/report.md" --no-progress >/dev/null
grep -q "jankhunt42 report" "$TMP/report.md" || fail "report missing title"
grep -q "Jank score" "$TMP/report.md" || fail "report missing score"
grep -q "Investigation worksheet" "$TMP/report.md" || fail "report missing worksheet"
grep -q "Log triage" "$TMP/report.md" || fail "report missing triage"

# ---------------------------------------------------------------------------
# Rule catalog, help, and TTY
# ---------------------------------------------------------------------------
"$PY" "$JH" rules --json > "$TMP/rules.json"
"$PY" - "$TMP/rules.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert len(d) == 96, len(d)
ids = {r["id"] for r in d}
assert "JH901" in ids and "JH101" in ids, ids
assert {r["id"] for r in d if r["category"] == "agent"} == {"JH70%d" % i for i in range(1, 9)}, ids
print("rules: %d" % len(d))
PY

"$PY" "$JH" --help >/dev/null
for cmd in scan review supply-chain score hunt merge triage doctor report rules; do
  "$PY" "$JH" "$cmd" --help >/dev/null || fail "help failed for $cmd"
done

if command -v script >/dev/null 2>&1; then
  script -qec "'$PY' '$JH' scan '$FIX' --no-progress" /dev/null > "$TMP/tty.txt" 2>/dev/null || true
  sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g' "$TMP/tty.txt" > "$TMP/tty-clean.txt"
  grep -q "J A N K H U N T" "$TMP/tty-clean.txt" || fail "TTY banner missing"
  grep -q "JANK" "$TMP/tty-clean.txt" || fail "TTY score missing"
  script -qec "'$PY' '$JH' review '$REVIEW' --no-color" /dev/null > "$TMP/review-tty.txt" 2>/dev/null || true
  sed -r 's/\x1B\[[0-9;]*[A-Za-z]//g' "$TMP/review-tty.txt" > "$TMP/review-tty-clean.txt"
  grep -q "diff review" "$TMP/review-tty-clean.txt" || fail "review TTY header missing"
fi

# ---------------------------------------------------------------------------
# Config file, cross-file duplicates, FP calibration
# ---------------------------------------------------------------------------
CFG="$TMP/cfgfix"
mkdir -p "$CFG/a" "$CFG/b"
printf 'def handler(value):\n    return eval(value)\n' > "$CFG/a/one.py"
printf 'def other(value):\n    return eval(value)\n' > "$CFG/b/two.py"

# Baseline: both files fire JH102, and the identical evidence lines across
# two files form one cross-file duplicate cluster.
"$PY" "$JH" scan "$CFG" --json --min-severity info --no-config > "$TMP/cfg-base.json"
"$PY" - "$TMP/cfg-base.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["summary"]["findings"] == 2, d["summary"]
dupes = d["cross_file_duplicates"]
assert len(dupes) == 1, dupes
assert dupes[0]["rule"] == "JH102" and dupes[0]["count"] == 2, dupes[0]
print("cross-file duplicates: %d cluster(s), %d sites" % (len(dupes), dupes[0]["count"]))
PY

# A config file can disable a rule and ignore a whole subtree.
cat > "$CFG/.jankhunt42.json" <<'JSON'
{"rules": {"JH102": {"enabled": false}}}
JSON
"$PY" "$JH" scan "$CFG" --json --min-severity info > "$TMP/cfg-disabled.json"
"$PY" - "$TMP/cfg-disabled.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["summary"]["findings"] == 0, d["summary"]
assert d["config"] and d["config"].endswith(".jankhunt42.json"), d["config"]
PY

# A path-scoped severity override applies only to matching paths.
cat > "$CFG/.jankhunt42.json" <<'JSON'
{"paths": {"a/*.py": {"severity": {"JH102": "info"}}}}
JSON
"$PY" "$JH" scan "$CFG" --json --min-severity info > "$TMP/cfg-sev.json"
"$PY" - "$TMP/cfg-sev.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
by_path = {f["path"]: f["severity"] for f in d["findings"]}
assert by_path["a/one.py"] == "info", by_path
assert by_path["b/two.py"] == "major", by_path
PY
rm -f "$CFG/.jankhunt42.json"

# TOML config needs tomllib (3.11+); older interpreters must warn and skip
# it, never crash or silently misparse it.
cat > "$CFG/.jankhunt42.toml" <<'TOML'
[rules.JH102]
enabled = false
TOML
if "$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)'; then
  "$PY" "$JH" scan "$CFG" --json --min-severity info > "$TMP/cfg-toml.json" 2>"$TMP/cfg-toml.err"
  "$PY" - "$TMP/cfg-toml.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["summary"]["findings"] == 0, d["summary"]
assert d["config"].endswith(".jankhunt42.toml"), d["config"]
PY
  [ -s "$TMP/cfg-toml.err" ] && fail "unexpected stderr parsing a valid .jankhunt42.toml: $(cat "$TMP/cfg-toml.err")"
else
  "$PY" "$JH" scan "$CFG" --json --min-severity info > "$TMP/cfg-toml.json" 2>"$TMP/cfg-toml.err"
  grep -qi "tomllib" "$TMP/cfg-toml.err" || fail "no tomllib-unavailable warning on <3.11"
  "$PY" - "$TMP/cfg-toml.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["summary"]["findings"] == 2, d["summary"]  # config was skipped, not applied
assert d["config"] is None, d["config"]
PY
fi
rm -f "$CFG/.jankhunt42.toml"
note "config: rule disable, path severity override, TOML/JSON, and cross-file duplicates all verified"

# FP calibration is opt-in, writes only on --calibrate, and needs history
# from a *prior* run before it downgrades anything (never self-referential
# within one run).
CAL="$TMP/calfix"
mkdir -p "$CAL"
# Exactly 50% suppressed (3 of 6): lands in the one-step-downgrade band
# (>=50%, <80%) rather than the info-floor band (>=80%), so this also
# exercises the distinction between the two calibration tiers.
for i in 1 2 3; do
  printf 'def h%d(v):\n    return eval(v)  # jankhunt42: ignore JH102\n' "$i" > "$CAL/s$i.py"
done
for i in 4 5 6; do
  printf 'def h%d(v):\n    return eval(v)\n' "$i" > "$CAL/s$i.py"
done
"$PY" "$JH" scan "$CAL" --json --min-severity info > "$TMP/cal-run1.json"
[ -f "$CAL/.jankhunt42/calibration.json" ] && fail "calibration ledger written without --calibrate"
"$PY" "$JH" scan "$CAL" --calibrate --json --min-severity info > "$TMP/cal-run1.json"
[ -f "$CAL/.jankhunt42/calibration.json" ] || fail "--calibrate did not write a ledger"
"$PY" - "$TMP/cal-run1.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["calibration"]["downgrades"] == [], d["calibration"]
PY
"$PY" "$JH" scan "$CAL" --calibrate --json --min-severity info > "$TMP/cal-run2.json"
"$PY" - "$TMP/cal-run2.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
downgrades = d["calibration"]["downgrades"]
assert len(downgrades) == 1 and downgrades[0]["rule"] == "JH102", downgrades
assert downgrades[0]["to"] == "minor", downgrades
sevs = {f["severity"] for f in d["findings"]}
assert sevs == {"minor"}, sevs
print("calibration: JH102 downgraded major->minor after %.0f%% suppression over %d runs"
      % (downgrades[0]["suppression_rate"] * 100, downgrades[0]["observations"]))
PY

# ---------------------------------------------------------------------------
# What can it hurt? / Can we ship it? (smoke; depth lives in tests/)
# ---------------------------------------------------------------------------
cp -R "$SKILL/tests/fixtures/demo-app" "$TMP/demo-app"
"$PY" "$JH" map "$TMP/demo-app" --json > "$TMP/map.json" || fail "map --json failed"
"$PY" - "$TMP/map.json" <<'PY'
import json, sys
d = json.load(open(sys.argv[1]))
assert d["schema_version"] == "jankhunt.map.v1", d["schema_version"]
assert d["assessment"]["exposure"]["class"] == "High", d["assessment"]["exposure"]
assert d["graph"]["nodes"] and d["graph"]["edges"]
assert "example-only" not in json.dumps(d), "fixture credential leaked"
PY
"$PY" "$JH" map "$TMP/demo-app" --html > "$TMP/map.html" || fail "map --html failed"
grep -q "default-src 'none'" "$TMP/map.html" || fail "map HTML lacks the no-network CSP"
"$PY" "$JH" passport "$TMP/demo-app" --json > "$TMP/passport.json" || fail "passport --json failed"
"$PY" - "$TMP/passport.json" <<'PY'
import json, sys
p = json.load(open(sys.argv[1]))
assert p["schema_version"] == "jankhunt.passport.v1"
assert p["assessment"]["decision"]["result"] in ("pass", "review", "insufficient-evidence", "block")
assert p["lifecycle"]["acceptance"]["state"] == "not-supplied"
PY
set +e
"$PY" "$JH" passport "$TMP/demo-app" --fail-on review >/dev/null 2>&1; rc=$?
set -e
[ "$rc" = 1 ] || fail "passport --fail-on review should exit 1 on the demo (got $rc)"
note "map/passport: versioned JSON, offline HTML, enforcement opt-in"

# ---------------------------------------------------------------------------
# Docs and packaging sanity
# ---------------------------------------------------------------------------
for doc in "$SKILL/SKILL.md" "$SKILL/README.md" "$SKILL/CHANGELOG.md" \
           "$SKILL/references/method.md" "$SKILL/references/playbooks.md" \
           "$SKILL/references/toolbox.md" "$SKILL/references/deep-hunt.md" \
           "$SKILL/references/scoring.md" "$SKILL/references/review.md" \
           "$SKILL/references/supply-chain.md" "$SKILL/templates/report.md" \
           "$SKILL/templates/hunt-report.md" "$SKILL/templates/panel-finding.json" \
           "$SKILL/templates/review-receipt.schema.json" \
           "$SKILL/references/connectivity.md" "$SKILL/references/passport.md" \
           "$SKILL/templates/map.schema.json" "$SKILL/templates/passport.schema.json"; do
  [ -s "$doc" ] || fail "missing or empty doc: $doc"
done
grep -q '^license: MIT' "$SKILL/SKILL.md" || fail "SKILL.md missing top-level license"
grep -q '^compatibility:' "$SKILL/SKILL.md" || fail "SKILL.md missing top-level compatibility"
grep -q 'references/review.md' "$SKILL/SKILL.md" || fail "SKILL.md missing review reference"
grep -q 'references/supply-chain.md' "$SKILL/SKILL.md" || fail "SKILL.md missing supply-chain reference"
grep -q 'references/connectivity.md' "$SKILL/SKILL.md" || fail "SKILL.md missing connectivity reference"
grep -q 'references/passport.md' "$SKILL/SKILL.md" || fail "SKILL.md missing passport reference"
grep -q '^name: jankhunt42$' "$SKILL/SKILL.md" || fail "SKILL.md name must be lowercase jankhunt42"
"$PY" - "$SKILL/templates/review-receipt.schema.json" <<'PY'
import json, sys
schema = json.load(open(sys.argv[1]))
assert schema["type"] == "object" and schema["required"], schema
assert schema["properties"]["verification"]["enum"] == ["supported", "unverified"], schema
PY
if find "$SKILL" -name '__pycache__' -o -name '*.pyc' | grep -q .; then
  fail "generated Python cache present in the skill directory"
fi

note "all checks passed"
