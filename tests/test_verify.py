"""2.2.0 verification mode: plan trust rules, offline/online gating, native
verifier outcomes (fake gh/cosign/jf programs), GitHub fetching through a fake
HTTP layer, credential handling on redirects, artifact safety, JFrog key
sources, and passport/policy integration. No test touches the network."""
import base64
import hashlib
import io
import json
import os
import shutil
import socket
import stat
import sys
import tempfile
import unittest
import urllib.error
import zipfile
from email.message import Message
from unittest import mock

import _util
from _util import run_cli
import jh_passport
import jh_supply
import jh_verify

PRED = "https://slsa.dev/provenance/v1"
TOKEN = "ghp_" + "Fake0123456789abcdefFAKEfake0123456789"


def statement(sha, ptype=PRED):
    return {"_type": "https://in-toto.io/Statement/v1", "subject": [{"name": "app.tar.gz", "digest": {"sha256": sha}}],
            "predicateType": ptype,
            "predicate": {"buildDefinition": {"buildType": "https://actions.github.io/buildtypes/workflow/v1",
                                              "externalParameters": {"workflow": {
                                                  "repository": "https://github.com/example-org/app",
                                                  "path": ".github/workflows/release.yml", "ref": "refs/tags/v1"}},
                                              "resolvedDependencies": [{"digest": {"gitCommit": "a" * 40}}]},
                          "runDetails": {"builder": {"id": "https://github.com/actions/runner"}}}}


def bundle(sha, ptype=PRED):
    payload = base64.b64encode(json.dumps(statement(sha, ptype)).encode()).decode()
    return {"mediaType": "application/vnd.dev.sigstore.bundle.v0.3+json",
            "verificationMaterial": {"certificate": {"rawBytes": "AAAA"}},
            "dsseEnvelope": {"payload": payload, "payloadType": "application/vnd.in-toto+json",
                             "signatures": [{"sig": "MEUCIQ=="}]}}


FAKE_TOOL = r'''#!{python}
import hashlib, json, os, sys
here = os.path.dirname(os.path.abspath(__file__))
name = os.path.basename(__file__)
beh = json.load(open(os.path.join(here, "behavior.json")))
args = sys.argv[1:]
if args in (["--version"], ["version"]):
    print({{"gh": "gh version 2.99.0 (fake)", "jf": "jf version 2.99.0", "cosign": "GitVersion:    v3.0.0-fake"}}[name])
    sys.exit(0)
with open(os.path.join(here, name + ".calls"), "a") as fh:
    fh.write(json.dumps(args) + "\n")
b = beh.get(name, {{}})
group = [f for f in ("--cert-identity", "--cert-identity-regex", "--signer-repo", "--signer-workflow") if f in args]
if name == "gh" and len(group) > 1:
    sys.stderr.write("if any flags in the group [cert-identity cert-identity-regex signer-repo signer-workflow] "
                     "are set none of the others can be\n")
    sys.exit(1)
if b.get("stderr"):
    sys.stderr.write(b["stderr"])
if name == "gh" and b.get("rc", 0) == 0:
    subject = args[2]
    sha = b.get("sha") or hashlib.sha256(open(subject, "rb").read()).hexdigest()
    ptype = args[args.index("--predicate-type") + 1]
    print(json.dumps([{{"verificationResult": {{
        "statement": {{"subject": [{{"digest": {{"sha256": sha}}}}], "predicateType": ptype}},
        "signature": {{"certificate": {{"sourceRepositoryIdentifier": b.get("repo_id", "4242"),
                                       "sourceRepositoryURI": "https://github.com/example-org/app",
                                       "buildSignerURI": "https://github.com/example-org/app/.github/workflows/release.yml@refs/tags/v1"}}}}}}}}]))
elif name == "jf":
    print(json.dumps(b["output"]))
sys.exit(b.get("rc", 0))
'''


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="jh-verify-")
        self.repo = os.path.join(self.tmp, "repo")
        self.ops = os.path.join(self.tmp, "ops")
        self.bin = os.path.join(self.tmp, "bin")
        for d in (self.repo, self.ops, self.bin):
            os.makedirs(d)
        os.makedirs(os.path.join(self.repo, "dist"))
        self.artifact = os.path.join(self.repo, "dist", "app.tar.gz")
        with open(self.artifact, "wb") as fh:
            fh.write(b"release artifact bytes")
        self.sha = hashlib.sha256(b"release artifact bytes").hexdigest()
        with open(os.path.join(self.ops, "trusted_root.jsonl"), "w") as fh:
            fh.write('{"mediaType": "application/vnd.dev.sigstore.trustedroot+json;version=0.1"}\n')
        self.write(os.path.join(self.ops, "app.sigstore.json"), bundle(self.sha))
        for name in ("gh", "cosign", "jf"):
            path = os.path.join(self.bin, name)
            with open(path, "w") as fh:
                fh.write(FAKE_TOOL.format(python=sys.executable))
            os.chmod(path, os.stat(path).st_mode | stat.S_IEXEC)
        self.behave({})

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    @staticmethod
    def write(path, data):
        with open(path, "w") as fh:
            json.dump(data, fh)

    def behave(self, beh):
        self.write(os.path.join(self.bin, "behavior.json"), beh)

    def calls(self, name):
        path = os.path.join(self.bin, name + ".calls")
        if not os.path.exists(path):
            return []
        with open(path) as fh:
            return [json.loads(line) for line in fh]

    def plan(self, **over):
        p = {"schema_version": "jankhunt.verify.v1",
             "identity": {"repo": "example-org/app", "signer_workflow": "example-org/app/.github/workflows/release.yml"},
             "trusted_root": "trusted_root.jsonl",
             "subjects": [{"path": "../repo/dist/app.tar.gz", "bundle": "app.sigstore.json"}],
             "tools": {"gh": "../bin/gh", "cosign": "../bin/cosign", "jf": "../bin/jf"}}
        for k, v in over.items():
            if v is None:
                p.pop(k, None)
            else:
                p[k] = v
        path = os.path.join(self.ops, "plan.json")
        self.write(path, p)
        return path

    def verify(self, online=False, requirements=None, **over):
        plan = jh_verify.load_plan(self.plan(**over), self.repo)
        return jh_verify.verify_supply(self.repo, plan, online, requirements=requirements or {}, discover=True)


class NoNetwork:
    """Any socket connection attempt fails the test."""

    def __enter__(self):
        self.p = mock.patch.object(socket.socket, "connect", side_effect=AssertionError("network used"))
        self.p.start()
        return self

    def __exit__(self, *exc):
        self.p.stop()


class Plans(Base):
    def test_plan_inside_repository_is_refused(self):
        path = os.path.join(self.repo, "plan.json")
        self.write(path, {"schema_version": "jankhunt.verify.v1", "identity": {"repo": "a/b"},
                          "subjects": [{"path": "dist/app.tar.gz"}]})
        with self.assertRaisesRegex(jh_verify.PlanError, "inside the scanned repository"):
            jh_verify.load_plan(path, self.repo)

    def test_misspelt_identity_key_is_refused(self):
        with self.assertRaisesRegex(jh_verify.PlanError, "unknown key"):
            jh_verify.load_plan(self.plan(identity={"repo": "a/b", "signer_workfow": "x"}), self.repo)

    def test_schema_and_requirements(self):
        with self.assertRaisesRegex(jh_verify.PlanError, "schema_version"):
            jh_verify.load_plan(self.plan(schema_version="v0"), self.repo)
        with self.assertRaisesRegex(jh_verify.PlanError, "identity.repo or identity.owner"):
            jh_verify.load_plan(self.plan(identity={}), self.repo)
        with self.assertRaisesRegex(jh_verify.PlanError, "certificate_identity"):
            jh_verify.load_plan(self.plan(subjects=[{"path": "x", "verifier": "cosign"}]), self.repo)
        with self.assertRaisesRegex(jh_verify.PlanError, "nothing to verify"):
            jh_verify.load_plan(self.plan(subjects=[]), self.repo)
        with self.assertRaisesRegex(jh_verify.PlanError, "trusted_root"):
            jh_verify.load_plan(self.plan(trusted_root="missing.jsonl"), self.repo)


class Offline(Base):
    def test_offline_verification_with_bundle_and_trusted_root(self):
        with NoNetwork():
            rep = self.verify(requirements={"verified_attestation": True})
        r = rep["verification"]["results"][0]
        self.assertEqual(r["outcome"], "tool-verified")
        self.assertEqual(r["mode"], "offline")
        self.assertEqual(rep["verification"]["network_requests"], 0)
        argv = self.calls("gh")[0]
        self.assertIn("--bundle", argv)
        self.assertIn("--custom-trusted-root", argv)
        self.assertEqual(argv[argv.index("--signer-workflow") + 1], "example-org/app/.github/workflows/release.yml")
        self.assertTrue(all(not os.path.isabs(a) for a in r["command"]), r["command"])
        att = rep["attestations"][0]
        self.assertEqual(att["verification"], "tool-verified")
        self.assertEqual(att["exporter_verification"], "unverified")
        self.assertEqual(rep["gate"]["result"], "pass")
        self.assertEqual(rep["summary"]["tool_verified_attestations"], 1)

    def test_gh_gets_one_signer_constraint(self):
        ident = "https://github.com/example-org/app/.github/workflows/release.yml@refs/tags/v1"
        rep = self.verify(identity={"repo": "example-org/app", "certificate_identity": ident,
                                    "signer_workflow": "example-org/app/.github/workflows/release.yml"})
        r = rep["verification"]["results"][0]
        self.assertEqual(r["outcome"], "tool-verified", r["reason"])
        self.assertEqual(r["signer_constraint"], "--cert-identity")
        argv = self.calls("gh")[0]
        self.assertEqual(argv[argv.index("--cert-identity") + 1], ident)
        self.assertNotIn("--signer-workflow", argv)

    def test_offline_without_trusted_root_does_not_run(self):
        with NoNetwork():
            rep = self.verify(trusted_root=None)
        r = rep["verification"]["results"][0]
        self.assertEqual(r["outcome"], "not-run")
        self.assertIn("trusted_root", r["reason"])
        self.assertEqual(self.calls("gh"), [])
        self.assertEqual(rep["gate"]["result"], "fail")
        self.assertTrue(any(x.startswith("verification not completed") for x in rep["gate"]["reasons"]))

    def test_fetch_is_skipped_offline(self):
        with NoNetwork():
            rep = self.verify(subjects=[{"path": "../repo/dist/app.tar.gz"}], fetch={"github_attestations": True})
        self.assertIn("fetch.github_attestations skipped: needs --online", rep["verification"]["warnings"])
        self.assertEqual(rep["verification"]["results"][0]["outcome"], "not-run")

    def test_gh_failure_fails_the_gate(self):
        self.behave({"gh": {"rc": 1, "stderr": "verification failed: certificate identity mismatch\n"}})
        rep = self.verify()
        r = rep["verification"]["results"][0]
        self.assertEqual(r["outcome"], "failed")
        self.assertIn("identity mismatch", r["reason"])
        self.assertTrue(any(x.startswith("verification failed") for x in rep["gate"]["reasons"]))
        self.assertEqual(rep["attestations"][0]["verification"], "unverified")

    def test_repository_id_mismatch_fails(self):
        self.behave({"gh": {"repo_id": "999"}})
        rep = self.verify(identity={"repo": "example-org/app", "repo_id": 4242})
        r = rep["verification"]["results"][0]
        self.assertEqual(r["outcome"], "failed")
        self.assertIn("repository ID", r["reason"])

    def test_success_that_names_another_digest_fails(self):
        self.behave({"gh": {"sha": "b" * 64}})
        r = self.verify()["verification"]["results"][0]
        self.assertEqual(r["outcome"], "failed")

    def test_missing_tool_never_verifies(self):
        rep = self.verify(tools={"gh": "../bin/nope"}, requirements={"verified_attestation": True})
        self.assertEqual(rep["verification"]["results"][0]["outcome"], "not-run")
        self.assertIn("no provider-verified or tool-verified attestation found", rep["gate"]["reasons"])

    def test_cosign_offline(self):
        rep = self.verify(identity={"repo": "example-org/app",
                                    "certificate_identity": "https://github.com/example-org/app/.github/workflows/release.yml@refs/tags/v1"},
                          subjects=[{"path": "../repo/dist/app.tar.gz", "bundle": "app.sigstore.json", "verifier": "cosign"}])
        r = rep["verification"]["results"][0]
        self.assertEqual(r["outcome"], "tool-verified")
        argv = self.calls("cosign")[0]
        self.assertIn("--trusted-root", argv)
        self.assertEqual(argv[argv.index("--certificate-oidc-issuer") + 1], jh_verify.GITHUB_ISSUER)
        self.assertEqual(rep["attestations"][0]["verification"], "tool-verified")


class FakeResponse(io.BytesIO):
    def __init__(self, body, status=200):
        super().__init__(body)
        self.status = status


class FakeHTTP:
    def __init__(self, routes):
        self.routes = routes
        self.seen = []

    def __call__(self, req, timeout):
        self.seen.append((req.full_url, dict(req.header_items())))
        for prefix, handler in self.routes:
            if req.full_url.startswith(prefix):
                return handler(req)
        raise AssertionError("unexpected URL %s" % req.full_url)


def http_error(code, location=None):
    headers = Message()
    if location:
        headers["Location"] = location
    return urllib.error.HTTPError("https://x", code, "status", headers, io.BytesIO(b""))


def raiser(exc):
    def handler(req):
        raise exc
    return handler


class Online(Base):
    def test_fetches_github_attestations_and_verifies_the_bundle(self):
        api = "https://api.github.com/repos/example-org/app/attestations/sha256:%s" % self.sha
        fake = FakeHTTP([(api, lambda req: FakeResponse(json.dumps(
            {"attestations": [{"bundle": bundle(self.sha), "repository_id": 4242}]}).encode()))])
        with mock.patch.object(jh_verify, "_open", fake), mock.patch.dict(os.environ, {"GH_TOKEN": TOKEN}):
            rep = self.verify(online=True, subjects=[{"path": "../repo/dist/app.tar.gz"}],
                              fetch={"github_attestations": True})
        self.assertEqual(rep["verification"]["network_requests"], 1)
        self.assertEqual(fake.seen[0][1].get("Authorization"), "Bearer " + TOKEN)
        argv = self.calls("gh")[0]
        self.assertTrue(argv[argv.index("--bundle") + 1].endswith("sha256-%s.jsonl" % self.sha))
        att = rep["attestations"][0]
        self.assertEqual(att["origin"], "github-attestations-api")
        self.assertEqual(att["verification"], "tool-verified")
        self.assertNotIn(TOKEN, json.dumps(rep))

    def _artifact_routes(self, zbytes, digest=None, run_sha="c" * 40):
        listing = {"artifacts": [{"id": 77, "name": "sbom", "expired": False, "created_at": "2026-10-01T00:00:00Z",
                                  "digest": digest if digest is not None else "sha256:" + hashlib.sha256(zbytes).hexdigest(),
                                  "workflow_run": {"id": 5, "head_sha": run_sha}}]}
        return [
            ("https://api.github.com/repos/example-org/app/actions/artifacts?",
             lambda req: FakeResponse(json.dumps(listing).encode())),
            ("https://api.github.com/repos/example-org/app/actions/artifacts/77/zip",
             raiser(http_error(302, "https://blob.example.net/signed?sig=abc"))),
            ("https://blob.example.net/", lambda req: FakeResponse(zbytes)),
        ]

    @staticmethod
    def _zip(members):
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            for name, data in members.items():
                zf.writestr(name, data)
        return buf.getvalue()

    def _spdx(self):
        return json.dumps({"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT", "name": "app",
                           "packages": [{"name": "requests", "versionInfo": "2.32.3", "SPDXID": "SPDXRef-p1"}]})

    def test_artifact_download_drops_the_token_on_redirect(self):
        z = self._zip({"../../etc/sbom.spdx.json": self._spdx(), "notes.bin": "x"})
        fake = FakeHTTP(self._artifact_routes(z))
        with mock.patch.object(jh_verify, "_open", fake), mock.patch.dict(os.environ, {"GH_TOKEN": TOKEN}):
            rep = self.verify(online=True, subjects=[], fetch={"actions_artifacts": [{"name": "sbom"}]},
                              trusted_root=None)
        blob = [h for url, h in fake.seen if url.startswith("https://blob.example.net/")]
        self.assertEqual(len(blob), 1)
        self.assertNotIn("Authorization", blob[0])
        api = [h for url, h in fake.seen if url.startswith("https://api.github.com/")]
        self.assertTrue(all(h.get("Authorization") == "Bearer " + TOKEN for h in api))
        info = rep["verification"]["fetched"][0]
        self.assertEqual(info["files"], ["artifact-77-sbom.spdx.json"])
        self.assertTrue(info["digest_match"])
        sbom = rep["sboms"][0]
        self.assertEqual(sbom["origin"], "github-actions-artifact")
        self.assertTrue(any("unsigned" in w for w in sbom["warnings"]))
        self.assertEqual(rep["summary"]["packages"], 1)

    def test_artifact_digest_mismatch_is_rejected(self):
        z = self._zip({"sbom.spdx.json": self._spdx()})
        fake = FakeHTTP(self._artifact_routes(z, digest="sha256:" + "0" * 64))
        with mock.patch.object(jh_verify, "_open", fake):
            rep = self.verify(online=True, subjects=[], fetch={"actions_artifacts": [{"name": "sbom"}]})
        self.assertIn("does not match", rep["verification"]["fetched"][0]["error"])
        self.assertEqual(rep["sboms"], [])

    def test_artifact_download_without_token_explains_why(self):
        routes = self._artifact_routes(b"")
        routes[1] = ("https://api.github.com/repos/example-org/app/actions/artifacts/77/zip", raiser(http_error(401)))
        env = {k: v for k, v in os.environ.items() if k not in ("GH_TOKEN", "GITHUB_TOKEN")}
        with mock.patch.object(jh_verify, "_open", FakeHTTP(routes)), mock.patch.dict(os.environ, env, clear=True):
            rep = self.verify(online=True, subjects=[], fetch={"actions_artifacts": [{"name": "sbom"}]})
        self.assertIn("needs GH_TOKEN", rep["verification"]["fetched"][0]["error"])

    def test_non_https_redirect_is_refused(self):
        net = jh_verify._Net(True, TOKEN)
        fake = FakeHTTP([("https://api.github.com/x", raiser(http_error(302, "http://plain.example.net/")))])
        with mock.patch.object(jh_verify, "_open", fake):
            with self.assertRaisesRegex(jh_verify.FetchError, "non-HTTPS"):
                net.get("https://api.github.com/x")

    def test_offline_net_refuses(self):
        with self.assertRaisesRegex(jh_verify.FetchError, "--online"):
            jh_verify._Net(False, None).get("https://api.github.com/x")

    def test_oversized_response_is_refused(self):
        net = jh_verify._Net(True, None)
        fake = FakeHTTP([("https://api.github.com/x", lambda req: FakeResponse(b"x" * 11))])
        with mock.patch.object(jh_verify, "_open", fake):
            with self.assertRaisesRegex(jh_verify.FetchError, "larger than"):
                net.get("https://api.github.com/x", limit=10)

    def test_zip_member_names_are_sanitized(self):
        self.assertEqual(jh_verify._safe_member_name("../../x/../sbom.json"), "sbom.json")
        self.assertEqual(jh_verify._safe_member_name("..\\..\\evil name.json"), "evil_name.json")
        self.assertEqual(jh_verify._safe_member_name("../.."), "")


class JFrog(Base):
    def jf_output(self, key_source, status="success"):
        b = bundle(self.sha)
        return {"schemaVersion": "1.2", "subject": {"path": "repo/app.tar.gz", "sha256": self.sha},
                "evidenceVerifications": [{
                    "mediaType": "sigstore.bundle", "predicateType": PRED, "evidenceSubjectSha256": self.sha,
                    "createdBy": "ci", "createdAt": "2026-10-01T00:00:00Z", "sigstoreBundle": b,
                    "verificationResult": {"sigstoreBundleVerificationStatus": status, "keySource": key_source}}],
                "overallVerificationStatus": status}

    def jplan(self, identity=None):
        return dict(subjects=[], trusted_root=None, identity=identity or {"repo": "example-org/app"},
                    jfrog=[{"subject_repo_path": "repo/app.tar.gz", "use_artifactory_keys": True}])

    def test_jf_needs_online(self):
        rep = self.verify(**self.jplan())
        self.assertEqual(rep["verification"]["results"][0]["outcome"], "not-run")
        self.assertEqual(self.calls("jf"), [])

    def test_user_key_is_tool_verified(self):
        self.behave({"jf": {"output": self.jf_output("User Provided Key")}})
        rep = self.verify(online=True, **self.jplan())
        r = rep["verification"]["results"][0]
        self.assertEqual(r["outcome"], "tool-verified")
        self.assertTrue(r["identity_checked"])
        self.assertEqual(rep["attestations"][0]["origin"], "jf-evd-verify")
        self.assertEqual(rep["attestations"][0]["verification"], "tool-verified")

    def test_bundle_key_is_signature_only_without_identity(self):
        self.behave({"jf": {"output": self.jf_output("Sigstore Bundle Key")}})
        rep = self.verify(online=True, requirements={"verified_attestation": True}, **self.jplan())
        r = rep["verification"]["results"][0]
        self.assertEqual(r["outcome"], "signature-only")
        self.assertFalse(r["identity_checked"])
        self.assertEqual(rep["attestations"][0]["verification"], "signature-only")
        self.assertEqual(rep["gate"]["result"], "fail")

    def test_bundle_key_rechecked_with_cosign(self):
        self.behave({"jf": {"output": self.jf_output("Sigstore Bundle Key")}})
        rep = self.verify(online=True, **self.jplan({"repo": "example-org/app",
                                                     "certificate_identity_regexp": "^https://github.com/example-org/"}))
        r = rep["verification"]["results"][0]
        self.assertEqual(r["outcome"], "tool-verified")
        self.assertEqual(r["identity_recheck"]["outcome"], "tool-verified")
        argv = self.calls("cosign")[0]
        self.assertEqual(argv[argv.index("--digest") + 1], self.sha)
        self.assertEqual(argv[argv.index("--type") + 1], PRED)

    def test_failed_status(self):
        self.behave({"jf": {"output": self.jf_output("User Provided Key", status="failed"), "rc": 1}})
        rep = self.verify(online=True, **self.jplan())
        self.assertEqual(rep["verification"]["results"][0]["outcome"], "failed")

    def test_exported_bundle_key_is_flagged_offline(self):
        export = self.jf_output("Sigstore Bundle Key")
        path = os.path.join(self.repo, "jfrog-evidence.json")
        self.write(path, export)
        rep = jh_supply.inspect(self.repo, discover=True)
        att = rep["attestations"][0]
        self.assertEqual(att["verification"], "provider-verified")
        self.assertEqual(att["key_source"], "Sigstore Bundle Key")
        self.assertIn(jh_supply.BUNDLE_KEY_WARNING, att["warnings"])
        self.assertIn("provider-verified (bundle key)", jh_supply.markdown(rep))


class Cli(Base):
    def test_online_without_verify_is_a_usage_error(self):
        r = run_cli("supply-chain", self.repo, "--online")
        self.assertEqual(r.returncode, 2)
        self.assertIn("--verify", r.stderr)

    def test_in_repo_plan_is_a_usage_error(self):
        path = os.path.join(self.repo, "plan.json")
        self.write(path, {"schema_version": "jankhunt.verify.v1"})
        r = run_cli("supply-chain", self.repo, "--verify", path)
        self.assertEqual(r.returncode, 2)
        self.assertIn("inside the scanned repository", r.stderr)

    def test_supply_chain_json_and_markdown(self):
        r = run_cli("supply-chain", self.repo, "--verify", self.plan(), "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        d = json.loads(r.stdout)
        self.assertEqual(d["verification"]["results"][0]["outcome"], "tool-verified")
        self.assertNotIn(self.tmp, json.dumps(d["verification"]))
        self.assertNotIn(self.tmp, json.dumps(d["attestations"]))
        self.assertEqual(d["attestations"][0]["verified_by"], "gh 2.99.0 (fake)")
        self.assertEqual(d["attestations"][0]["warnings"], [])
        md = run_cli("supply-chain", self.repo, "--verify", self.plan(), "--md").stdout
        self.assertIn("### Verification (offline, plan `plan.json`)", md)
        self.assertIn("tool-verified (gh 2.99.0 (fake))", md)

    def test_passport_failed_verification_is_insufficient_evidence(self):
        self.behave({"gh": {"rc": 1, "stderr": "no matching attestation"}})
        r = run_cli("passport", self.repo, "--verify", self.plan(), "--json")
        self.assertEqual(r.returncode, 0, r.stderr)
        p = json.loads(r.stdout)
        rule = next(x for x in p["assessment"]["decision"]["rules"] if x["rule"] == "P-EVD-001")
        self.assertEqual(rule["outcome"], "insufficient-evidence")
        self.assertIn("completed attestation verification", rule["message"])
        self.assertEqual(p["provenance"]["verification"]["results"][0]["outcome"], "failed")
        self.assertNotIn("ran_at", json.dumps(p["provenance"]))
        red = jh_passport.redact(p)
        self.assertEqual(red["provenance"]["verification"]["results"][0]["subject"], "subject-1")
        self.assertNotIn("no matching attestation", json.dumps(red))

    def test_passport_tool_verified_digest(self):
        r = run_cli("passport", self.repo, "--verify", self.plan(), "--json")
        p = json.loads(r.stdout)
        d = p["subject"]["artifact_digests"][0]
        self.assertEqual(d["digest"], "sha256:" + self.sha)
        self.assertIn("verified by gh", d["verification"])
        rule = next(x for x in p["assessment"]["decision"]["rules"] if x["rule"] == "P-EVD-001")
        self.assertEqual(rule["outcome"], "pass")
        self.assertEqual(p["provenance"]["attestations"][0]["kind"], "slsa-provenance-v1")


if __name__ == "__main__":
    unittest.main()
