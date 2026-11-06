"""Agent Substrate (4.13.0): egress policies and actor templates, scanned (JH709, JH710, JH713),
emitted (passport --emit-sandbox-policy substrate) and read back as a declared boundary.
Invented manifests only; every secret-looking value is fake."""
import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import run_cli
import jh_core
import jh_egress
import jh_fence
import jh_substrate as S

DEMO = os.path.join(_util.FIXTURES, "demo-app")

TEMPLATE = """\
metadata:
  atespace: helpdesk
  name: triage-agent
workerSelector:
  matchLabels:
    workload: helpdesk
containers:
- name: agent
  image: ${WORKLOAD_IMAGE}
  env:
  - name: ANTHROPIC_API_KEY
    value: "${ANTHROPIC_API_KEY}"
  - name: TICKETS_TOKEN
    value: "tk_live_9f8e7d6c5b4a39281706"
  - name: OPENAI_API_KEY
    value: "placeholder-replaced-by-egress-gateway"
  - name: TOKEN_URL
    value: "https://login.helpdesk.invalid/oauth/token"
  - name: SSL_CERT_FILE
    value: /run/ate/egress-trust-bundle/trust-bundle.pem
  - name: GITHUB_TOKEN
    value: "gh-tok-EXAMPLE-EXAMPLE-EXAMPLE"
goldenEgressPolicy:
  rules:
  - tlsPassthrough:
      hostnames: ["api.anthropic.com"]
      ports:
        numbers: [443]
"""

POLICY = """\
rules:
- https:
    hostnames:
    - "*"
- http:
    hostnames: ["metrics.helpdesk.invalid"]
    effects:
      replaceHeaders:
      - header: Authorization
        prefix: "Bearer "
        credentialUri: ate-secret://k8s.io/default/helpdesk/metrics/token
- tlsPassthrough:
    hostnames: ["github.com"]
    ports:
      all: {}
- tlsPassthrough:
    hostnames:
    - "*.openai.com"
    - "pypi.org"
    ports:
      numbers: [443]
- https:
    hostnames: ["api.openai.com", "*.helpdesk.invalid"]
    effects:
      replaceHeaders:
      - header: Authorization
        prefix: "Bearer "
        credentialUri: ate-secret://k8s.io/default/helpdesk/openai/key
"""

CLEAN = """\
metadata:
  atespace: notes
  name: summariser
snapshotConfig:
  preferredFidelity: SNAPSHOT_FIDELITY_MEMORY
containers:
- name: app
  image: registry.invalid/summariser@sha256:0000000000000000000000000000000000000000000000000000000000000000
  env:
  - name: ANTHROPIC_API_KEY
    value: placeholder
goldenEgressPolicy:
  rules:
  - https:
      hostnames: [api.anthropic.com]
      effects:
        replaceHeaders:
        - header: x-api-key
          credentialUri: ate-secret://k8s.io/default/notes/anthropic/api-key
  - tlsPassthrough:
      hostnames: [registry.npmjs.org]
      ports:
        numbers: [443]
"""

ROLE = """\
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: reader
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get"]
"""

MESH = """\
rules:
- http:
    hostnames: ["edge.mesh.svc.cluster.local"]
    effects:
      replaceHeaders:
      - header: X-Mesh-Auth
        credentialUri: ate-secret://k8s.io/default/mesh/edge/token
"""

FILES = {
    "deploy/triage-template.yaml.tmpl": TEMPLATE,
    "deploy/mesh-policy.yaml": MESH,
    "deploy/egress-policy.yaml": POLICY,
    "deploy/summariser.yaml": CLEAN,
    "deploy/role.yaml": ROLE,
    "tests/fixtures/substrate/agent.yaml": TEMPLATE,
}


def scan(root, *rules):
    args = ["scan", root, "--json", "--no-config"]
    for r in rules:
        args += ["--rule", r]
    return json.loads(run_cli(*args).stdout)["findings"]


class Project(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.root = tempfile.mkdtemp()
        for rel, text in FILES.items():
            os.makedirs(os.path.join(cls.root, os.path.dirname(rel)), exist_ok=True)
            with open(os.path.join(cls.root, rel), "w") as fh:
                fh.write(text)
        cls.found = scan(cls.root, "JH709", "JH710", "JH713")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.root)

    def at(self, rule, path):
        return sorted((f["line"], f["severity"]) for f in self.found if f["rule"] == rule and f["path"] == path)

    def message(self, rule, path, line):
        return next(f["message"] for f in self.found if (f["rule"], f["path"], f["line"]) == (rule, path, line))

    def test_key_in_the_template(self):
        tmpl = "deploy/triage-template.yaml.tmpl"
        self.assertEqual(self.at("JH713", tmpl), [(12, "major"), (14, "major")])
        self.assertIn("filled in from ${ANTHROPIC_API_KEY} when the template is applied",
                      self.message("JH713", tmpl, 12))
        self.assertIn("is written into the template", self.message("JH713", tmpl, 14))
        self.assertIn("memory snapshots", self.message("JH713", tmpl, 14))
        self.assertNotIn("tk_live", self.message("JH713", tmpl, 14))          # never the value

    def test_test_data_is_minor(self):
        self.assertEqual(self.at("JH713", "tests/fixtures/substrate/agent.yaml"), [(12, "minor"), (14, "minor")])

    def test_keyed_api_behind_passthrough(self):
        self.assertEqual(self.at("JH710", "deploy/triage-template.yaml.tmpl"), [(26, "major")])
        self.assertEqual(self.at("JH710", "deploy/egress-policy.yaml"), [(8, "major"), (18, "major")])
        self.assertIn("cannot inject its API key", self.message("JH710", "deploy/egress-policy.yaml", 18))
        self.assertIn("cleartext HTTP to metrics.helpdesk.invalid",
                      self.message("JH710", "deploy/egress-policy.yaml", 8))

    def test_cleartext_inside_the_cluster_is_minor(self):
        self.assertEqual(self.at("JH710", "deploy/mesh-policy.yaml"), [(5, "minor")])
        self.assertIn("the cluster network past the gateway", self.message("JH710", "deploy/mesh-policy.yaml", 5))
        self.assertTrue(S.cluster_internal("edge.mesh.svc.cluster.local"))
        self.assertTrue(S.cluster_internal("edge.mesh.svc"))
        self.assertFalse(S.cluster_internal("metrics.helpdesk.invalid"))
        self.assertFalse(S.cluster_internal("intranet"))

    def test_broad_egress(self):
        self.assertEqual(self.at("JH709", "deploy/egress-policy.yaml"), [(4, "major"), (15, "minor")])
        self.assertIn("every host (*)", self.message("JH709", "deploy/egress-policy.yaml", 4))
        self.assertIn("covers every port", self.message("JH709", "deploy/egress-policy.yaml", 15))

    def test_quiet_when_clean_or_not_substrate(self):
        for path in ("deploy/summariser.yaml", "deploy/role.yaml"):
            with self.subTest(path=path):
                self.assertEqual([f for f in self.found if f["path"] == path], [])


class ScanRootInsideABuildFolder(unittest.TestCase):
    """A project kept under a folder named out/, build/ or dist/ is scanned; such folders are skipped only inside
    the scan root (before 4.13.0 every file was skipped, silently)."""
    def test_root_under_out_is_scanned_and_inner_dist_is_not(self):
        top = tempfile.mkdtemp()
        try:
            root = os.path.join(top, "out", "helpdesk")
            for rel in ("deploy/egress.yaml", "dist/egress.yaml"):
                os.makedirs(os.path.join(root, os.path.dirname(rel)), exist_ok=True)
                with open(os.path.join(root, rel), "w") as fh:
                    fh.write("rules:\n- https:\n    hostnames:\n    - \"*\"\n")
            self.assertEqual([f["path"] for f in scan(root, "JH709")], ["deploy/egress.yaml"])
        finally:
            shutil.rmtree(top)


class Shapes(unittest.TestCase):
    def test_detection(self):
        self.assertEqual(jh_core.substrate_shape(POLICY), "egress_policy")
        self.assertEqual(jh_core.substrate_shape(TEMPLATE), "actor_template")
        self.assertEqual(jh_core.substrate_shape(CLEAN), "actor_template")
        self.assertIsNone(jh_core.substrate_shape(ROLE))
        self.assertIsNone(jh_core.substrate_shape("containers:\n- name: a\n  image: b\n"))
        self.assertIn("substrate", jh_core.detect_kinds("x/agent.yaml.tmpl", TEMPLATE, "text"))
        self.assertNotIn("substrate", jh_core.detect_kinds("x/agent.txt", TEMPLATE, "text"))

    def test_credential_values(self):
        for name, value, want in (("ANTHROPIC_API_KEY", "${ANTHROPIC_API_KEY}", "rendered"),
                                  ("DB_PASSWORD", "s3cr3t-Pa55w0rd-123", "literal"),
                                  ("OPENAI_API_KEY", "placeholder", None),
                                  ("OPENAI_API_KEY", "sk-EXAMPLE-EXAMPLE-EXAMPLE", None),
                                  ("TOKEN_URL", "https://login.example.invalid/token", None),
                                  ("API_KEY_FILE", "/run/secrets/key", None),
                                  ("SERVICE_TOKEN", "/run/secrets/token", None),
                                  ("GITHUB_TOKEN_ENABLED", "true", None),
                                  ("CLIENT_SECRET_NAME", "helpdesk-oauth-client", None),
                                  ("CURSOR_API_KEY", "crsr_" + "0" * 64, None),
                                  ("AUTH_TOKEN_SERVICE", "https://auth.helpdesk.invalid/v2/token", None),
                                  ("BROKER_PASSWORD", "amqps://agent:hunter2-long-one@mq.helpdesk.invalid/",
                                   "literal"),
                                  ("WORKLOAD_IMAGE", "${WORKLOAD_IMAGE}", None),
                                  ("APP_SECRET", 12345678, None)):
            with self.subTest(name=name, value=value):
                self.assertEqual(S.credential_value(name, value), want)

    def test_keyed_api(self):
        self.assertEqual(S.keyed_api("api.anthropic.com"), "api.anthropic.com")
        self.assertEqual(S.keyed_api("*.anthropic.com"), "api.anthropic.com")
        self.assertEqual(S.keyed_api("my-model.openai.azure.com"), "my-model.openai.azure.com")
        for host in ("*", "*.com", "github.com", "pypi.org", "anthropic.com"):
            with self.subTest(host=host):
                self.assertIsNone(S.keyed_api(host))

    def test_golden_policy_stays_a_template(self):
        self.assertEqual(jh_core.substrate_shape("containers:\n- name: a\n  image: b\ngoldenEgressPolicy:\n  rules:\n"
                                                 "  - https:\n      hostnames: [a.example]\n"), "actor_template")

    def test_snake_case_and_flow_rules(self):
        doc = S.docs("rules:\n- tls_passthrough: {hostnames: [api.openai.com], ports: {numbers: [443]}}\n")[0]
        self.assertEqual([(k, S.hostnames(b)) for k, b in S.rules(doc)], [("tlsPassthrough", ["api.openai.com"])])


class Emit(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        p = run_cli("passport", DEMO, "--emit-sandbox-policy", "substrate")
        assert p.returncode == 0, p.stderr
        cls.out, cls.err = p.stdout, p.stderr

    def test_key_injected_at_the_gateway(self):
        self.assertIn("- https:\n    hostnames:\n    - 'api.openai.com'", self.out)
        self.assertIn("      - header: 'Authorization'\n        prefix: 'Bearer '\n        credentialUri: "
                      "'ate-secret://k8s.io/default/replace-with-namespace/openai-api-key/api-key'", self.out)
        self.assertIn("placeholder value", self.err)

    def test_other_hosts_pass_through_on_their_port(self):
        self.assertIn("- tlsPassthrough:\n    hostnames:", self.out)
        self.assertIn("    - 'registry.npmjs.org'", self.out)
        self.assertIn("      numbers: [443]", self.out)

    def test_unsupported_protocols_and_production_left_out(self):
        self.assertNotIn("ledger-db.prod.internal", self.out)
        self.assertIn("cache:6379: the egress gateway passes only HTTP and TLS", self.err)
        self.assertNotIn("'cache'", self.out)

    def test_count_matches_what_was_written(self):
        written = {ln.split("'")[1] for ln in self.out.splitlines() if ln.startswith("    - '")}
        self.assertIn("%d host(s) allowed" % len(written), self.err)

    def test_its_own_output_is_clean_and_reads_back(self):
        root = tempfile.mkdtemp()
        try:
            with open(os.path.join(root, "egress-policy.yaml"), "w") as fh:
                fh.write(self.out)
            self.assertEqual(scan(root, "JH709", "JH710", "JH713"), [])
        finally:
            shutil.rmtree(root)

        class Item:
            rel, text = "deploy/egress-policy.yaml", self.out
        bounds = jh_egress.boundaries([Item()])
        self.assertEqual([b["tool"] for b in bounds], ["substrate"])
        self.assertIn("api.openai.com", bounds[0]["allow"])

    def test_network_ceiling_from_the_cli(self):
        import jh_ceiling
        top = tempfile.mkdtemp()
        try:
            path = os.path.join(top, "approved.json")
            with open(path, "w") as fh:
                json.dump({"schema": jh_ceiling.SCHEMA, "allow": [{"host": "api.openai.com", "port": 443},
                                                                  {"host": "registry.npmjs.org", "port": 443}]}, fh)
            p = run_cli("passport", DEMO, "--emit-sandbox-policy", "substrate", "--sandbox-network-ceiling", path)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn("'api.openai.com'", p.stdout)
            self.assertIn("'registry.npmjs.org'", p.stdout)
            self.assertNotIn("'pypi.org'", p.stdout)
            self.assertIn("2 host(s) allowed", p.stderr)
        finally:
            shutil.rmtree(top)

    def test_validation_catches_what_the_api_rejects(self):
        for text, problem in (("rules:\n- tlsPassthrough:\n    hostnames: [a.example]\n", "needs port numbers"),
                              ("rules:\n- https:\n    hostnames: ['*']\n", "bad host"),
                              ("rules:\n- https:\n    hostnames: [10.0.0.1]\n", "bad host"),
                              ("rules:\n- https:\n    hostnames: [a.example]\n- https:\n    hostnames: [a.example]\n",
                               "two rules for a.example on port 443"),
                              ("rules:\n- http:\n    hostnames: [a.example]\n    effects:\n      replaceHeaders:\n"
                               "      - header: X\n        credentialUri: ate-secret://k8s.io/a/b\n",
                               "credential effects on a http rule"),
                              ("rules: []\nextra: 1\n", "one document with a rules list")):
            with self.subTest(problem=problem):
                self.assertTrue(any(problem in p for p in jh_fence.validate("substrate", text)),
                                jh_fence.validate("substrate", text))

    def test_template_without_policy_declares_no_boundary(self):
        class Item:
            rel = "deploy/t.yaml"
            text = "metadata:\n  atespace: a\n  name: b\nworkerSelector: {}\ncontainers:\n- name: c\n  image: d\n"
        self.assertEqual(jh_egress.boundaries([Item()]), [])


if __name__ == "__main__":
    unittest.main()
