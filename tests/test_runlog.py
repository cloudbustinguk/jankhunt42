"""passport --sandbox-log (4.14.0): an agent sandbox's own network log (OpenShell OCSF JSON, Agent Substrate egress
gateway) compared with what the repository declares (P-RUN-003). Invented logs and hosts only."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli
import jh_runlog as R

OCSF_ALLOWED = {"class_uid": 4001, "action_id": 1, "action": "Allowed", "disposition_id": 1,
                "dst_endpoint": {"domain": "api.helpdesk.invalid", "port": 443},
                "firewall_rule": {"name": "helpdesk_api", "type": "opa"},
                "actor": {"process": {"name": "/usr/bin/node", "pid": 57}}, "metadata": {"version": "1.8.0"}}
OCSF_DENIED = {"class_uid": 4001, "action_id": 2, "action": "Denied", "disposition_id": 2, "disposition": "Blocked",
               "dst_endpoint": {"domain": "paste.attacker.invalid", "ip": "198.18.0.2", "port": 443},
               "actor": {"process": {"name": "/usr/bin/curl", "pid": 2187, "cmd_line": "curl https://paste.attacker.invalid"}}}
SUBSTRATE_DENIED = {"time": "2026-11-06T21:41:00Z", "level": "WARN", "msg": "egress denied: no rule allows the destination",
                    "actor": {"type": "ateapi.Actor", "atespace": "helpdesk", "name": "triage"}, "leg": "egress-tls-mitm",
                    "method": "POST", "host": "exfil.attacker.invalid", "dialedPort": 443,
                    "sni": "exfil.attacker.invalid", "rule": -1}


def ocsf_line(obj):
    return "2026-11-06T21:40:01.123Z OCSF-JSON " + json.dumps(obj)


class Parse(unittest.TestCase):
    def test_openshell_stderr_and_jsonl(self):
        text = "\n".join([ocsf_line(OCSF_ALLOWED),
                          "2026-11-06T21:40:02.000Z OCSF NET:OPEN ALLOWED /usr/bin/node api.helpdesk.invalid:443",
                          json.dumps(OCSF_DENIED), json.dumps({"class_uid": 6002, "activity_id": 1}), ""])
        got = R.parse(text)
        self.assertEqual((got["lines"], got["unparsed"]), (4, 2))
        self.assertEqual([(e["source"], e["endpoint"], e["outcome"], e["process"]) for e in got["events"]],
                         [("openshell", ("api.helpdesk.invalid", 443), "allowed", "/usr/bin/node"),
                          ("openshell", ("paste.attacker.invalid", 443), "denied", "/usr/bin/curl")])
        self.assertEqual(got["events"][0]["rule"], "helpdesk_api")

    def test_outcome_from_disposition_only_and_none_without_one(self):
        only_disposition = {"class_uid": 4002, "disposition_id": 2, "dst_endpoint": {"domain": "a.invalid", "port": 80}}
        no_outcome = {"class_uid": 4001, "dst_endpoint": {"domain": "b.invalid", "port": 443}}
        conflict = {"class_uid": 4001, "action_id": 1, "disposition_id": 2, "dst_endpoint": {"domain": "c.invalid", "port": 443}}
        got = R.parse("\n".join(json.dumps(o) for o in (only_disposition, no_outcome, conflict)))
        self.assertEqual([(e["endpoint"], e["outcome"]) for e in got["events"]],
                         [(("a.invalid", 80), "denied"), (("c.invalid", 443), "denied")])
        self.assertEqual(got["unparsed"], 1)

    def test_substrate_gateway_lines(self):
        restored = {"time": "t", "level": "INFO", "msg": "Actor restored", "actor": {"atespace": "a", "name": "b"}}
        allowed = dict(SUBSTRATE_DENIED, level="DEBUG", msg="egress allowed", host="api.helpdesk.invalid:8443",
                       dialedPort=None)
        got = R.parse("\n".join(json.dumps(o) for o in (SUBSTRATE_DENIED, restored, allowed)))
        self.assertEqual([(e["endpoint"], e["outcome"], e["process"]) for e in got["events"]],
                         [(("exfil.attacker.invalid", 443), "denied", "helpdesk/triage"),
                          (("api.helpdesk.invalid", 8443), "allowed", "helpdesk/triage")])
        self.assertEqual(got["events"][0]["rule"], "no rule allows the destination")

    def test_text_before_json_is_not_a_record(self):
        got = R.parse('level=warn msg="egress denied" {"msg": "egress denied: x", "host": "a.invalid"}')
        self.assertEqual((got["events"], got["unparsed"]), ([], 1))

    def test_hostile_and_odd_destinations(self):
        for host, want in (("evil.invalid/../x", None), ("a b.invalid", None), ("<script>.invalid", None),
                           ("exämple.invalid", None), ("API.Helpdesk.Invalid", ("api.helpdesk.invalid", None)),
                           ("[2001:db8::1]:8443", ("2001:db8::1", 8443)), ("198.18.0.2", ("198.18.0.2", None)),
                           ("a.invalid:99999", None), ("", None)):
            with self.subTest(host=host):
                self.assertEqual(R._endpoint(host), want)
        self.assertEqual(R._endpoint("a.invalid", True), ("a.invalid", None))       # a bool is not a port


class Project(unittest.TestCase):
    """A small app that calls api.helpdesk.invalid, with a committed OpenShell policy that also allows
    docs.helpdesk.invalid, and two logs kept outside it."""

    @classmethod
    def setUpClass(cls):
        cls.top = tempfile.mkdtemp()
        cls.root = os.path.join(cls.top, "app")
        os.makedirs(os.path.join(cls.root, "sandbox"))
        with open(os.path.join(cls.root, "app.py"), "w") as fh:
            fh.write('import requests\n\nrequests.get("https://api.helpdesk.invalid/v1/tickets")\n')
        with open(os.path.join(cls.root, "requirements.txt"), "w") as fh:
            fh.write("requests==2.32.3\n")
        with open(os.path.join(cls.root, "sandbox", "policy.yaml"), "w") as fh:
            fh.write("version: 1\nnetwork_policies:\n  docs:\n    endpoints:\n      - host: docs.helpdesk.invalid\n"
                     "        port: 443\n    binaries:\n      - path: /usr/bin/python3\n")
        cls.openshell = os.path.join(cls.top, "openshell.log")
        with open(cls.openshell, "w") as fh:
            fh.write("\n".join([
                ocsf_line(OCSF_ALLOWED), ocsf_line(OCSF_ALLOWED), ocsf_line(OCSF_DENIED),
                json.dumps(dict(OCSF_ALLOWED, dst_endpoint={"domain": "docs.helpdesk.invalid", "port": 443})),
                json.dumps(dict(OCSF_ALLOWED, dst_endpoint={"domain": "pypi.org", "port": 443})),
                json.dumps(dict(OCSF_ALLOWED, dst_endpoint={"domain": "telemetry.vendor.invalid", "port": 443})),
                json.dumps(dict(OCSF_DENIED, dst_endpoint={"domain": "api.helpdesk.invalid", "port": 443})),
                json.dumps(dict(OCSF_DENIED, dst_endpoint={"domain": "evil.invalid/../x", "port": 443}))]) + "\n")
        cls.substrate = os.path.join(cls.top, "gateway.log")
        with open(cls.substrate, "w") as fh:
            fh.write(json.dumps(SUBSTRATE_DENIED) + "\n")

    @classmethod
    def tearDownClass(cls):
        shutil.rmtree(cls.top)

    def passport(self, *args):
        p = run_cli("passport", self.root, "--json", *args)
        self.assertIn(p.returncode, (0, 1), p.stderr)
        return json.loads(p.stdout)

    def rule(self, p):
        return next(r for r in p["assessment"]["decision"]["rules"] if r["rule"] == "P-RUN-003")

    def test_undeclared_destinations_need_review(self):
        p = self.passport("--sandbox-log", self.openshell, "--sandbox-log", self.substrate)
        log = p["sandbox_log"]
        self.assertEqual((log["state"], log["bound_to_tree"], log["sources"]), ("observed", False, ["openshell", "substrate"]))
        self.assertEqual([(r["target"], r["outcome"], r["count"]) for r in log["undeclared"]],
                         [("telemetry.vendor.invalid:443", "allowed", 1), ("exfil.attacker.invalid:443", "denied", 1),
                          ("paste.attacker.invalid:443", "denied", 1)])
        self.assertEqual(log["counts"]["no_destination"], 1)                 # the hostile name never became a row
        self.assertEqual([r["target"] for r in log["blocked_needed"]], ["api.helpdesk.invalid:443"])
        rule = self.rule(p)
        self.assertEqual(rule["outcome"], "review")
        self.assertIn("3 destination(s) the repository does not declare (1 reached", rule["message"])

    def test_citizen_profile_blocks(self):
        p = self.passport("--sandbox-log", self.substrate, "--profile", "citizen")
        self.assertEqual(self.rule(p)["outcome"], "block")

    def test_declared_by_map_policy_and_ceiling(self):
        import jh_ceiling
        ceiling = os.path.join(self.top, "approved.json")
        with open(ceiling, "w") as fh:
            json.dump({"schema": jh_ceiling.SCHEMA, "allow": [{"host": "telemetry.vendor.invalid", "port": 443},
                                                              {"host": "paste.attacker.invalid", "port": 443},
                                                              {"host": "exfil.attacker.invalid", "port": 443}]}, fh)
        p = self.passport("--sandbox-log", self.openshell, "--sandbox-log", self.substrate,
                          "--sandbox-network-ceiling", ceiling)
        declared = {r["target"]: r["declared"] for r in p["sandbox_log"]["destinations"]}
        self.assertTrue(declared["api.helpdesk.invalid:443"])               # the map
        self.assertTrue(declared["docs.helpdesk.invalid:443"])              # the committed policy
        self.assertTrue(declared["pypi.org:443"])                           # the registry the repository installs from
        self.assertTrue(declared["telemetry.vendor.invalid:443"])           # the operator ceiling
        self.assertEqual(self.rule(p)["outcome"], "pass")
        self.assertIn("a quiet log proves nothing", self.rule(p)["message"])

    def test_no_log_and_markdown(self):
        self.assertEqual(self.rule(self.passport())["message"], "no sandbox log supplied")
        md = run_cli("passport", self.root, "--md", "--sandbox-log", self.openshell).stdout
        self.assertIn("## Sandbox log", md)
        self.assertIn("Blocked, but the repository needs it: api.helpdesk.invalid:443", md)
        self.assertIn("best-effort", md)
        html = run_cli("passport", self.root, "--html", "--sandbox-log", self.openshell).stdout
        self.assertIn('"sandbox_log": {', html)
        self.assertIn("SL=P.sandbox_log", html)

    def test_redacted_passport_names_no_destination(self):
        p = run_cli("passport", self.root, "--json", "--redact", "--sandbox-log", self.openshell,
                    "--sandbox-log", self.substrate).stdout
        self.assertNotIn("attacker.invalid", p)
        self.assertNotIn("/usr/bin/curl", p)
        self.assertIn("destination-1", p)

    def test_log_inside_the_repository_is_refused(self):
        inside = os.path.join(self.root, "agent.log")
        shutil.copy(self.substrate, inside)
        try:
            p = run_cli("passport", self.root, "--json", "--sandbox-log", inside)
            self.assertEqual(p.returncode, 2)
            self.assertIn("outside the scanned repository", p.stderr)
        finally:
            os.remove(inside)

    def test_distinct_destinations_are_capped(self):
        from unittest import mock
        with mock.patch.object(R, "MAX_DESTINATIONS", 2):
            ev = R.evidence([self.openshell], self.root, None)
        self.assertEqual(ev["counts"]["destinations"], 2)
        self.assertGreater(ev["counts"]["beyond_limit"], 0)

    def test_too_many_logs(self):
        with self.assertRaises(ValueError):
            R.evidence([self.substrate] * (R.MAX_LOGS + 1), self.root, None)


if __name__ == "__main__":
    unittest.main()
