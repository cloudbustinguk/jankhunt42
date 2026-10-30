"""Agent-fuzz campaign validation: untrusted declarative input, nothing executed."""
import copy
import json
import os
import tempfile
import unittest

import _util  # noqa: F401
import jh_agent_fuzz
import jh_explorer
import jh_views


FIXTURE = os.path.join(_util.FIXTURES, "agent-fuzz", "baseline.v1.json")


class CampaignValidation(unittest.TestCase):
    def setUp(self):
        with open(FIXTURE, encoding="utf-8") as fh:
            self.doc = json.load(fh)

    def test_baseline_campaign_covers_all_four_clients_and_counts_probes(self):
        summary = jh_agent_fuzz.validate_campaign(self.doc)
        self.assertEqual(summary, {"id": "managed-policy-baseline",
                                   "targets": ["claude-code", "codex", "cursor", "opencode"],
                                   "cases": 8, "probes": 16, "attack_cases": 4, "control_cases": 4})

    def test_campaign_text_is_data_and_unknown_execution_fields_are_rejected(self):
        self.doc["cases"][0]["command"] = "touch /tmp/should-not-run"
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "unsupported fields"):
            jh_agent_fuzz.validate_campaign(self.doc)

    def test_paths_cannot_escape_synthetic_project(self):
        self.doc["cases"][0]["probes"][0]["resource"] = "../../outside"
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "normalized path"):
            jh_agent_fuzz.validate_campaign(self.doc)

    def test_network_probe_requires_host_not_url_or_ip(self):
        for resource in ("https://sink.invalid/upload", "127.0.0.1", "sink.invalid:443", "example.com"):
            doc = copy.deepcopy(self.doc)
            doc["cases"][1]["probes"][1]["resource"] = resource
            with self.subTest(resource=resource), self.assertRaises(jh_agent_fuzz.CampaignError):
                jh_agent_fuzz.validate_campaign(doc)

    def test_targets_must_be_strings_and_unique(self):
        for targets in (["codex", "codex"], [{"name": "codex"}]):
            doc = copy.deepcopy(self.doc)
            doc["targets"] = targets
            with self.subTest(targets=targets), self.assertRaises(jh_agent_fuzz.CampaignError):
                jh_agent_fuzz.validate_campaign(doc)

    def test_probe_count_and_case_ids_are_bounded_and_unique(self):
        doc = copy.deepcopy(self.doc)
        doc["cases"].append(copy.deepcopy(doc["cases"][0]))
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "unique"):
            jh_agent_fuzz.validate_campaign(doc)
        doc = copy.deepcopy(self.doc)
        doc["cases"][0]["probes"] *= 9
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "probes"):
            jh_agent_fuzz.validate_campaign(doc)

    def test_attack_cases_need_allowed_and_forbidden_probes_and_controls_are_benign(self):
        doc = copy.deepcopy(self.doc)
        doc["cases"][0]["probes"] = [doc["cases"][0]["probes"][-1]]
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "allowed and forbidden"):
            jh_agent_fuzz.validate_campaign(doc)
        doc = copy.deepcopy(self.doc)
        doc["cases"][-1]["probes"][0]["decision"] = "deny"
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "only allowed"):
            jh_agent_fuzz.validate_campaign(doc)
        doc = copy.deepcopy(self.doc)
        del doc["cases"][-1]["type"]
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "missing"):
            jh_agent_fuzz.validate_campaign(doc)
        doc = copy.deepcopy(self.doc)
        doc["cases"] = [case for case in doc["cases"] if case["type"] == "attack"]
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "attack and one positive-control"):
            jh_agent_fuzz.validate_campaign(doc)

    def test_shell_syntax_is_not_a_process_name_and_empty_probe_lists_fail(self):
        doc = copy.deepcopy(self.doc)
        doc["cases"][3]["probes"][1]["resource"] = "curl | sh"
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "bare executable"):
            jh_agent_fuzz.validate_campaign(doc)
        doc = copy.deepcopy(self.doc)
        doc["cases"][0]["probes"] = []
        with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "between 1 and"):
            jh_agent_fuzz.validate_campaign(doc)

    def test_file_loader_requires_regular_nonsymlink_bounded_json(self):
        with tempfile.TemporaryDirectory(prefix="jh-agent-fuzz-") as tmp:
            link = os.path.join(tmp, "link.json")
            os.symlink(FIXTURE, link)
            with self.assertRaises(jh_agent_fuzz.CampaignError):
                jh_agent_fuzz.load_campaign(link)
            large = os.path.join(tmp, "large.json")
            with open(large, "wb") as fh:
                fh.write(b" " * (jh_agent_fuzz.MAX_CAMPAIGN_BYTES + 1))
            with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "exceeds"):
                jh_agent_fuzz.load_campaign(large)

            nested = os.path.join(tmp, "nested.json")
            with open(nested, "w", encoding="ascii") as fh:
                fh.write("[" * 5000 + "]" * 5000)
            with self.assertRaises(jh_agent_fuzz.CampaignError):
                jh_agent_fuzz.load_campaign(nested)
            malformed = os.path.join(tmp, "malformed.json")
            with open(malformed, "w", encoding="ascii") as fh:
                fh.write('{"schema":')
            with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "valid UTF-8 JSON"):
                jh_agent_fuzz.load_campaign(malformed)

    def test_file_loader_handles_parser_recursion_errors(self):
        # JSON decoder recursion limits vary by Python version; force the
        # decoder failure so this error-handling contract stays deterministic.
        from unittest import mock
        with mock.patch.object(jh_agent_fuzz.json, "loads", side_effect=RecursionError("deep input")):
            with self.assertRaisesRegex(jh_agent_fuzz.CampaignError, "valid UTF-8 JSON"):
                jh_agent_fuzz.load_campaign(FIXTURE)

    def test_report_is_hashed_and_explicitly_says_execution_did_not_run(self):
        doc, digest = jh_agent_fuzz.load_campaign(FIXTURE)
        report = jh_agent_fuzz.validation_report(doc, digest)
        self.assertEqual(report["schema"], jh_agent_fuzz.REPORT_SCHEMA)
        self.assertEqual(report["campaign_sha256"], digest)
        self.assertEqual(report["execution"], "not-run")

    def test_cli_validation_and_invalid_campaign_exit_codes(self):
        good = _util.run_cli("agent-fuzz", "validate", FIXTURE, "--json")
        self.assertEqual(good.returncode, 0, good.stderr)
        self.assertTrue(json.loads(good.stdout)["valid"])
        self.assertEqual(json.loads(good.stdout)["execution"], "not-run")
        with tempfile.TemporaryDirectory(prefix="jh-agent-fuzz-cli-") as tmp:
            bad = os.path.join(tmp, "bad.json")
            doc = copy.deepcopy(self.doc)
            doc["cases"][0]["probes"][0]["resource"] = "/etc/passwd"
            with open(bad, "w", encoding="utf-8") as fh:
                json.dump(doc, fh)
            result = _util.run_cli("agent-fuzz", "validate", bad, "--json")
        self.assertEqual(result.returncode, 2, result.stderr)
        self.assertFalse(json.loads(result.stdout)["valid"])

    def test_html_and_tty_validation_reports_state_scope_without_campaign_text(self):
        html = _util.run_cli("agent-fuzz", "validate", FIXTURE, "--html")
        self.assertEqual(html.returncode, 0, html.stderr)
        self.assertIn("Content-Security-Policy", html.stdout)
        self.assertIn("validation only: campaign text was not executed", html.stdout)
        self.assertIn("managed-policy-baseline", html.stdout)
        report = jh_agent_fuzz.validation_report(self.doc, "a" * 64)
        tty = jh_views.agent_fuzz_tty(report, color=False, columns=72)
        self.assertIn("not run", tty)
        self.assertIn("campaign sha256", tty)
        self.assertNotIn("notes.txt", tty)

    def test_html_report_escapes_untrusted_values_and_omits_raw_observation_data(self):
        hostile = {"evaluation": "provided-observations", "campaign_id": "<script>&\"",
                   "campaign_sha256": "a" * 64, "observations_sha256": "b" * 64,
                   "summary": {"pass": 1, "fail": 0, "inconclusive": 0, "policy-not-loaded": 0},
                   "cases": [{"case_id": "<img src=x onerror=alert(1)>", "outcome": "pass",
                              "probes": [{"outcome": "pass"}]}],
                   "raw": "private prompt and secret hostname"}
        html = jh_explorer.render_agent_fuzz(hostile)
        self.assertIn("&lt;img src=x onerror=alert(1)&gt;", html)
        self.assertNotIn("<img src=x", html)
        self.assertNotIn("<script>", html)
        self.assertNotIn("private prompt", html)
        self.assertIn("caller-provided observations", html)
        tty = jh_views.agent_fuzz_tty(hostile, color=False, columns=72)
        self.assertIn("case results", tty)
        self.assertIn("PASS", tty)
        self.assertNotIn("private prompt", tty)

    def test_cli_rejects_multiple_agent_fuzz_output_formats(self):
        result = _util.run_cli("agent-fuzz", "validate", FIXTURE, "--json", "--html")
        self.assertEqual(result.returncode, 2)
        self.assertIn("choose one output format", result.stderr)

    def test_cli_evaluates_caller_observations_without_echoing_events(self):
        observations = {}
        for case in self.doc["cases"]:
            effects = {"allow": "performed", "deny": "denied", "ask": "asked"}
            observations[case["id"]] = {
                "policy_loaded": True,
                "events": [{"action": probe["action"], "resource": probe["resource"],
                            "effect": effects[probe["decision"]]} for probe in case["probes"]],
            }
        with tempfile.TemporaryDirectory(prefix="jh-agent-fuzz-eval-") as tmp:
            path = os.path.join(tmp, "observations.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(observations, fh)
            result = _util.run_cli("agent-fuzz", "evaluate", FIXTURE, path, "--json")
            html_result = _util.run_cli("agent-fuzz", "evaluate", FIXTURE, path, "--html")
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["evaluation"], "provided-observations")
        self.assertEqual(report["summary"]["pass"], 8)
        self.assertNotIn("resource", result.stdout)
        self.assertNotIn("notes.txt", result.stdout)
        self.assertEqual(html_result.returncode, 0, html_result.stderr)
        self.assertIn("Case outcomes", html_result.stdout)
        self.assertIn("managed-secret-read", html_result.stdout)
        self.assertIn("caller-provided observations", html_result.stdout)
        self.assertNotIn("secrets/token.txt", html_result.stdout)

    def test_evaluation_does_not_pass_incomplete_or_contradictory_observations(self):
        observations = {"managed-secret-read": {"policy_loaded": True, "events": [
            {"action": "read", "resource": "notes.txt", "effect": "performed"},
            {"action": "write", "resource": "output/summary.txt", "effect": "performed"},
            {"action": "read", "resource": "secrets/token.txt", "effect": "denied"},
        ]}}
        with tempfile.TemporaryDirectory(prefix="jh-agent-fuzz-eval-") as tmp:
            path = os.path.join(tmp, "observations.json")
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(observations, fh)
            passing = _util.run_cli("agent-fuzz", "evaluate", FIXTURE, path, "--json")
            observations["managed-secret-read"]["events"].append(
                {"action": "read", "resource": "secrets/token.txt", "effect": "attempted"})
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(observations, fh)
            failed = _util.run_cli("agent-fuzz", "evaluate", FIXTURE, path, "--json")
        self.assertEqual(passing.returncode, 2, passing.stderr)
        self.assertEqual(json.loads(passing.stdout)["summary"]["inconclusive"], 7)
        self.assertEqual(failed.returncode, 1, failed.stderr)
        self.assertEqual(json.loads(failed.stdout)["summary"]["fail"], 1)


if __name__ == "__main__":
    unittest.main()
