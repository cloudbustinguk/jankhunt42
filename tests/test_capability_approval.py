"""Exact external approvals, using invented data and temporary Git fixtures."""
import copy
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

import _util
from _util import run_cli
import test_capabilities as fixtures
import jh_capabilities as C
import jh_capability_approval as A
import jh_policy
import jh_views

NOW = datetime(2026, 10, 27, 1, 0, tzinfo=timezone.utc)
SETTINGS = dict(subject_id="fixture-app", approvers=["reviewer-1"], max_lifetime_seconds=7200)


def policy():
    return jh_policy.merge(dict(capability_approvals=SETTINGS), [], [])


def delta():
    return dict(model=C.MODEL, state="complete", base_sha="a" * 40, head_sha="b" * 40,
                context_hash="c" * 64, delta_hash="d" * 64,
                counts=dict(total=1, unknown=0, unchanged_unknown=0, lower_bound=False),
                requests=[dict(id="1" * 64, certainty="supported")], unknowns=[], unchanged_unknowns=[],
                truncation=dict(truncated=False, omitted=0, unknowns_omitted=0, reasons=[]))


def filled(d=None, p=None, clock=NOW):
    d, p = d or delta(), p or policy()
    doc = A.template(d, p, jh_policy.policy_hash(p), clock)
    doc.update(approved_by="reviewer-1", expires_at=(clock + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
               rationale="Reviewed the invented access change")
    return doc


class RecordModel(unittest.TestCase):
    def evaluate(self, record, d=None, p=None):
        d, p = d or delta(), p or policy()
        return A.evaluate(record, d, p, jh_policy.policy_hash(p), now=NOW)

    def test_exact_match_and_replay(self):
        for unused in range(2):
            r = self.evaluate(filled())
            self.assertEqual((r["state"], r["assurance"]), ("accepted", "declared-by-operator"))
            self.assertEqual(r["approved_request_ids"], ["1" * 64])

    def test_each_binding_is_independent(self):
        for key in A.BINDINGS:
            with self.subTest(key=key):
                doc = filled()
                doc[key] = "wrong-binding"
                r = self.evaluate(doc)
                self.assertEqual(r["state"], "invalid")
                self.assertIn(key + "-mismatch", r["reasons"])

    def test_ids_are_exact_complete_and_unique(self):
        for ids in ([], ["2" * 64], ["1" * 64, "2" * 64], ["1" * 64] * 2, ["*"], [True]):
            with self.subTest(ids=ids):
                doc = filled(); doc["approved_request_ids"] = ids
                self.assertEqual(self.evaluate(doc)["state"], "invalid")

    def test_approver_rationale_schema_and_unknown_fields(self):
        for key, value in (("approved_by", "other-reviewer"), ("rationale", " "), ("schema", "other-schema"),
                           ("signature", "invented-unsupported-signature")):
            with self.subTest(key=key):
                doc = filled(); doc[key] = value
                self.assertEqual(self.evaluate(doc)["state"], "invalid")

    def test_expiry_future_lifetime_and_utc_format(self):
        cases = ((NOW - timedelta(hours=2), NOW - timedelta(hours=1)),
                 (NOW + timedelta(minutes=1), NOW + timedelta(hours=1)),
                 (NOW - timedelta(hours=1), NOW + timedelta(hours=2)), (NOW, NOW))
        for issued, expires in cases:
            with self.subTest(issued=issued, expires=expires):
                doc = filled()
                doc.update(issued_at=issued.strftime("%Y-%m-%dT%H:%M:%SZ"), expires_at=expires.strftime("%Y-%m-%dT%H:%M:%SZ"))
                self.assertEqual(self.evaluate(doc)["state"], "invalid")
        for text in ("not-a-date", "2026-10-27T02:00:00+00:00", "2026-13-01T00:00:00Z"):
            doc = filled(); doc["expires_at"] = text
            self.assertEqual(self.evaluate(doc)["state"], "invalid")

    def test_template_has_bindings_and_blank_completion_fields(self):
        p, d = policy(), delta()
        doc = A.template(d, p, jh_policy.policy_hash(p), NOW)
        self.assertEqual(set(doc), A.FIELDS)
        self.assertEqual(doc["approved_request_ids"], ["1" * 64])
        self.assertEqual([doc[k] for k in ("approved_by", "expires_at", "rationale")], ["", "", ""])
        self.assertEqual(self.evaluate(doc)["state"], "invalid")

    def test_template_refuses_incomplete_and_hidden_rows(self):
        for mutate in (lambda d: d.update(state="incomplete"),
                       lambda d: d["truncation"].update(truncated=True),
                       lambda d: d["counts"].update(total=2),
                       lambda d: d["counts"].update(unchanged_unknown=1),
                       lambda d: d["counts"].update(lower_bound=True)):
            d = delta(); mutate(d)
            with self.assertRaises(ValueError):
                A.template(d, policy(), jh_policy.policy_hash(policy()), NOW)

    def test_active_unknowns_never_accepted(self):
        d = delta()
        d.update(unknowns=[dict(id="2" * 64)])
        d["counts"]["unknown"] = 1
        # Bind every current hash and visible concrete ID; only uncertainty remains.
        doc = filled()
        self.assertEqual(self.evaluate(doc, d)["state"], "invalid")
        with self.assertRaises(ValueError):
            A.template(d, policy(), jh_policy.policy_hash(policy()), NOW)

    def test_displayed_subset_cannot_approve_hidden_requests(self):
        d = delta(); doc = filled()
        d["counts"]["total"] = 2
        d["truncation"].update(truncated=True, omitted=1)
        self.assertEqual(self.evaluate(doc, d)["state"], "invalid")

    def test_repository_cannot_add_subject_or_approvers_or_extend_lifetime(self):
        repo = dict(capability_approvals=dict(subject_id="forged-subject", approvers=["reviewer-1", "other-reviewer"],
                                             max_lifetime_seconds=14400))
        p = jh_policy.merge(dict(capability_approvals=SETTINGS), [repo], [])
        self.assertEqual(p["capability_approvals"], SETTINGS)
        doc = filled(p=p); doc["approved_by"] = "other-reviewer"
        self.assertEqual(self.evaluate(doc, p=p)["state"], "invalid")
        p = jh_policy.merge(None, [dict(capability_approvals=SETTINGS)], [])
        with self.assertRaises(ValueError):
            A.template(delta(), p, jh_policy.policy_hash(p), NOW)

    def test_repository_can_restrict_approvers_and_lifetime(self):
        repo = dict(capability_approvals=dict(approvers=[], max_lifetime_seconds=60))
        p = jh_policy.merge(dict(capability_approvals=SETTINGS), [repo], [])
        self.assertEqual(p["capability_approvals"]["approvers"], [])
        self.assertEqual(p["capability_approvals"]["max_lifetime_seconds"], 60)
        self.assertEqual(self.evaluate(filled(), p=p)["state"], "invalid")

    def test_invalid_operator_configuration_cannot_enable_approvals(self):
        for caps in ({}, [], dict(SETTINGS, max_lifetime_seconds=True), dict(SETTINGS, subject_id="*"),
                     dict(SETTINGS, approvers=["*"]), dict(SETTINGS, max_lifetime_seconds=-1)):
            with self.subTest(caps=caps):
                p = jh_policy.merge(dict(capability_approvals=caps), [], [])
                self.assertEqual(self.evaluate(filled(), p=p)["state"], "invalid")


@unittest.skipUnless(shutil.which("git"), "git is not installed")
class CommandAndFiles(unittest.TestCase):
    def setUp(self):
        self.fixture = fixtures.CapabilityChanges()
        self.fixture.setUp()
        self.addCleanup(self.fixture.doCleanups)
        self.root = self.fixture.root
        external = tempfile.TemporaryDirectory(prefix="jh-approval-operator-", dir=_util.ROOT)
        self.addCleanup(external.cleanup)
        self.external = Path(external.name)
        self.policy_path = self.external / "policy.json"
        self.policy_path.write_text(json.dumps(dict(capability_approvals=SETTINGS)))
        self.fixture.write(".jankhunt42.json", json.dumps(dict(passport=dict(owners=["fixture-owner"]))))
        self.base = self.fixture.commit()
        self.fixture.write("app.py", 'import requests\nrequests.get("https://%s:8443/v1")\n' % ".".join(("fixture-api", "invalid")))
        self.fixture.commit()

    def run_passport(self, *args, **kwargs):
        return run_cli("passport", str(self.root), "--base", self.base, "--policy", str(self.policy_path), *args, **kwargs)

    def template(self):
        proc = self.run_passport("--emit-capability-approval")
        self.assertEqual(proc.returncode, 0, proc.stderr)
        doc = json.loads(proc.stdout)
        doc.update(approved_by="reviewer-1", rationale="invented rationale marker",
                   expires_at=(A._utc(doc["issued_at"]) + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"))
        return doc

    def save(self, doc):
        path = self.external / "approval-marker.json"
        path.write_text(json.dumps(doc))
        return path

    def report(self, path=None, *args):
        options = ["--capability-approval", str(path)] if path is not None else []
        proc = self.run_passport("--json", *options, *args)
        self.assertEqual(proc.returncode, 0, proc.stderr)
        return json.loads(proc.stdout)

    def cap(self, report):
        return next(r for r in report["assessment"]["decision"]["rules"] if r["rule"] == "P-CAP-001")

    def test_template_record_gate_and_counts(self):
        before = self.report()
        self.assertEqual(self.cap(before)["outcome"], "review")
        doc = self.template(); path = self.save(doc)
        after = self.report(path)
        self.assertEqual(after["capability_approval"]["state"], "accepted")
        self.assertEqual(self.cap(after)["outcome"], "pass")
        self.assertEqual(before["capability_delta"], after["capability_delta"])
        self.assertEqual(after["lifecycle"]["acceptance"]["state"], "not-supplied")
        self.assertEqual(self.run_passport("--capability-approval", str(path), "--fail-on", "review").returncode, 0)

    def test_policy_inventory_ceiling_and_head_changes_invalidate_record(self):
        doc = self.template(); path = self.save(doc)
        current = json.loads(self.policy_path.read_text()); current["require"] = dict(owner=True)
        self.policy_path.write_text(json.dumps(current))
        self.assertEqual(self.report(path)["capability_approval"]["state"], "invalid")
        self.policy_path.write_text(json.dumps(dict(capability_approvals=SETTINGS)))
        inventory = self.external / "inventory.json"
        inventory.write_text('{"assets":[]}')
        ceiling = self.external / "ceiling.json"
        ceiling.write_text(json.dumps(dict(schema="jankhunt.network-ceiling.v1", allow=[])))
        for options in (("--inventory", str(inventory)), ("--sandbox-network-ceiling", str(ceiling))):
            self.assertEqual(self.report(path, *options)["capability_approval"]["state"], "invalid")
        self.fixture.write("note.txt", "another invented commit\n"); self.fixture.commit()
        self.assertEqual(self.report(path)["capability_approval"]["state"], "invalid")

    def test_template_and_record_refuse_flood_and_incomplete_comparison(self):
        text = "import requests\n" + "".join('requests.get("https://%s/v1")\n' % ".".join(("fixture%d" % i, "invalid")) for i in range(101))
        self.fixture.write("app.py", text); self.fixture.commit()
        report = self.report()
        self.assertEqual(report["capability_delta"]["counts"]["total"], 101)
        self.assertEqual(self.run_passport("--emit-capability-approval").returncode, 2)
        doc = filled()
        p = report["assessment"]["decision"]["policy"]
        doc.update(A._bindings(report["capability_delta"], SETTINGS, p["hash"]))
        doc.update(issued_at=A._now().strftime("%Y-%m-%dT%H:%M:%SZ"),
                   expires_at=(A._now() + timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                   approved_request_ids=[r["id"] for r in report["capability_delta"]["requests"]])
        r = self.report(self.save(doc))
        self.assertEqual(self.cap(r)["outcome"], "review")
        self.assertEqual(r["capability_approval"]["state"], "invalid")
        self.assertEqual(self.run_passport("--emit-capability-approval", "--max-files", "1").returncode, 2)

    def test_template_refuses_unknowns(self):
        self.fixture.write(".mcp.json", '{"mcpServers":{"helper":{"command":"invented-helper"}}}')
        self.fixture.commit()
        proc = self.run_passport("--emit-capability-approval")
        self.assertEqual(proc.returncode, 2)
        self.assertIn("active-unknowns", proc.stderr)
        self.assertEqual(proc.stdout, "")

    def test_record_is_external_no_links_and_subdirectory_boundary(self):
        path = self.save(self.template())
        internal = self.root / "record.json"; internal.write_text(path.read_text())
        sub = self.root / "sub"; sub.mkdir()
        for root in (self.root, sub):
            with self.assertRaisesRegex(ValueError, "outside"):
                A.load(str(internal), str(root))
        alias = self.external / "alias.json"; alias.symlink_to(path)
        with self.assertRaisesRegex(ValueError, "symlink"):
            A.load(str(alias), str(self.root))
        linked = self.external / "hardlink.json"; os.link(path, linked)
        with self.assertRaisesRegex(ValueError, "hard links"):
            A.load(str(path), str(self.root))

    def test_duplicate_keys_oversized_and_nonregular_inputs(self):
        path = self.external / "invalid.json"
        path.write_text('{"schema":"first","schema":"second"}')
        with self.assertRaisesRegex(ValueError, "unambiguous"):
            A.load(str(path), str(self.root))
        path.write_text(" " * 65537)
        with self.assertRaisesRegex(ValueError, "size limit"):
            A.load(str(path), str(self.root))
        fifo = self.external / "fifo"; os.mkfifo(fifo)
        with self.assertRaisesRegex(ValueError, "regular file"):
            A.load(str(fifo), str(self.root))

    def test_stale_record_is_reported_and_gate_fails(self):
        doc = self.template(); doc["context_hash"] = "0" * 64
        path = self.save(doc); report = self.report(path)
        self.assertEqual(report["capability_approval"]["state"], "invalid")
        self.assertEqual(self.cap(report)["outcome"], "review")
        self.assertEqual(self.run_passport("--capability-approval", str(path), "--fail-on", "review").returncode, 1)

    def test_stronger_outcome_and_redaction_and_views(self):
        config = json.loads(self.policy_path.read_text())
        config["max_exposure"] = "Low"
        config["actions"] = {"P-EXP-001": "block"}
        self.policy_path.write_text(json.dumps(config))
        path = self.save(self.template()); report = self.report(path)
        self.assertEqual(self.cap(report)["outcome"], "pass")
        self.assertEqual(report["assessment"]["decision"]["result"], "block")
        self.assertIn("Access change accepted", jh_views.passport_tty(report, color=False))
        md = self.run_passport("--capability-approval", str(path), "--md")
        self.assertIn("Access change accepted", md.stdout)
        redacted = self.report(path, "--redact")
        text = json.dumps(redacted)
        for marker in ("reviewer-1", "fixture-app", "invented rationale marker", "approval-marker"):
            self.assertNotIn(marker, text)

    def test_template_needs_external_policy_and_clock_is_real(self):
        proc = run_cli("passport", str(self.root), "--base", self.base, "--emit-capability-approval")
        self.assertEqual(proc.returncode, 2)
        proc = self.run_passport("--emit-capability-approval", env={"SOURCE_DATE_EPOCH": "1"})
        self.assertEqual(proc.returncode, 0, proc.stderr)
        self.assertGreater(A._utc(json.loads(proc.stdout)["issued_at"]).year, 1970)

    def test_cli_modes(self):
        for options in (("--emit-capability-approval", "--json"), ("--emit-capability-approval", "--redact"),
                        ("--emit-capability-approval", "--capability-approval", "not-read")):
            self.assertEqual(self.run_passport(*options).returncode, 2)
        for option in ("--emit-capability-approval", "--capability-approval"):
            args = [option] + (["not-read"] if option == "--capability-approval" else [])
            self.assertEqual(run_cli("passport", str(self.root), *args).returncode, 2)
