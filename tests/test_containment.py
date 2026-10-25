"""Static containment evidence (2.6.0): agent-branch CI, agent sandbox and dev
container rules, package sources and allowed registries, change control on
the default branch, the citizen pull-request gate recipe, and precision
fixes from the second soak trial."""
import json
import os
import shutil
import tempfile
import unittest

import _util
from _util import run_cli
import jh_change
import jh_core
import jh_egress
import jh_graph
import jh_map
import jh_hcl
import jh_policy
import jh_registry
import jh_rules
import jh_yaml

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PIPE = "| " + "bash"                      # assembled so this file does not match JH111 itself


class Item:
    def __init__(self, rel, text):
        self.rel, self.text = rel, text


def scan(files):
    sources = [jh_core.source_from_text(rel, "/x/" + rel, text) for rel, text in files.items()]
    return jh_rules.scan_sources([s for s in sources if s]).findings


def hits(files, rule):
    return sorted((f.path, f.line, f.severity) for f in scan(files) if f.rule == rule)


class AgentBranchCI(unittest.TestCase):
    def test_push_to_any_branch_with_secrets_or_write_token(self):
        files = {
            ".github/workflows/any.yml": "on: push\njobs:\n  build:\n    runs-on: x\n    steps:\n      - run: ./d\n"
                                         "        env:\n          T: ${{ secrets.DEPLOY_TOKEN }}\n",
            ".github/workflows/agent.yml": "on:\n  push:\n    branches: ['claude/**']\npermissions:\n  contents: write\n"
                                           "jobs:\n  fmt:\n    runs-on: x\n    steps:\n      - run: git push\n",
            ".github/workflows/ignore.yml": "on:\n  push:\n    branches-ignore: [main]\njobs:\n  j:\n    secrets: inherit\n"
                                            "    uses: o/r/.github/workflows/w.yml@v1\n",
        }
        self.assertEqual([h[0] for h in hits(files, "JH432")],
                         [".github/workflows/agent.yml", ".github/workflows/any.yml", ".github/workflows/ignore.yml"])

    def test_default_branch_read_only_and_guarded_jobs_are_quiet(self):
        files = {
            ".github/workflows/main.yml": "on:\n  push:\n    branches: [main]\njobs:\n  deploy:\n    runs-on: x\n"
                                          "    steps:\n      - run: ./d\n        env:\n          T: ${{ secrets.T }}\n",
            ".github/workflows/ro.yml": "on:\n  push:\n    branches: ['**']\npermissions:\n  contents: read\njobs:\n"
                                        "  t:\n    runs-on: x\n    steps:\n      - run: npm test\n",
            ".github/workflows/tags.yml": "on:\n  push:\n    tags: ['v*']\njobs:\n  r:\n    runs-on: x\n    steps:\n"
                                          "      - run: ./r\n        env:\n          T: ${{ secrets.T }}\n",
            ".github/workflows/guard.yml": "on: [push]\njobs:\n  d:\n    if: github.ref == 'refs/heads/main'\n"
                                           "    runs-on: x\n    steps:\n      - run: ./d\n        env:\n"
                                           "          T: ${{ secrets.T }}\n  p:\n    environment: prod\n    runs-on: x\n"
                                           "    steps:\n      - run: ./p\n        env:\n          K: ${{ secrets.K }}\n",
        }
        self.assertEqual(hits(files, "JH432"), [])


SANDBOX = {
    ".codex/config.toml": ('sandbox_mode = "workspace-write"\n\n[sandbox_workspace_write]\nnetwork_access = true\n\n'
                           '[features.network_proxy.domains]\n"*.amazonaws.com" = "allow"\n"api.github.com" = "allow"\n\n'
                           '[permissions.ci.network]\nmode = "full"\n'),
    ".claude/settings.json": ('{\n  "sandbox": {\n    "excludedCommands": ["docker *", "npm test"],\n'
                              '    "network": {\n      "allowedDomains": ["github.com", "*"]\n    },\n'
                              '    "filesystem": {"allowWrite": ["~/.aws"]}\n  }\n}\n'),
    ".devcontainer/devcontainer.json": ('{\n  // comment\n  "image": "x",\n  "runArgs": ["--network", "host"],\n'
                                        '  "mounts": ["source=/var/run/docker.sock,target=/var/run/docker.sock,type=bind"]\n}\n'),
    "sandbox/policy.yaml": ("version: 1\nfilesystem_policy:\n  read_only: [/usr]\nnetwork_policies:\n  wide:\n"
                            "    endpoints:\n      - host: \"**.amazonaws.com\"\n        port: 443\n        protocol: rest\n"
                            "        access: full\n      - allowed_ips: [\"10.0.0.0/8\"]\n        port: 5432\n"
                            "    binaries:\n      - path: /**\n  gh:\n    endpoints:\n      - host: api.github.com\n"
                            "        port: 443\n        protocol: rest\n        enforcement: audit\n        access: read-only\n"
                            "        tls: skip\n        allow_uninspected_credentials: true\n    binaries:\n"
                            "      - path: /usr/bin/gh\n"),
}
SANDBOX_OK = {
    ".claude/settings.json": '{"sandbox": {"enabled": true, "network": {"allowedDomains": ["github.com", "*.npmjs.org"]}}}\n',
    ".devcontainer/devcontainer.json": '{"image": "x", "runArgs": ["--init"]}\n',
    "sandbox/policy.yaml": ("version: 1\nlandlock:\n  compatibility: hard_requirement\nnetwork_policies:\n  pypi:\n"
                            "    endpoints:\n      - host: pypi.org\n        port: 443\n        protocol: rest\n"
                            "        enforcement: enforce\n        access: read-only\n    binaries:\n      - path: /usr/bin/pip\n"),
    "k8s/policy.yaml": "version: 1\nkind: Something\n",
}


class Sandboxes(unittest.TestCase):
    def test_scope_rule(self):
        got = hits(SANDBOX, "JH709")
        self.assertEqual({p for p, _, _ in got}, {".codex/config.toml", ".claude/settings.json", "sandbox/policy.yaml"})
        self.assertEqual(len([g for g in got if g[0] == ".codex/config.toml"]), 3)
        self.assertGreaterEqual(len([g for g in got if g[0] == "sandbox/policy.yaml"]), 4)

    def test_enforcement_rule(self):
        got = hits(SANDBOX, "JH710")
        sev = {(line, s) for _, line, s in got}
        self.assertIn((2, "minor"), sev)                    # no landlock section
        self.assertEqual(len([g for g in got if g[2] == "major"]), 3)   # audit, tls skip, uninspected credentials

    def test_devcontainer_rule(self):
        self.assertEqual([h[0] for h in hits(SANDBOX, "JH711")], [".devcontainer/devcontainer.json"] * 2)

    def test_safe_configs_are_quiet(self):
        for rule in ("JH709", "JH710", "JH711"):
            self.assertEqual(hits(SANDBOX_OK, rule), [], rule)

    def test_sandbox_policy_kind(self):
        sf = jh_core.source_from_text("p.yaml", "/x/p.yaml", SANDBOX["sandbox/policy.yaml"])
        self.assertIn("sandbox_policy", sf.kinds)
        sf = jh_core.source_from_text("p.yaml", "/x/p.yaml", "version: 1\nservices: {}\n")
        self.assertNotIn("sandbox_policy", sf.kinds)


class Hcl(unittest.TestCase):
    def test_nested_blocks_strings_and_heredocs(self):
        text = ('# a { comment\nresource "github_repository_ruleset" "m" {\n  name = "x ${var.y}"\n'
                '  rules {\n    pull_request {\n      required_approving_review_count = 2\n    }\n'
                '    required_status_checks {\n      required_check { context = "ci" }\n'
                '      required_check {\n        context = "lint"\n      }\n    }\n  }\n'
                '  bypass_actors {\n    actor_type = "Integration"\n  }\n  bypass_actors {\n    actor_type = "Team"\n  }\n'
                '  policy = <<EOT\n{ "}": 1 }\nEOT\n}\n')
        (r,) = jh_hcl.resources(text)
        rules = jh_hcl.first(r["body"], "rules")
        self.assertEqual(jh_hcl.as_int(jh_hcl.first(rules, "pull_request")["required_approving_review_count"]), 2)
        self.assertEqual([jh_hcl.as_str(c["context"]) for c in jh_hcl.first(rules, "required_status_checks")["required_check"]],
                         ["ci", "lint"])
        self.assertEqual([jh_hcl.as_str(a["actor_type"]) for a in r["body"]["bypass_actors"]], ["Integration", "Team"])
        self.assertEqual(jh_hcl.as_list('["a", "b", var.c]'), ["a", "b", "var.c"])


class PackageSources(unittest.TestCase):
    ITEMS = [Item("package.json", "{}"),
             Item(".npmrc", "registry=https://registry.internal.example/api/npm/\n@acme:registry=https://npm.pkg.github.com\n"),
             Item("requirements.txt", "--index-url https://pypi.org/simple\n--extra-index-url https://pkgs.example.com/simple\n"),
             Item("build.gradle", "repositories {\n  mavenCentral()\n  maven { url 'https://repo.internal.example/maven' }\n}\n"
                                  "publishing { repositories { maven { url 'https://publish.example/x' } } }\n"),
             Item("App/App.csproj", "<Project/>"),
             Item("nuget.config", '<configuration><packageSources>\n<add key="corp" value="https://nuget.internal.example/v3/index.json" />\n'
                                  "</packageSources></configuration>\n")]

    def test_declared_sources(self):
        eco = jh_registry.collect(self.ITEMS)["ecosystems"]
        self.assertEqual(sorted(eco), ["maven", "npm", "nuget", "pypi"])
        self.assertEqual({s["scope"] for s in eco["npm"]["sources"]}, {"", "@acme"})
        self.assertNotIn("https://publish.example/x/", [s["url"] for s in eco["maven"]["sources"]])
        self.assertEqual(eco["nuget"]["state"], "declared")

    def test_assessment(self):
        a = jh_registry.assess(jh_registry.collect(self.ITEMS),
                               ["https://registry.internal.example/", "repo.internal.example", "nuget.internal.example"])
        self.assertEqual(sorted({(d["ecosystem"], d["url"]) for d in a["disallowed"]}),
                         [("maven", "https://repo.maven.apache.org/maven2/"), ("npm", "https://npm.pkg.github.com/"),
                          ("pypi", "https://pkgs.example.com/simple/"), ("pypi", "https://pypi.org/simple/")])
        a = jh_registry.assess(jh_registry.collect([Item("package.json", "{}")]), ["https://x/"])
        self.assertEqual(a, {"disallowed": [], "unconfigured": ["npm"]})

    def test_gradle_publishing_block_ends(self):
        eco = jh_registry.collect([Item("build.gradle", "publishing {\n  repositories {\n    maven { url 'https://publish.example/x' }\n"
                                                        "  }\n}\nrepositories {\n  maven { url 'https://repo.example/m' }\n}\n")])
        self.assertEqual([s["url"] for s in eco["ecosystems"]["maven"]["sources"]], ["https://repo.example/m/"])

    def test_lockfiles_are_observed(self):
        tmp = tempfile.mkdtemp()
        try:
            with open(os.path.join(tmp, "package-lock.json"), "w") as fh:
                json.dump({"packages": {"node_modules/a": {"resolved": "https://registry.npmjs.org/a/-/a-1.0.0.tgz"},
                                        "node_modules/@s/b": {"resolved": "https://registry.npmjs.org/@s/b/-/b-1.0.0.tgz"}}},
                          fh, indent=1)
            eco = jh_registry.collect([Item("package.json", "{}")], tmp)["ecosystems"]
            self.assertEqual(eco["npm"]["state"], "observed")
            self.assertEqual([s["url"] for s in eco["npm"]["sources"]], ["https://registry.npmjs.org/"])
        finally:
            shutil.rmtree(tmp)


RULESET = {"name": "main", "target": "branch", "enforcement": "active",
           "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}}, "bypass_actors": [],
           "rules": [{"type": "pull_request", "parameters": {"required_approving_review_count": 1,
                                                             "require_code_owner_review": True,
                                                             "require_last_push_approval": True}},
                     {"type": "required_status_checks", "parameters": {"required_status_checks": [{"context": "ci"}]}},
                     {"type": "deletion"}, {"type": "non_fast_forward"}]}
OWNERS = [Item("CODEOWNERS", "* @org/eng\n")]


class ChangeControl(unittest.TestCase):
    def test_compliant_export(self):
        cc = jh_change.build(OWNERS, RULESET, True, "r.json")
        self.assertEqual(cc["state"], "provider-verified")
        self.assertEqual(jh_change.violations(cc), ([], [], []))

    def test_app_bypass_and_missing_review(self):
        bad = dict(RULESET, bypass_actors=[{"actor_id": 9, "actor_type": "Integration", "bypass_mode": "always"}])
        self.assertEqual(jh_change.violations(jh_change.build(OWNERS, bad, True))[0], ["no_app_bypass"])
        key = dict(RULESET, bypass_actors=[{"actor_id": 3, "actor_type": "DeployKey", "bypass_mode": "always"}])
        self.assertEqual(jh_change.violations(jh_change.build(OWNERS, key, True))[0], ["no_app_bypass"])
        classic = {"required_pull_request_reviews": {"required_approving_review_count": 0},
                   "allow_force_pushes": {"enabled": True}, "allow_deletions": {"enabled": False}}
        severe, weak, _ = jh_change.violations(jh_change.build(OWNERS, classic, True))
        self.assertEqual(severe, ["pull_request_review"])
        self.assertIn("force_push_protected", weak)

    def test_rulesets_not_enforced_or_not_on_default_branch(self):
        for rs in (dict(RULESET, enforcement="evaluate"),
                   dict(RULESET, conditions={"ref_name": {"include": ["refs/heads/release/*"], "exclude": []}})):
            self.assertIn("pull_request_review", jh_change.violations(jh_change.build(OWNERS, [rs], True))[0])

    def test_branch_rules_list_leaves_bypass_unknown(self):
        cc = jh_change.build(OWNERS, RULESET["rules"], True)
        self.assertEqual(cc["checks"]["no_app_bypass"]["state"], "unknown")
        self.assertEqual(jh_change.violations(cc)[2], ["no_app_bypass"])

    def test_terraform_is_declared(self):
        tf = Item("infra/gh.tf", 'resource "github_repository_ruleset" "m" {\n  target = "branch"\n  enforcement = "active"\n'
                                  '  rules {\n    pull_request {\n      required_approving_review_count = 1\n    }\n  }\n'
                                  '  bypass_actors {\n    actor_id = 1\n    actor_type = "DeployKey"\n  }\n}\n')
        cc = jh_change.build(OWNERS + [tf])
        self.assertEqual((cc["state"], jh_change.violations(cc)[0]), ("declared", ["no_app_bypass"]))
        self.assertEqual(cc["source"]["receipts"], [{"path": "infra/gh.tf", "line": 1}])

    def test_codeowners_coverage(self):
        self.assertEqual(jh_change.codeowners([Item(".github/CODEOWNERS", "/docs/ @x\n")])["state"], "partial")
        self.assertEqual(jh_change.codeowners([Item("CODEOWNERS", "* @x\n*\n")])["state"], "partial")
        self.assertEqual(jh_change.codeowners([])["state"], "none")


def cc_facts(state, severe=(), weak=(), unknown=()):
    return {"files_scanned": 3, "map_files_inspected": 2, "exposure": "Low", "owner_state": "observed",
            "declared_custodians": [], "operations": {"tests": "observed", "ci": "observed"}, "jank_policy": "pass",
            "change_control": {"state": state, "severe": list(severe), "weak": list(weak), "unknown": list(unknown),
                               "details": list(severe)}}


class ChangeControlPolicy(unittest.TestCase):
    GRAPH = {"nodes": [], "edges": []}

    def outcome(self, eff, facts):
        return {r["rule"]: r["outcome"] for r in jh_policy.evaluate(eff, facts, self.GRAPH)["rules"]}["P-CHG-001"]

    def test_standard_profile_is_off_unless_required(self):
        std = jh_policy.merge(None, None, [])
        self.assertEqual(self.outcome(std, cc_facts("unknown", unknown=["pull_request_review"])), "pass")
        req = jh_policy.merge({"require": {"change_control": True}}, None, [])
        self.assertEqual(self.outcome(req, cc_facts("unknown", unknown=["pull_request_review"])), "insufficient-evidence")
        self.assertEqual(self.outcome(req, cc_facts("declared")), "pass")
        self.assertEqual(self.outcome(req, cc_facts("provider-verified", severe=["no_app_bypass"])), "review")

    def test_citizen_profile(self):
        cit = jh_policy.merge({"custodians": ["x"]}, None, [], "citizen")
        self.assertEqual(self.outcome(cit, cc_facts("unknown", unknown=["pull_request_review"])), "insufficient-evidence")
        self.assertEqual(self.outcome(cit, cc_facts("declared")), "insufficient-evidence")
        self.assertEqual(self.outcome(cit, cc_facts("declared", severe=["pull_request_review"])), "block")
        self.assertEqual(self.outcome(cit, cc_facts("provider-verified", severe=["no_app_bypass"])), "block")
        self.assertEqual(self.outcome(cit, cc_facts("provider-verified", weak=["status_checks"])), "review")
        self.assertEqual(self.outcome(cit, cc_facts("provider-verified")), "pass")
        self.assertEqual(self.outcome(cit, cc_facts("provider-verified", unknown=["no_app_bypass"])),
                         "insufficient-evidence")


class RegistryPolicy(unittest.TestCase):
    def outcome(self, eff, reg):
        facts = dict(cc_facts("provider-verified"), registry=reg)
        out = jh_policy.evaluate(eff, facts, {"nodes": [], "edges": []})
        return {r["rule"]: r["outcome"] for r in out["rules"]}["P-SUP-001"]

    def test_outcomes(self):
        none = jh_policy.merge(None, None, [])
        bad = {"disallowed": [{"ecosystem": "npm", "url": "https://registry.npmjs.org/", "path": ".npmrc", "line": 1}],
               "unconfigured": []}
        self.assertEqual(self.outcome(none, bad), "pass")
        std = jh_policy.merge({"allowed_registries": ["https://r.internal.example/"]}, None, [])
        self.assertEqual(self.outcome(std, bad), "review")
        self.assertEqual(self.outcome(std, {"disallowed": [], "unconfigured": ["npm"]}), "pass")
        cit = jh_policy.merge({"allowed_registries": ["https://r.internal.example/"], "custodians": ["x"]}, None, [],
                              "citizen")
        self.assertEqual(self.outcome(cit, bad), "block")
        self.assertEqual(self.outcome(cit, {"disallowed": [], "unconfigured": ["npm"]}), "insufficient-evidence")

    def test_repository_cannot_allow_registries(self):
        warns = []
        eff = jh_policy.merge(None, {"allowed_registries": ["https://anything/"]}, warns)
        self.assertEqual(eff["allowed_registries"], [])
        self.assertIn("repository policy cannot approve package registries; ignored", warns)


class CitizenGate(unittest.TestCase):
    def test_template_is_read_only_pinned_and_secretless(self):
        with open(os.path.join(REPO, "templates", "citizen-gate.yml"), encoding="utf-8") as fh:
            text = fh.read()
        doc = jh_yaml.load_all(text)[0]
        self.assertEqual(doc["permissions"], {"contents": "read"})
        self.assertNotIn("secrets.", text)
        uses = [s["uses"] for j in doc["jobs"].values() for s in j["steps"] if "uses" in s]
        self.assertTrue(uses and all("@" in u and len(u.split("@")[1]) == 40 for u in uses), uses)
        self.assertNotIn("${{ github.event", "".join(str(s.get("run", "")) for j in doc["jobs"].values() for s in j["steps"]))

    def test_branch_rules_inside_the_repository_are_only_declared(self):
        tmp = tempfile.mkdtemp()
        try:
            shutil.copytree(os.path.join(REPO, "tests", "fixtures", "citizen-gate"), os.path.join(tmp, "g"))
            app = os.path.join(tmp, "g", "app")
            shutil.copy(os.path.join(tmp, "g", "gate", "rules", "app.json"), os.path.join(app, "rules.json"))
            out = run_cli("passport", app, "--branch-rules", os.path.join(app, "rules.json"), "--json")
            p = json.loads(out.stdout)
            self.assertEqual(p["change_control"]["state"], "declared")
            self.assertTrue(any("--branch-rules file is inside" in w for w in p["warnings"]))
            out = run_cli("passport", app, "--branch-rules", os.path.join(tmp, "g", "gate", "rules", "app.json"), "--json")
            self.assertEqual(json.loads(out.stdout)["change_control"]["state"], "provider-verified")
            # the rules/branches export is a JSON list
            listed = os.path.join(tmp, "g", "gate", "rules", "listed.json")
            with open(listed, "w") as fh:
                json.dump(RULESET["rules"], fh)
            out = run_cli("passport", app, "--branch-rules", listed, "--json")
            self.assertEqual(out.returncode, 0, out.stderr)
            self.assertEqual(json.loads(out.stdout)["change_control"]["checks"]["no_app_bypass"]["state"], "unknown")
        finally:
            shutil.rmtree(tmp)


class EgressBoundary(unittest.TestCase):
    def build(self, files):
        col = jh_map.Collected(items=[jh_map.Item(k, v) for k, v in files.items()], considered=len(files))
        return jh_map.build_report(col, "/x", "app", "t", None)

    CODE = {"app/main.py": 'import requests\nrequests.get("https://api.github.com/r")\n'
                           'requests.post("https://hooks.chat.example.com/x")\nrequests.get("https://evil.example.net/a")\n'}

    def test_unknown_without_a_boundary(self):
        eg = self.build(self.CODE)["egress"]
        self.assertEqual((eg["state"], eg["outside"]), ("unknown", []))

    def test_both_directions_with_tiers(self):
        files = dict(self.CODE, **{".claude/settings.json": json.dumps({"sandbox": {"enabled": True, "network": {
            "allowedDomains": ["api.github.com", "registry.npmjs.org", "*.amazonaws.com"],
            "deniedDomains": ["evil.example.net"]}}})})
        eg = self.build(files)["egress"]
        self.assertEqual([(o["host"], o["tier"]) for o in eg["outside"]],
                         [("evil.example.net", "supported"), ("hooks.chat.example.com", "supported")])
        self.assertIn("denied", eg["outside"][0]["why"])
        self.assertEqual(eg["unused"], ["registry.npmjs.org (.claude/settings.json)"])
        self.assertEqual(eg["wildcards"], ["*.amazonaws.com (.claude/settings.json)"])

    def test_codex_and_openshell_boundaries(self):
        b = jh_egress.boundaries([Item(".codex/config.toml", '[features.network_proxy]\nenabled = true\n'
                                       '[features.network_proxy.domains]\n"api.github.com" = "allow"\n"*.evil.test" = "deny"\n'),
                                  Item("sandbox/p.yaml", SANDBOX["sandbox/policy.yaml"])])
        self.assertEqual([(x["tool"], x["allow"], x["deny"]) for x in b],
                         [("codex", ["api.github.com"], ["*.evil.test"]),
                          ("openshell", ["**.amazonaws.com", "10.0.0.0/8", "api.github.com"], [])])
        self.assertTrue(jh_egress.matches("a.b.amazonaws.com", "**.amazonaws.com"))
        self.assertTrue(jh_egress.matches("amazonaws.com", "**.amazonaws.com"))
        self.assertFalse(jh_egress.matches("amazonaws.com", "*.amazonaws.com"))

    def test_redacted_copy_keeps_counts_only(self):
        files = dict(self.CODE, **{".claude/settings.json": '{"sandbox": {"network": {"allowedDomains": ["api.github.com"]}}}'})
        shared = jh_graph.pseudonymize(self.build(files))
        self.assertEqual(shared["egress"]["outside"], 2)
        self.assertNotIn("hooks.chat.example.com", json.dumps(shared))


class RedactedPassport(unittest.TestCase):
    def test_new_sections_hold_no_hosts_names_or_paths(self):
        tmp = tempfile.mkdtemp()
        try:
            shutil.copytree(os.path.join(REPO, "tests", "fixtures", "citizen-gate"), os.path.join(tmp, "g"))
            g = os.path.join(tmp, "g")
            os.makedirs(os.path.join(g, "app", ".claude"))
            with open(os.path.join(g, "app", ".claude", "settings.json"), "w") as fh:
                json.dump({"sandbox": {"enabled": True, "network": {"allowedDomains": ["api.secret-host.example"]}}}, fh)
            with open(os.path.join(g, "app", ".npmrc"), "w") as fh:
                fh.write("registry=https://npm.private-corp.example/repo/\n")
            bad = dict(RULESET, name="internal-ruleset-name",
                       bypass_actors=[{"actor_id": 424242, "actor_type": "Integration", "bypass_mode": "always"}])
            with open(os.path.join(g, "gate", "rules", "app.json"), "w") as fh:
                json.dump(bad, fh)
            out = run_cli("passport", os.path.join(g, "app"), "--policy", os.path.join(g, "gate", "policy", "citizen.json"),
                          "--branch-rules", os.path.join(g, "gate", "rules", "app.json"), "--redact", "--json")
            text = out.stdout
            p = json.loads(text)
            for leak in ("private-corp", "registry.internal.example", "secret-host", "424242", "app.json",
                         "Engineering custodian"):
                self.assertNotIn(leak, text, leak)
            self.assertEqual(p["change_control"]["checks"]["no_app_bypass"]["state"], "not-met")
            self.assertIn("P-SUP-001", [r["rule"] for r in p["assessment"]["decision"]["reasons"]])
        finally:
            shutil.rmtree(tmp)


def _graph(caps):
    from _util import edge, node
    edges = [edge("e%d" % i, "app", "db", "connects" if c == "unknown" else {"read": "reads", "write": "writes",
              "delete": "deletes", "admin": "administers"}[c], c) for i, c in enumerate(caps)]
    return {"graph": {"nodes": [node("app", "application"), node("db")], "edges": edges}, "evidence": [],
            "coverage": {}, "assessment": {"blast_radius": {}, "exposure": {"class": "Low"}}}


class DiffUnknownCapability(unittest.TestCase):
    def changes(self, before, after):
        d = jh_graph.diff(_graph(before), _graph(after))
        return ([(e["before"], e["after"], e.get("possible", False), e.get("was_unknown", False))
                 for e in d["permission_escalations"]], [(e["before"], e["after"]) for e in d["permission_reductions"]])

    def test_known_to_unknown_is_a_possible_escalation_not_a_reduction(self):
        self.assertEqual(self.changes(["read"], ["unknown"]), ([(["read"], ["unknown"], True, False)], []))

    def test_unknown_to_known_is_marked(self):
        self.assertEqual(self.changes(["unknown"], ["write"]), ([(["unknown"], ["write"], False, True)], []))

    def test_known_changes(self):
        self.assertEqual(self.changes(["read"], ["write"]), ([(["read"], ["write"], False, False)], []))
        self.assertEqual(self.changes(["write"], ["read"]), ([], [(["write"], ["read"])]))
        self.assertEqual(self.changes(["unknown"], ["unknown"]), ([], []))
        self.assertEqual(self.changes(["admin"], ["unknown"]), ([], []))     # nothing exceeds admin


class ThirdSoakPrecision(unittest.TestCase):
    def test_values_that_are_not_secrets(self):
        files = {"src/refs.js": "const TO" + "KEN = '[FSG]\\\\d{1,3}'\n",
                 "src/ds.tsx": "const t = { to" + "ken: \"--palette-background\" }\n",
                 "src/users.tsx": "errs.pass" + "word = 'Password must be at least 6 characters'\n",
                 "scripts/notes.sh": "# miss `API_" + "KEY = \"sk-live-...\"` entirely\n",
                 "site/p.astro": "const c = { api_" + "key: \"Supply the adapter's API-key inputs. Some checks only validate structure\" }\n",
                 "src/deploy.mjs": "lines.push('  secret_" + "key: \"' + crypto.randomBytes(32).toString('hex') + '\"')\n",
                 "android/app/google-services.json": "{\n  \"api_key\": [{\"current_key\": \"AIza" + "SyD3f8kQ2mZx9LwR4tVn8sYb3HcJpQ1aVv9\"}]\n}\n"}
        got = {p: s for p, _, s in hits(files, "JH101")}
        self.assertEqual(got, {"android/app/google-services.json": "minor"})

    def test_rules_tests_prose_and_identifiers(self):
        files = {"firestore.test.rules": "service cloud.firestore {\n  match /{d=**} { allow read, write: if true; }\n}\n",
                 "src/scanners/ci.py": '"""Flags `curl \u2026 %s` style remote execution."""\n' % PIPE,
                 "src/security/checks.ts": "const PUBLIC_" + "SECRET = /SECRET|PRIVATE/;\n",
                 "src/client.ts": "const k = process.env.NEXT_PUBLIC_STRIPE_" + "SECRET_KEY;\n"}
        self.assertEqual(hits(files, "JH134"), [])
        self.assertEqual(hits(files, "JH111"), [])
        self.assertEqual([h[0] for h in hits(files, "JH132")], ["src/client.ts"])


class SoakPrecision(unittest.TestCase):
    def test_pipe_to_shell(self):
        files = {
            "deploy/a.sh": "curl -fsSL https://get.docker.com %s\n" % PIPE,
            "deploy/b.sh": "curl -fsSL https://downloads.example.net/i.sh %s\n" % PIPE,
            "deploy/c.sh": 'echo "    Install with: curl -fsSL https://ollama.com/install.sh %s"\n' % PIPE,
            "tests/test_x.py": 'CASES = ["RUN curl https://x.example/i.sh %s"]\n' % PIPE,
        }
        self.assertEqual(hits(files, "JH111"), [("deploy/a.sh", 1, "major"), ("deploy/b.sh", 1, "critical"),
                                                ("tests/test_x.py", 1, "minor")])

    def test_signature_checks(self):
        files = {"app/jwt.py": "jwt.decode(t, options={'verify_" + "signature': False})\n",
                 "app/client.py": "def call(url, verify_" + "signatures: bool = False):\n    pass\n",
                 "app/check.py": "assert verify_" + "signature(body, key, sig) is False\n"}
        self.assertEqual([h[0] for h in hits(files, "JH115")], ["app/client.py", "app/jwt.py"])

    def test_commit_sha_is_not_injection(self):
        files = {".github/workflows/w.yml": "on: pull_request_target\njobs:\n  j:\n    runs-on: x\n    steps:\n"
                                            "      - run: echo \"${{ github.event.pull_request.head.sha }}\"\n"
                                            "      - run: echo \"${{ github.event.pull_request.head.ref }}\"\n"}
        self.assertEqual([h[1] for h in hits(files, "JH419")], [7])

    def test_public_read_is_major_and_vulnerable_examples_are_minor(self):
        files = {"firestore.rules": "service cloud.firestore {\n  match /scores/{id} {\n    allow read: if true;\n"
                                    "    allow write: if true;\n  }\n}\n",
                 "examples/vulnerable-app/firestore.rules": "service cloud.firestore {\n  match /x/{id} {\n"
                                                            "    allow write: if true;\n  }\n}\n"}
        self.assertEqual(hits(files, "JH134"), [("examples/vulnerable-app/firestore.rules", 3, "minor"),
                                                ("firestore.rules", 3, "major"), ("firestore.rules", 4, "critical")])

    def test_secret_placeholders_and_contexts(self):
        for value in ("x-oauth-" + "basic", "$RUNNER_TEMP/apple.json", "DATA_" + "BUCKET",
                      "Fly macaroon token exchange is not available on Runtime; create a key in the console",
                      "sk-ant-api03-" + "REPLACE_WITH_REAL_KEY"):
            self.assertTrue(jh_rules.secret_placeholder('pass' + 'word = "%s"' % value), value)
        files = {"scripts/seed.js": "const u = { pass" + "word: 'password123' }\n",
                 "README.md": "[doc](https://s3.amazonaws.com/b/x?AWSAccessKeyId=AKIA" + "IOSFODNN7ABCDEFG&Expires=1)\n",
                 "web/firebase.js": "const config = {\n  apiKey: 'AIza" + "SyD3f8kQ2mZx9LwR4tVn8sYb3HcJpQ1aVv9',\n"
                                    "  authDomain: 'demo.firebaseapp.com',\n};\n",
                 "tests/fixtures/c.ts": "const T = \"sk-" + "proj-Zk82KdpQ1aVv93x7Kq2mZp9LwR4tVn8\";\n"}
        got = {p: s for p, _, s in hits(files, "JH101")}
        self.assertEqual(got, {"scripts/seed.js": "minor", "README.md": "minor", "web/firebase.js": "minor",
                               "tests/fixtures/c.ts": "critical"})        # a provider token stays critical in tests


if __name__ == "__main__":
    unittest.main()
