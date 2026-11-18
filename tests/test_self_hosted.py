"""4.20.0: self-hosted AI services deployed in a known-bad state. JH434: a GPUStack server image before 2.2.0
(CVE-2026-102895, GHSA-gj9m-f8ph-pmhr; on CISA's Known Exploited Vulnerabilities list), with tags in the shapes Docker
Hub really publishes (v0.7.1, 0.4.0rc1-cpu, v2.1-dev-<sha>, v0.7.1-cuda12.8). JH163: LiteLLM's master key left at
sk-1234, the value in LiteLLM's own examples: master_key under general_settings or the LITELLM_MASTER_KEY variable,
case-sensitive, with the whole decoded value equal to the default. JH434 counts only a deployed image: a Compose or
Kubernetes image field, a Dockerfile FROM, or a docker or podman run, pull or create command."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli

DEFAULT_KEY = "sk-" + "1234"


def scan(files, *rules):
    root = tempfile.mkdtemp(prefix="jh-selfhosted-")
    try:
        for rel, text in files.items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w", encoding="utf-8") as fh:
                fh.write(text)
        args = [a for r in rules for a in ("--rule", r)]
        out = run_cli("scan", root, "--json", "--min-severity", "info", "--no-progress", *args).stdout
        return json.loads(out)["findings"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


def compose(image):
    return "services:\n  gpustack:\n    image: %s\n    ports:\n      - \"80:80\"\n" % image


class GPUStack(unittest.TestCase):
    def test_tags_before_2_2(self):
        for image in ("gpustack/gpustack:v0.7.1", "gpustack/gpustack:0.4.0rc1-cpu", "gpustack/gpustack:v2.1.1",
                      "gpustack/gpustack:v2.1-dev-0c348af", "gpustack/gpustack:v0.7.1-cuda12.8",
                      "gpustack/gpustack:v2.0", "docker.io/gpustack/gpustack:v2.1.2",
                      "registry.cn-hangzhou.aliyuncs.com/gpustack/gpustack:v0.6.2-npu"):
            with self.subTest(image=image):
                found = scan({"docker-compose.yml": compose(image)}, "JH434")
                self.assertEqual([(f["line"], f["severity"]) for f in found], [(3, "critical")])

    def test_fixed_floating_and_unrelated_tags_are_quiet(self):
        for image in ("gpustack/gpustack:v2.2.0", "gpustack/gpustack:v2.2.2", "gpustack/gpustack:v2.2",
                      "gpustack/gpustack:v2.3.1", "gpustack/gpustack:v2.10.0", "gpustack/gpustack:v2.2.0rc1",
                      "gpustack/gpustack:v2.2-dev-1cfcbbf", "gpustack/gpustack:latest", "gpustack/gpustack:main-cpu",
                      "gpustack/gpustack@sha256:" + "0" * 64, "gpustack/runner:v0.1.0", "acme/gpustack-ui:v0.7.1",
                      "mygpustack/gpustack:v0.7.1"):
            with self.subTest(image=image):
                self.assertEqual(scan({"docker-compose.yml": compose(image)}, "JH434"), [])

    def test_a_mention_that_is_not_the_deployed_image(self):
        found = scan({"compose.yml": ("services:\n  server:\n    image: gpustack/gpustack:v2.2.0\n    environment:\n"
                                      "      OLD_IMAGE: gpustack/gpustack:v2.1.1\n"),
                      "scripts/notes.sh": "echo 'we used gpustack/gpustack:v0.7.1 before'\n"}, "JH434")
        self.assertEqual(found, [])

    def test_a_run_command_continued_over_lines(self):
        found = scan({"scripts/start.sh": ("docker run -d --gpus all \\\n  -p 80:80 \\\n"
                                           "  gpustack/gpustack:v0.7.1\n")}, "JH434")
        self.assertEqual([f["line"] for f in found], [3])

    def test_dockerfile_kubernetes_and_a_run_script(self):
        found = scan({
            "Dockerfile": "FROM gpustack/gpustack:v0.6.0\nRUN pip install extra\n",
            "k8s/gpustack.yaml": ("apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: gpustack\nspec:\n"
                                  "  template:\n    spec:\n      containers:\n        - name: server\n"
                                  "          image: gpustack/gpustack:v0.5.1\n"),
            "scripts/start.sh": "docker run -d --gpus all -p 80:80 gpustack/gpustack:v2.0.3\n",
            "docs/install.md": "docker run -d gpustack/gpustack:v0.6.0\n",
            "deploy/old.yml": "# image: gpustack/gpustack:v0.6.0\nimage: gpustack/gpustack:v2.3.1\n",
        }, "JH434")
        self.assertEqual(sorted((f["path"], f["line"]) for f in found),
                         [("Dockerfile", 1), ("k8s/gpustack.yaml", 10), ("scripts/start.sh", 1)])


class LiteLLM(unittest.TestCase):
    def test_default_key_where_the_proxy_is_configured(self):
        found = scan({
            "docker-compose.yml": ("services:\n  litellm:\n    image: ghcr.io/berriai/litellm:main-stable\n"
                                   "    environment:\n      - LITELLM_MASTER_KEY=%s\n" % DEFAULT_KEY),
            "litellm/config.yaml": ("model_list: []\ngeneral_settings:\n  master_key: %s\n" % DEFAULT_KEY),
            ".env": "LITELLM_MASTER_KEY=\"%s\"\n" % DEFAULT_KEY,
            "Dockerfile": "FROM ghcr.io/berriai/litellm:main-stable\nENV LITELLM_MASTER_KEY=%s\n" % DEFAULT_KEY,
        }, "JH163")
        self.assertEqual(sorted((f["path"], f["line"], f["severity"]) for f in found),
                         [(".env", 1, "critical"), ("Dockerfile", 2, "critical"), ("docker-compose.yml", 5, "critical"),
                          ("litellm/config.yaml", 3, "critical")])

    def test_kubernetes_env_and_a_compose_list(self):
        found = scan({
            "k8s/litellm.yaml": ("apiVersion: apps/v1\nkind: Deployment\nspec:\n  template:\n    spec:\n      containers:\n"
                                 "        - name: proxy\n          env:\n            - name: LITELLM_MASTER_KEY\n"
                                 "              value: \"%s\"\n" % DEFAULT_KEY),
            "compose.yaml": "services:\n  proxy:\n    environment:\n      - \"LITELLM_MASTER_KEY=%s\"\n" % DEFAULT_KEY,
            "litellm/config.yaml": "general_settings:\n  master_key: >-\n    %s\n" % DEFAULT_KEY,
        }, "JH163")
        self.assertEqual(sorted((f["path"], f["line"]) for f in found),
                         [("compose.yaml", 4), ("k8s/litellm.yaml", 10), ("litellm/config.yaml", 2)])

    def test_only_the_default_value_under_the_real_key(self):
        for text in ("general_settings:\n  master_key: %s.abcd\n" % DEFAULT_KEY,
                     "general_settings:\n  master_key: \"%s.abcd\"\n" % DEFAULT_KEY,
                     "general_settings:\n  master_key: SK-1234\n",
                     "general_settings:\n  MASTER_KEY: %s\n" % DEFAULT_KEY,
                     "other_settings:\n  master_key: %s\n" % DEFAULT_KEY):
            with self.subTest(text=text):
                self.assertEqual(scan({"litellm/config.yaml": text}, "JH163"), [])
        self.assertEqual(scan({"scripts/run.sh": "echo LITELLM_MASTER_KEY=%s\n" % DEFAULT_KEY,
                               ".env": "litellm_master_key=%s\nLITELLM_MASTER_KEY=%s-old\n" % (DEFAULT_KEY, DEFAULT_KEY)},
                              "JH163"), [])

    def test_in_examples_and_templates_it_is_a_note(self):
        found = scan({".env.example": "LITELLM_MASTER_KEY=%s\n" % DEFAULT_KEY,
                      "examples/litellm/docker-compose.yml": "services:\n  p:\n    environment:\n"
                                                             "      LITELLM_MASTER_KEY: %s\n" % DEFAULT_KEY}, "JH163")
        self.assertEqual(sorted((f["path"], f["severity"], f["confidence"]) for f in found),
                         [(".env.example", "minor", "low"), ("examples/litellm/docker-compose.yml", "minor", "low")])

    def test_other_keys_and_values_are_quiet(self):
        found = scan({
            ".env": ("LITELLM_MASTER_KEY=%s5678\nOPENAI_API_KEY=%s\nMASTER_KEY_ID=%s\n"
                     "# LITELLM_MASTER_KEY=%s\nLITELLM_MASTER_KEY=${MASTER_KEY}\n" % (
                         DEFAULT_KEY, DEFAULT_KEY, DEFAULT_KEY, DEFAULT_KEY)),
            "config.yaml": "general_settings:\n  master_key: os.environ/LITELLM_MASTER_KEY\n",
            "README.md": "Set LITELLM_MASTER_KEY=%s for a quick try.\n" % DEFAULT_KEY,
            "app/client.py": "client = OpenAI(api_key=\"%s\", base_url=\"http://localhost:4000\")\n" % DEFAULT_KEY,
        }, "JH163")
        self.assertEqual(found, [])


if __name__ == "__main__":
    unittest.main()
