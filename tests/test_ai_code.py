"""4.20.0: AI application code that switches a safety default off. JH106 reads torch.load(..., weights_only=False):
PyTorch's default since 2.6 is the safe loader, and False unpickles the checkpoint. JH160 reads LangChain's
allow_dangerous_code, allow_dangerous_requests and allow_dangerous_deserialization set to True. Both read Python's
syntax tree: the call's own keyword set to the constant, never a nested call or a larger expression; a file that does
not parse is read line by line, at low confidence.

The code is invented. Flags that would trip the scanner on this file are assembled at run time."""
import json
import os
import shutil
import tempfile
import unittest

from _util import run_cli

OFF = "weights_only" + "=False"
ON = "weights_only" + "=True"
DANGER = "allow_dangerous_"


def write(root, files):
    for rel, text in files.items():
        path = os.path.join(root, rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(text)


def scan(files, *rules):
    root = tempfile.mkdtemp(prefix="jh-ai-code-")
    try:
        write(root, files)
        args = [a for r in rules for a in ("--rule", r)]
        out = run_cli("scan", root, "--json", "--min-severity", "info", "--no-progress", *args).stdout
        return json.loads(out)["findings"]
    finally:
        shutil.rmtree(root, ignore_errors=True)


class TorchLoad(unittest.TestCase):
    def test_weights_only_false_on_one_line_and_across_lines(self):
        found = scan({"train/resume.py": (
            "import torch\n\n"
            "def resume(path):\n"
            "    state = torch.load(path, map_location=\"cpu\", %s)\n"
            "    model = torch.load(\n"
            "        path,\n"
            "        map_location=device,\n"
            "        %s,\n"
            "    )\n"
            "    return state, model\n" % (OFF, OFF))}, "JH106")
        self.assertEqual([(f["line"], f["severity"]) for f in found], [(4, "major"), (5, "major")])
        self.assertIn("weights_only=False", found[0]["message"])
        self.assertIn("runs code here when it loads", found[0]["message"])

    def test_the_safe_loader_and_text_are_quiet(self):
        found = scan({"serve/app.py": (
            "import torch\n"
            "a = torch.load(\"model.pt\")\n"
            "b = torch.load(\"model.pt\", %s)\n"
            "c = torch.load(\"model.pt\", map_location=\"cpu\")\n"
            "# d = torch.load(\"model.pt\", %s)\n"
            "HELP = \"torch.load(path, %s) is unsafe\"\n"
            "e = torch.load(\"model.pt\")  # never pass %s here\n"
            "f = safetensors.torch.load_file(\"model.safetensors\")\n" % (ON, OFF, OFF, OFF))}, "JH106")
        self.assertEqual(found, [])

    def test_another_call_on_the_same_lines_does_not_count(self):
        found = scan({"serve/load.py": "x = torch.load(p); y = other(%s)\n" % OFF}, "JH106")
        self.assertEqual(found, [])

    def test_only_the_calls_own_constant_keyword_counts(self):
        found = scan({"serve/edge.py": (
            "x = torch.load(get_path(%s), %s)\n"
            "y = torch.load(p, weights_only=False or True)\n"
            "z = torch.load(p, weights_only=flag)\n" % (OFF, ON))}, "JH106")
        self.assertEqual(found, [])

    def test_every_call_on_a_line(self):
        found = scan({"serve/two.py": "x = torch.load(p); y = torch.load(q, %s)\n" % OFF}, "JH106")
        self.assertEqual([(f["line"], f["column"]) for f in found], [(1, 24)])

    def test_a_file_that_does_not_parse_is_read_by_line_at_low_confidence(self):
        found = scan({"legacy/load.py": "print 'loading'\nstate = torch.load(path, %s)\n" % OFF}, "JH106")
        self.assertEqual([(f["line"], f["severity"], f["confidence"]) for f in found], [(2, "major", "low")])

    def test_in_tests_it_is_a_note(self):
        found = scan({"tests/test_checkpoint.py": "state = torch.load(tmp_path / \"m.pt\", %s)\n" % OFF}, "JH106")
        self.assertEqual([(f["severity"], f["confidence"]) for f in found], [("minor", "low")])

    def test_pickle_findings_keep_their_place(self):
        found = scan({"app/cache.py": "import pickle, torch\nd = pickle.loads(blob)\nm = torch.load(p, %s)\n" % OFF},
                     "JH106")
        self.assertEqual([(f["line"], f["severity"]) for f in found], [(2, "critical"), (3, "major")])


class LangChainSwitches(unittest.TestCase):
    def test_each_switch(self):
        found = scan({"rag/app.py": (
            "from langchain_community.vectorstores import FAISS\n"
            "from langchain_experimental.agents import create_pandas_dataframe_agent\n"
            "from langchain_community.agent_toolkits import RequestsToolkit\n\n"
            "db = FAISS.load_local(\"index\", embeddings, %sdeserialization=True)\n"
            "agent = create_pandas_dataframe_agent(llm, df, verbose=True, %scode=True)\n"
            "toolkit = RequestsToolkit(\n    requests_wrapper=TextRequestsWrapper(headers={}),\n"
            "    %srequests=True,\n)\n" % (DANGER, DANGER, DANGER))}, "JH160")
        self.assertEqual([(f["line"], f["severity"]) for f in found], [(5, "major"), (6, "major"), (9, "major")])
        self.assertIn("pickle", found[0]["message"])
        self.assertIn("write Python", found[1]["message"])
        self.assertIn("any address", found[2]["message"])

    def test_off_defaults_strings_and_comments_are_quiet(self):
        found = scan({"rag/safe.py": (
            "db = FAISS.load_local(\"index\", embeddings, %sdeserialization=False)\n"
            "agent = create_pandas_dataframe_agent(llm, df)\n"
            "# toolkit = RequestsToolkit(%srequests=True)\n"
            "NOTE = \"set %scode=True only in a sandbox\"\n"
            "def load(path, %sdeserialization: bool = False):\n    pass\n" % (DANGER, DANGER, DANGER, DANGER)),
            "docs/rag.md": "Pass `%sdeserialization=True` only for files you wrote.\n" % DANGER}, "JH160")
        self.assertEqual(found, [])

    def test_expressions_and_dictionaries_do_not_count(self):
        found = scan({"rag/edge.py": (
            "db = FAISS.load_local(p, e, %sdeserialization=True and False)\n"
            "db = FAISS.load_local(p, e, **{\"%sdeserialization\": True})\n"
            "db = FAISS.load_local(p, e, %sdeserialization=trusted)\n" % (DANGER, DANGER, DANGER))}, "JH160")
        self.assertEqual(found, [])

    def test_the_value_on_the_next_line(self):
        found = scan({"rag/load.py": "db = FAISS.load_local(p, e, %sdeserialization=\n    True)\n" % DANGER}, "JH160")
        self.assertEqual([(f["line"], f["severity"]) for f in found], [(1, "major")])

    def test_a_file_that_does_not_parse_is_read_by_line_at_low_confidence(self):
        found = scan({"legacy/rag.py": "print 'x'\ndb = FAISS.load_local(p, e, %sdeserialization=True)\n" % DANGER},
                     "JH160")
        self.assertEqual([(f["line"], f["confidence"]) for f in found], [(2, "low")])

    def test_in_tests_it_is_a_note(self):
        found = scan({"tests/test_agent.py": "agent = create_csv_agent(llm, path, %scode=True)\n" % DANGER}, "JH160")
        self.assertEqual([(f["severity"], f["confidence"]) for f in found], [("minor", "low")])


if __name__ == "__main__":
    unittest.main()
