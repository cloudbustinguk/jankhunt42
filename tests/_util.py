"""Shared helpers for the jankhunt42 unittest suite (stdlib only)."""
import json
import os
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
SCRIPTS = os.path.join(ROOT, "scripts")
FIXTURES = os.path.join(HERE, "fixtures")
CLI = os.path.join(SCRIPTS, "jankhunt42")
if SCRIPTS not in sys.path:
    sys.path.insert(0, SCRIPTS)
os.environ.setdefault("PYTHONDONTWRITEBYTECODE", "1")
sys.dont_write_bytecode = True


def run_cli(*args, env=None, cwd=None, input_text=None):
    e = dict(os.environ)
    e["PYTHONDONTWRITEBYTECODE"] = "1"
    e.pop("FORCE_COLOR", None)
    if env:
        e.update(env)
    return subprocess.run([sys.executable, CLI] + list(args), capture_output=True, text=True,
                          env=e, cwd=cwd, input=input_text, timeout=300)


def node(nid, kind="database", **kw):
    n = {"id": nid, "kind": kind, "display_label": nid, "trust_domain": kw.pop("trust_domain", "internal"),
         "environment": kw.pop("environment", "unknown"), "sensitivity": kw.pop("sensitivity", "unknown"),
         "criticality": kw.pop("criticality", "unknown"), "attributes": {}, "evidence_refs": [],
         "classification_source": "test"}
    n.update(kw)
    return n


def edge(eid, s, t, kind="connects", cap="unknown", ver="observed"):
    return {"id": eid, "source": s, "target": t, "kind": kind, "capability": cap, "identity_ref": None,
            "verification": ver, "confidence": "medium", "source_trust": "repository", "evidence_refs": [],
            "assumptions": [], "trust_boundary": {"domain": None, "environment": None}}


def read_json(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def write_json(path, data):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
