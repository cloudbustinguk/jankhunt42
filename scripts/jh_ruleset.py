"""Site rulesets (`--ruleset FILE.json`): an organisation's own scan policy, passed in.

A ruleset adds site rules, which run on the same engine as the shipped ones, and can set shipped rules aside or
change their severity. Its schema is `jankhunt.ruleset.v1`:

    {"schema_version": "jankhunt.ruleset.v1", "name": "acme-site-policy",
     "ignore": ["JH417"], "severity": {"JH213": "minor"},
     "rules": [{"id": "ACME001", "title": "Internal hostname in code", "severity": "major",
                "category": "security", "message": "...", "fix": "...",
                "patterns": ["\\\\b[a-z0-9-]+\\\\.corp\\\\.acme\\\\.internal\\\\b"], "files": ["*.cs", "*.json"],
                "examples": {"match": ["host = \\"db1.corp.acme.internal\\""], "no_match": ["acme.com"]}}]}

Every site rule carries examples, and a ruleset whose rule misses its own match example, or matches a no_match one,
is refused: a site policy stays honest as people edit it. Ids starting with JH stay reserved for shipped rules.

Trust follows the file, as it does for every other operator input: a ruleset outside the scanned repository is the
operator's policy and applies everywhere. One inside the repository is the repository's own say, like
`.jankhunt42.toml`: its rules still run, but its ignores and severity changes do not reach the citizen profile's
governance scans.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import signal
import stat
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Sequence, Set

import jh_ceiling
from jh_core import SEVERITIES, Rule, redact_secrets

SCHEMA = "jankhunt.ruleset.v1"
MAX_BYTES = 1000000
MAX_RULES = 500
MAX_PATTERNS = 10
MAX_PATTERN = 500
TARGETS = ("code", "raw", "nocomment", "comments")
CONFIDENCE = ("high", "medium", "low")
EXAMPLE_SECONDS = 2.0     # a rule checks all its own examples within this, or the ruleset is refused
_ID = re.compile(r"[A-Z][A-Z0-9]{1,15}(?:-[A-Z0-9]{1,8})?\Z")
_CATEGORY = re.compile(r"[a-z][a-z0-9-]{0,31}\Z")
# user:password@ after any ://, wherever it stands (after _, in Markdown emphasis, or straight after other letters)
_URL_CREDENTIALS = re.compile(r"://[^/\s@]*:[^/\s@]*@")


def _secret_in(value: str) -> bool:
    """Text a report would print that carries a credential: anything the redactor masks, or a URL's user:password."""
    return redact_secrets(value) != value or bool(_URL_CREDENTIALS.search(value))
_KEYS = {"schema_version", "name", "description", "ignore", "severity", "rules"}
_RULE_KEYS = {"id", "title", "severity", "category", "message", "fix", "confidence", "patterns", "target", "files",
              "langs", "exclude", "examples"}


class RulesetError(ValueError):
    pass


@dataclass
class Ruleset:
    path: str
    name: str
    sha256: str
    trusted: bool                          # outside the scanned repository: the operator's own policy
    rules: List[Rule] = field(default_factory=list)
    ignore: Set[str] = field(default_factory=set)
    severity: Dict[str, str] = field(default_factory=dict)

    def summary(self) -> Dict[str, Any]:
        return {"name": self.name, "sha256": self.sha256, "trusted": self.trusted,
                "rules": sorted(r.id for r in self.rules), "ignored": sorted(self.ignore),
                "severity": dict(sorted(self.severity.items()))}


def _text(value: Any, where: str, limit: int, required: bool = True) -> str:
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not value.strip() or len(value) > limit:
        raise RulesetError("%s: expected text of 1 to %d characters" % (where, limit))
    if _secret_in(value):
        # this text is printed in every report: it must not carry a credential
        raise RulesetError("%s: looks like it holds a secret, which every report would print" % where)
    return value.strip()


class _Overrun(Exception):
    pass


def bounded(seconds: float):
    """A context that raises _Overrun once seconds pass, so a runaway regular expression cannot stall the run. Python's
    regex engine checks for signals while it matches, so the timer stops it. Where there is no interval timer (not
    Unix, or not the main thread) the work runs unbounded."""
    class _Bound:
        def __enter__(self):
            self.armed = hasattr(signal, "setitimer") and threading.current_thread() is threading.main_thread()
            if self.armed:
                def over(*_):
                    raise _Overrun()
                self.old = signal.signal(signal.SIGALRM, over)
                signal.setitimer(signal.ITIMER_REAL, max(seconds, 0.001))
            return self

        def __exit__(self, *exc):
            if self.armed:
                signal.setitimer(signal.ITIMER_REAL, 0)
                signal.signal(signal.SIGALRM, self.old)
            return False
    return _Bound()


def _compile(pattern: str, where: str) -> "re.Pattern[str]":
    try:
        return re.compile(pattern)
    except (re.error, OverflowError, RecursionError, ValueError, MemoryError) as exc:
        raise RulesetError("%s: pattern %r does not compile: %s" % (where, pattern, exc))


def _strings(value: Any, where: str, limit: int, most: int) -> List[str]:
    if value is None:
        return []
    if not isinstance(value, list) or len(value) > most or not all(isinstance(v, str) and 0 < len(v) <= limit
                                                                  for v in value):
        raise RulesetError("%s: expected a list of at most %d strings" % (where, most))
    return list(value)


def load(path: str, root: str, known: Set[str]) -> Ruleset:
    """Read and check one ruleset. known holds the rule ids already defined (shipped, and earlier rulesets)."""
    try:
        # never blocks: a FIFO or device is refused, not waited on
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_CLOEXEC", 0))
    except OSError as exc:
        raise RulesetError("cannot read %s: %s" % (path, exc.strerror or exc))
    try:
        if not stat.S_ISREG(os.fstat(fd).st_mode):
            raise RulesetError("%s is not a regular file" % path)
        with os.fdopen(fd, "rb", closefd=False) as fh:
            raw = fh.read(MAX_BYTES + 1)
    except OSError as exc:
        raise RulesetError("cannot read %s: %s" % (path, exc.strerror or exc))
    finally:
        os.close(fd)
    if len(raw) > MAX_BYTES:
        raise RulesetError("%s is over %d bytes" % (path, MAX_BYTES))
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=jh_ceiling._unique)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise RulesetError("%s is not valid JSON: %s" % (path, str(exc).replace("network ceiling", "ruleset")))
    if not isinstance(doc, dict) or doc.get("schema_version") != SCHEMA:
        raise RulesetError("%s: schema_version must be %s" % (path, SCHEMA))
    extra = sorted(set(doc) - _KEYS)
    if extra:
        raise RulesetError("%s: unknown keys %s" % (path, ", ".join(extra)))
    rs = Ruleset(path=path, name=_text(doc.get("name"), "name", 80), sha256=hashlib.sha256(raw).hexdigest(),
                 trusted=not jh_ceiling.inside_repository(path, root))
    rules = doc.get("rules") or []
    if not isinstance(rules, list) or len(rules) > MAX_RULES:
        raise RulesetError("rules: expected a list of at most %d rules" % MAX_RULES)
    ids = set(known)
    for i, spec in enumerate(rules):
        rule = _rule(spec, "rules[%d]" % i)
        if rule.id in ids:
            raise RulesetError("rules[%d]: id %s is already defined" % (i, rule.id))
        ids.add(rule.id)
        rs.rules.append(rule)
    for rid in _strings(doc.get("ignore"), "ignore", 32, MAX_RULES):
        if rid.upper() not in ids:
            raise RulesetError("ignore: no such rule: %s" % rid)
        rs.ignore.add(rid.upper())
    severity = doc.get("severity") or {}
    if not isinstance(severity, dict):
        raise RulesetError("severity: expected an object of rule id to severity")
    for rid, sev in severity.items():
        if rid.upper() not in ids:
            raise RulesetError("severity: no such rule: %s" % rid)
        if sev not in SEVERITIES:
            raise RulesetError("severity.%s: expected one of %s" % (rid, ", ".join(SEVERITIES)))
        rs.severity[rid.upper()] = sev
    return rs


def _rule(spec: Any, where: str) -> Rule:
    if not isinstance(spec, dict):
        raise RulesetError("%s: expected an object" % where)
    extra = sorted(set(spec) - _RULE_KEYS)
    if extra:
        raise RulesetError("%s: unknown keys %s" % (where, ", ".join(extra)))
    rid = _text(spec.get("id"), where + ".id", 32)
    if not _ID.match(rid) or rid.startswith("JH"):
        raise RulesetError("%s.id: %s must be upper-case letters and digits (ACME001, SITE-12), not starting with JH, "
                           "which is reserved for shipped rules" % (where, rid))
    where = "%s (%s)" % (where, rid)
    sev = spec.get("severity")
    if sev not in SEVERITIES:
        raise RulesetError("%s.severity: expected one of %s" % (where, ", ".join(SEVERITIES)))
    confidence = spec.get("confidence", "medium")
    target = spec.get("target", "code")
    if confidence not in CONFIDENCE or target not in TARGETS:
        raise RulesetError("%s: confidence must be one of %s, and target one of %s"
                           % (where, ", ".join(CONFIDENCE), ", ".join(TARGETS)))
    patterns = _strings(spec.get("patterns"), where + ".patterns", MAX_PATTERN, MAX_PATTERNS)
    if not patterns:
        raise RulesetError("%s.patterns: at least one is required" % where)
    compiled = [_compile(p, where) for p in patterns]
    exclude = _text(spec.get("exclude"), where + ".exclude", MAX_PATTERN, required=False)
    exclude_re = _compile(exclude, where + ".exclude") if exclude else None
    examples = spec.get("examples")
    if not isinstance(examples, dict) or set(examples) - {"match", "no_match"}:
        raise RulesetError("%s.examples: expected {\"match\": [...], \"no_match\": [...]}" % where)
    match = _strings(examples.get("match"), where + ".examples.match", 1000, 50)
    if not match:
        raise RulesetError("%s.examples.match: at least one line the rule must report is required" % where)

    def hits(line: str) -> bool:
        return any(p.search(line) for p in compiled) and not (exclude_re and exclude_re.search(line))
    no_match = _strings(examples.get("no_match"), where + ".examples.no_match", 1000, 50)
    try:
        with bounded(EXAMPLE_SECONDS):
            for line in match:
                if not hits(line):
                    raise RulesetError("%s: misses its own match example %r" % (where, line))
            for line in no_match:
                if hits(line):
                    raise RulesetError("%s: reports its own no_match example %r" % (where, line))
    except _Overrun:
        raise RulesetError("%s: its patterns take over %g seconds on its own examples; a scan would stall"
                           % (where, EXAMPLE_SECONDS))
    return Rule(id=rid, title=_text(spec.get("title"), where + ".title", 120), severity=sev,
                category=_category(spec.get("category", "site"), where),
                message=_text(spec.get("message"), where + ".message", 600),
                fix=_text(spec.get("fix"), where + ".fix", 600, required=False), confidence=confidence,
                langs=tuple(_strings(spec.get("langs"), where + ".langs", 32, 30)),
                files=tuple(_strings(spec.get("files"), where + ".files", 200, 50)),
                patterns=tuple(patterns), target=target, ignore=exclude, tags=("site",))


def _category(value: Any, where: str) -> str:
    if not isinstance(value, str) or not _CATEGORY.match(value):
        raise RulesetError("%s.category: lower-case letters, digits and -, up to 32 (security, site)" % where)
    if _secret_in(value):
        raise RulesetError("%s.category: looks like it holds a secret, which every report would print" % where)
    return value


def load_all(paths: Sequence[str], root: str, known: Set[str]) -> List[Ruleset]:
    out: List[Ruleset] = []
    known = set(known)
    for path in paths:
        rs = load(os.path.abspath(path), root, known)
        known |= {r.id for r in rs.rules}
        out.append(rs)
    return out
