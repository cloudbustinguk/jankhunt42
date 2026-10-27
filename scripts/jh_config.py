#!/usr/bin/env python3
"""Repo-local scanner configuration: `.jankhunt42.toml` / `.jankhunt42.json`.

Every competing scanner (Semgrep, SonarQube, ESLint, ...) lets a repo tune
which rules apply and at what severity without editing source comments one
line at a time. jankhunt42's only prior mechanism was the inline
`# jankhunt42: ignore JHxxx` pragma. This module adds a config file that is
discovered the way `.git` is discovered: walk upward from the scan root
until one is found, or none is.

Loading is read-only and best-effort: a missing file is not an error, and a
malformed one is a warning (printed to stderr, scan continues as if there
were no config) rather than a crash. stdlib only: JSON always works; TOML
only parses on Python 3.11+ (`tomllib`). Older interpreters get a warning
and the file is skipped rather than silently misread with a hand-rolled
parser.
"""
from __future__ import annotations

import fnmatch
import json
import os
import sys
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Sequence, Set, Tuple

HERE = os.path.dirname(os.path.realpath(__file__))
if HERE not in sys.path:
    sys.path.insert(0, HERE)

from jh_core import sev_at_least  # noqa: E402

CONFIG_NAMES = (".jankhunt42.toml", ".jankhunt42.json")

try:
    import tomllib  # Python 3.11+
except ImportError:  # pragma: no cover - exercised on 3.9/3.10 in CI
    tomllib = None  # type: ignore[assignment]


@dataclass
class PathRule:
    pattern: str
    ignore_rules: Set[str] = field(default_factory=set)  # rule ids, or "*" for all
    min_severity: Optional[str] = None
    severity: Dict[str, str] = field(default_factory=dict)  # rule id -> severity


@dataclass
class Config:
    source: Optional[str] = None
    rule_enabled: Dict[str, bool] = field(default_factory=dict)
    rule_severity: Dict[str, str] = field(default_factory=dict)
    path_rules: List[PathRule] = field(default_factory=list)
    ignore_globs: List[str] = field(default_factory=list)
    fail_on: Optional[str] = None
    calibrate: Optional[bool] = None
    # `passport` section: owners, asset classifications, operations
    # declarations, tighten-only policy. Repository-controlled, so every
    # consumer treats it as `declared`, never as verified or trusted.
    passport: Dict[str, object] = field(default_factory=dict)
    warnings: List[str] = field(default_factory=list)

    def is_rule_enabled(self, rule_id: str) -> bool:
        return self.rule_enabled.get(rule_id, True)

    def severity_for(self, rule_id: str, path: str, base_severity: str) -> Optional[str]:
        """Returns the effective severity, or None if this finding should be dropped."""
        sev = self.rule_severity.get(rule_id, base_severity)
        for pr in self.path_rules:
            if not fnmatch.fnmatch(path, pr.pattern) and not fnmatch.fnmatch("/" + path, pr.pattern):
                continue
            if "*" in pr.ignore_rules or rule_id in pr.ignore_rules:
                return None
            if rule_id in pr.severity:
                sev = pr.severity[rule_id]
            if pr.min_severity and not sev_at_least(sev, pr.min_severity):
                return None
        return sev


def find_config(start_dir: str) -> Optional[str]:
    """Walk upward from start_dir looking for a config file, stopping at the
    filesystem root or a `.git` directory (repo boundary)."""
    cur = os.path.abspath(start_dir)
    seen = set()
    while cur not in seen:
        seen.add(cur)
        for name in CONFIG_NAMES:
            candidate = os.path.join(cur, name)
            if os.path.isfile(candidate):
                return candidate
        if os.path.isdir(os.path.join(cur, ".git")):
            return None
        parent = os.path.dirname(cur)
        if parent == cur:
            return None
        cur = parent
    return None


def _parse_raw(path: str, contents: Optional[str] = None) -> Tuple[Optional[dict], Optional[str]]:
    if path.endswith(".toml"):
        if tomllib is None:
            return None, (
                "%s found but this interpreter has no tomllib (needs Python 3.11+); "
                "skipping. Use .jankhunt42.json for compatibility with older interpreters." % path
            )
        try:
            if contents is not None:
                return tomllib.loads(contents), None
            with open(path, "rb") as fh:
                return tomllib.load(fh), None
        except (OSError, tomllib.TOMLDecodeError, RecursionError) as exc:  # type: ignore[attr-defined]
            return None, "could not parse %s: %s" % (path, exc)
    try:
        if contents is not None:
            return json.loads(contents), None
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh), None
    except (OSError, ValueError, RecursionError) as exc:
        return None, "could not parse %s: %s" % (path, exc)


def load_config(path: Optional[str], contents: Optional[str] = None) -> Config:
    cfg = Config()
    if not path:
        return cfg
    raw, warning = _parse_raw(path, contents)
    if warning:
        cfg.warnings.append(warning)
    if raw is not None and not isinstance(raw, dict):
        cfg.warnings.append("config must be an object")
        return cfg
    if not raw:
        return cfg
    cfg.source = path

    rules = raw.get("rules", {})
    if isinstance(rules, dict):
        for rid, spec in rules.items():
            if isinstance(spec, bool):
                cfg.rule_enabled[rid] = spec
                continue
            if not isinstance(spec, dict):
                cfg.warnings.append("rules.%s: expected bool or table" % rid)
                continue
            if "enabled" in spec:
                cfg.rule_enabled[rid] = bool(spec["enabled"])
            if "severity" in spec:
                cfg.rule_severity[rid] = str(spec["severity"])

    paths = raw.get("paths", {})
    if isinstance(paths, dict):
        for pattern, spec in paths.items():
            if not isinstance(spec, dict):
                cfg.warnings.append("paths.%s: expected a table" % pattern)
                continue
            pr = PathRule(pattern=pattern)
            ignore = spec.get("ignore", [])
            if isinstance(ignore, str):
                ignore = [ignore]
            pr.ignore_rules = set(str(r) for r in ignore)
            if spec.get("min_severity"):
                pr.min_severity = str(spec["min_severity"])
            severity = spec.get("severity", {})
            if isinstance(severity, dict):
                pr.severity = {str(k): str(v) for k, v in severity.items()}
            cfg.path_rules.append(pr)

    ignore_globs = raw.get("ignore", [])
    if isinstance(ignore_globs, str):
        ignore_globs = [ignore_globs]
    cfg.ignore_globs = [str(g) for g in ignore_globs]

    if raw.get("fail_on"):
        cfg.fail_on = str(raw["fail_on"])
    if "calibrate" in raw:
        cfg.calibrate = bool(raw["calibrate"])
    passport = raw.get("passport", {})
    if isinstance(passport, dict):
        cfg.passport = passport
    else:
        cfg.warnings.append("passport: expected a table")

    return cfg


def load_config_for_root(root: str, explicit_path: Optional[str] = None,
                          disabled: bool = False) -> Config:
    if disabled:
        return Config()
    path = explicit_path or find_config(root)
    return load_config(path)


def emit_warnings(cfg: Config) -> None:
    for w in cfg.warnings:
        print("jankhunt42: config: %s" % w, file=sys.stderr)


def apply_to_findings(cfg: Config, findings: Sequence) -> List:
    """Filters/overrides findings in place according to cfg. Returns the
    surviving list; findings are mutated (severity) before being kept."""
    if not cfg.source:
        return list(findings)
    out = []
    for f in findings:
        if not cfg.is_rule_enabled(f.rule):
            continue
        sev = cfg.severity_for(f.rule, f.path, f.severity)
        if sev is None:
            continue
        f.severity = sev
        out.append(f)
    return out
