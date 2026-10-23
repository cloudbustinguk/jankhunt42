#!/usr/bin/env python3
"""Opt-in, repo-local false-positive calibration.

The industry's actual bottleneck is false-positive noise (SonarSource cites
a 3.2% FP rate across 137M issues as the bar; untuned LLM reviewers start at
40-80%). jankhunt42's rules ship with a severity and confidence baked in at
authoring time and never revisited. This module closes that loop with
counting, not inference: every `--calibrate` run records how many times
each rule fired and how many of those were suppressed (inline
`# jankhunt42: ignore` pragma) in *this* repo, in a small ledger file. Once a
rule has enough history and a high enough suppression rate, later runs
downgrade its severity and mark its confidence `low` -- transparently, with
the exact rate and sample size attached to every affected finding, never by
silently dropping it.

This is the only thing besides `--cve` that writes anything. It only runs
when `--calibrate` is passed.
"""
from __future__ import annotations

import json
import os
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence

LEDGER_RELPATH = os.path.join(".jankhunt42", "calibration.json")

MIN_OBSERVATIONS = 5
RATE_DOWNGRADE = 0.5   # >=50% suppressed, >=MIN_OBSERVATIONS fires: drop one severity step
RATE_FLOOR = 0.8        # >=80% suppressed: floor at info regardless of starting severity


@dataclass
class CalibrationNote:
    rule: str
    observations: int
    suppression_rate: float
    from_severity: str
    to_severity: str

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "observations": self.observations,
            "suppression_rate": round(self.suppression_rate, 3),
            "from": self.from_severity,
            "to": self.to_severity,
        }


def ledger_path(root: str) -> str:
    return os.path.join(root, LEDGER_RELPATH)


def load_ledger(root: str) -> Dict[str, object]:
    path = ledger_path(root)
    if not os.path.isfile(path):
        return {"version": 1, "rules": {}}
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return {"version": 1, "rules": {}}
    if not isinstance(data, dict):
        return {"version": 1, "rules": {}}
    data.setdefault("rules", {})
    return data


def save_ledger(root: str, ledger: Dict[str, object]) -> None:
    path = ledger_path(root)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(ledger, fh, indent=2, sort_keys=True)
        fh.write("\n")
    os.replace(tmp, path)


def update_ledger(ledger: Dict[str, object], fired_by_rule: Dict[str, int],
                   suppressed_by_rule: Dict[str, int]) -> None:
    rules = ledger.setdefault("rules", {})
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    for rule_id, fired in fired_by_rule.items():
        entry = rules.setdefault(rule_id, {"fired": 0, "suppressed": 0})
        entry["fired"] = int(entry.get("fired", 0)) + int(fired)
        entry["suppressed"] = int(entry.get("suppressed", 0)) + int(suppressed_by_rule.get(rule_id, 0))
        entry["last_seen"] = now


def _suppression_rate(entry: dict) -> Optional[float]:
    fired = int(entry.get("fired", 0))
    if fired < MIN_OBSERVATIONS:
        return None
    return int(entry.get("suppressed", 0)) / fired


def apply_calibration(findings: Sequence, ledger: Dict[str, object],
                       severities: Sequence[str]) -> List[CalibrationNote]:
    """Mutates findings in place (severity, confidence, tags) using ledger
    history recorded *before* this run. Returns one note per affected rule
    (not per finding) so callers can report "N findings across rule X were
    downgraded because it is suppressed Y% of the time here"."""
    rules = ledger.get("rules", {})
    if not isinstance(rules, dict):
        return []
    rank = {s: i for i, s in enumerate(severities)}
    notes: Dict[str, CalibrationNote] = {}
    for f in findings:
        entry = rules.get(f.rule)
        if not isinstance(entry, dict):
            continue
        rate = _suppression_rate(entry)
        if rate is None:
            continue
        original = f.severity
        if rate >= RATE_FLOOR:
            new_sev = severities[-1]
        elif rate >= RATE_DOWNGRADE:
            idx = min(rank.get(f.severity, 0) + 1, len(severities) - 1)
            new_sev = severities[idx]
        else:
            continue
        if new_sev == original:
            continue
        f.severity = new_sev
        f.confidence = "low"
        f.tags = tuple(f.tags) + ("calibrated",)
        if f.rule not in notes:
            notes[f.rule] = CalibrationNote(
                rule=f.rule, observations=int(entry.get("fired", 0)),
                suppression_rate=rate, from_severity=original, to_severity=new_sev,
            )
    return sorted(notes.values(), key=lambda n: n.rule)
