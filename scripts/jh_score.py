#!/usr/bin/env python3
"""Jank Score 2.0 — a transparent, density-based risk score.

Philosophy borrowed, formulas our own:

* SonarQube separates security, reliability, and maintainability ratings, uses
  A-E grades, measures debt density, and focuses on new code ("Clean as You
  Code"). We keep the separation, the grades, the density, and the new-code
  view, but replace "technical debt in days" with risk points so we never invent
  precision we do not have.
* Veracode combines severity with confidence and applies policy gates to
  high-severity, high-confidence flaws. We use severity x confidence x exposure,
  then apply an explicit advisory policy to the result.

The headline is deliberately anchored to the weakest dimension. A security
catastrophe must not be averaged away by a thousand pristine style lines.
"""
from __future__ import annotations

import math
import re
import subprocess
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Set, Tuple

from jh_core import Finding, SEV_RANK, SEVERITIES

SCORE_VERSION = "2.0"

# Severity is potential impact. Confidence is how much we trust the finding.
SEV_POINTS = {"blocker": 40.0, "critical": 20.0, "major": 8.0, "minor": 3.0, "info": 1.0}
CONF_FACTOR = {"high": 1.0, "medium": 0.65, "low": 0.30}

# Exposure is a coarse, honest proxy for reachability. We do not pretend to have
# data-flow analysis: runtime security and reliability code counts fully; style,
# tests, and docs are discounted because they are less likely to hurt a user.
EXPOSURE = {
    "security": 1.00,
    "reliability": 1.00,
    "supply-chain": 1.00,
    "agent": 1.00,
    "ci": 0.90,
    "maintainability": 0.55,
    "tests": 0.45,
    "docs": 0.25,
}

DIMENSIONS = ("security", "reliability", "maintainability", "tests")
DIMENSION_LABELS = {
    "security": "Security",
    "reliability": "Reliability",
    "maintainability": "Maintainability",
    "tests": "Test confidence",
}
DIMENSION_WEIGHTS = {"security": 0.35, "reliability": 0.30, "maintainability": 0.20, "tests": 0.15}
DIMENSION_K = {"security": 25.0, "reliability": 35.0, "maintainability": 45.0, "tests": 30.0}

# SonarQube-style rating floors: a single severe issue makes the dimension
# severe even in a large codebase. The floor is scaled by confidence and
# exposure so a low-confidence style hit cannot dominate.
SEV_FLOOR = {"blocker": 80.0, "critical": 55.0, "major": 30.0, "minor": 12.0, "info": 2.0}

GRADE_BANDS = ((5, "A"), (15, "B"), (35, "C"), (60, "D"), (100, "E"))

CATEGORY_DIMENSION = {
    "security": "security",
    "supply-chain": "security",
    "agent": "security",
    "ci": "security",
    "reliability": "reliability",
    "maintainability": "maintainability",
    "docs": "maintainability",
    "tests": "tests",
}

MAX_PER_RULE_FULL = 10
EXTRA_RULE_WEIGHT = 0.10


def dimension_for(finding: Finding) -> str:
    return CATEGORY_DIMENSION.get(finding.category, "maintainability")


def grade_for(score: float) -> str:
    for ceiling, grade in GRADE_BANDS:
        if score <= ceiling:
            return grade
    return "E"


def label_for(score: float) -> str:
    if score <= 5:
        return "pristine"
    if score <= 15:
        return "mild jank"
    if score <= 35:
        return "spicy"
    if score <= 60:
        return "grimy"
    if score <= 85:
        return "biohazard"
    return "call the priest"


def finding_points(f: Finding) -> float:
    return SEV_POINTS.get(f.severity, 1.0) * CONF_FACTOR.get(f.confidence, 0.65)


def _counted_points(items: Sequence[Finding]) -> float:
    """Count a rule's findings, but let a flood of one pattern saturate."""
    by_rule: Dict[str, List[Finding]] = {}
    for f in items:
        by_rule.setdefault(f.rule, []).append(f)
    total = 0.0
    for group in by_rule.values():
        group = sorted(group, key=finding_points, reverse=True)
        total += sum(finding_points(f) for f in group[:MAX_PER_RULE_FULL])
        total += EXTRA_RULE_WEIGHT * sum(finding_points(f) for f in group[MAX_PER_RULE_FULL:])
    return total


@dataclass
class DimensionScore:
    key: str
    label: str
    score: int
    grade: str
    points: float
    density: float
    findings: int
    counted: int
    worst: str
    top_rules: List[Tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "score": self.score,
            "grade": self.grade,
            "points": round(self.points, 2),
            "density_per_kloc": round(self.density, 2),
            "findings": self.findings,
            "counted": self.counted,
            "worst_severity": self.worst,
            "top_rules": [{"rule": rid, "count": count} for rid, count in self.top_rules],
        }


@dataclass
class ScoreReport:
    version: str
    score: int
    grade: str
    label: str
    policy: str
    weighted: float
    worst_dimension: str
    dimensions: Dict[str, DimensionScore]
    findings: int
    loc: int
    counted: int
    new_code: Optional[Dict[str, Any]] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "version": self.version,
            "score": self.score,
            "grade": self.grade,
            "label": self.label,
            "policy": self.policy,
            "weighted_score": round(self.weighted, 2),
            "worst_dimension": self.worst_dimension,
            "findings": self.findings,
            "counted_findings": self.counted,
            "loc": self.loc,
            "dimensions": {k: v.to_dict() for k, v in self.dimensions.items()},
            "new_code": self.new_code,
            "formula": (
                "risk_points = severity_weight x confidence x exposure; "
                "dimension = 100*(1-exp(-points_per_kloc/K)); "
                "dimension = max(density_score, severity_floor); "
                "headline = round(0.7*worst + 0.3*weighted_average)"
            ),
            "grade_bands": {"A": "0-5", "B": "6-15", "C": "16-35", "D": "36-60", "E": "61-100"},
            "policy_rules": (
                "fail: any dimension >= 61, overall >= 61, or a high/medium-confidence "
                "blocker or high-confidence critical in security/reliability; "
                "warn: overall >= 16, any dimension >= 16, or a medium-confidence "
                "critical/high-confidence major in security/reliability; else pass"
            ),
        }


def _dimension(items: Sequence[Finding], loc: int, key: str) -> DimensionScore:
    exp = EXPOSURE[key]
    raw = _counted_points(items) * exp
    denom = max(0.25, float(loc) / 1000.0)
    density = raw / denom
    exp_score = 100.0 * (1.0 - math.exp(-density / DIMENSION_K[key]))
    floor = 0.0
    for f in items:
        candidate = SEV_FLOOR.get(f.severity, 2.0) * CONF_FACTOR.get(f.confidence, 0.65) * exp
        if candidate > floor:
            floor = candidate
    score = max(exp_score, floor)
    score = max(0, min(100, int(round(score))))
    worst = "none"
    if items:
        worst = min((f.severity for f in items), key=lambda s: SEV_RANK.get(s, 9))
    counts: Dict[str, int] = {}
    for f in items:
        counts[f.rule] = counts.get(f.rule, 0) + 1
    top = sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))[:3]
    return DimensionScore(
        key=key, label=DIMENSION_LABELS[key], score=score, grade=grade_for(score),
        points=raw, density=density, findings=len(items), counted=len(items),
        worst=worst, top_rules=top,
    )


def _policy(findings: Sequence[Finding], dims: Dict[str, DimensionScore], overall: int) -> str:
    fail = False
    warn = False
    for f in findings:
        dim = dimension_for(f)
        if dim not in ("security", "reliability"):
            continue
        if f.severity == "blocker" and f.confidence in ("high", "medium"):
            fail = True
        elif f.severity == "critical" and f.confidence == "high":
            fail = True
        elif f.severity in ("blocker", "critical") and f.confidence in ("high", "medium"):
            warn = True
        elif f.severity == "major" and f.confidence == "high":
            warn = True
    if any(d.score >= 61 for d in dims.values()):
        fail = True
    if overall >= 61:
        fail = True
    if overall >= 16 or any(d.score >= 16 for d in dims.values()):
        warn = True
    if fail:
        return "fail"
    if warn:
        return "warn"
    return "pass"


def compute(findings: Sequence[Finding], loc: int) -> ScoreReport:
    items = list(findings)
    loc = max(0, int(loc or 0))
    dims = {key: _dimension([f for f in items if dimension_for(f) == key], loc, key)
            for key in DIMENSIONS}
    weighted = sum(DIMENSION_WEIGHTS[k] * dims[k].score for k in DIMENSIONS)
    worst_key = max(DIMENSIONS, key=lambda k: dims[k].score)
    worst = dims[worst_key].score
    overall = int(round(0.7 * worst + 0.3 * weighted))
    overall = max(0, min(100, overall))
    return ScoreReport(
        version=SCORE_VERSION,
        score=overall,
        grade=grade_for(overall),
        label=label_for(overall),
        policy=_policy(items, dims, overall),
        weighted=weighted,
        worst_dimension=worst_key,
        dimensions=dims,
        findings=len(items),
        loc=loc,
        counted=sum(d.counted for d in dims.values()),
    )


def scorecard_markdown(report: ScoreReport, heading: str = "## Jank score") -> str:
    out: List[str] = [heading, ""]
    out.append("**%d/100 · %s · %s** · policy **%s**"
               % (report.score, report.grade, report.label, report.policy))
    out.append("")
    out.append("_Score %s: severity × confidence × exposure, density per KLOC, "
               "severity floors, and a weakest-dimension anchor._" % report.version)
    out.append("")
    out.append("| Dimension | Score | Grade | Findings | Worst | Top rule |")
    out.append("|---|---:|---|---:|---|---|")
    for key in DIMENSIONS:
        d = report.dimensions[key]
        top = ("`%s` ×%d" % (d.top_rules[0][0], d.top_rules[0][1])) if d.top_rules else "—"
        out.append("| %s | %d | **%s** | %d | %s | %s |"
                   % (d.label, d.score, d.grade, d.findings, d.worst, top))
    out.append("")
    out.append("> A severe dimension anchors the headline; a security catastrophe "
               "is not averaged away by clean style. The score is a prioritization "
               "device, not a compliance certificate. Gate CI on `--fail-on`.")
    if report.new_code:
        nc = report.new_code
        if nc.get("warning"):
            out.append("")
            out.append("> New-code view unavailable: %s" % nc["warning"])
        else:
            out.append("")
            out.append("**New code since `%s`:** %d changed lines · %d findings · "
                       "**%d/100 (%s)** · policy **%s**"
                       % (nc.get("since", "?"), nc.get("changed_lines", 0),
                          nc.get("findings", 0), nc.get("score", 0),
                          nc.get("grade", "A"), nc.get("policy", "pass")))
    return "\n".join(out)


def scorecard_tty(report: ScoreReport, color: Any, width: int) -> List[str]:
    """Return colored scorecard lines. `color` is a jh_render.Colors-like object."""
    out: List[str] = []
    # Tones and grade colours follow the HTML scan report (score ring bands,
    # grade badges); jh_render.score_tone is the shared banding.
    from jh_render import score_tone
    gauge_width = max(16, width - 36)
    filled = int(round(gauge_width * report.score / 100.0))
    tone = score_tone(report.score)
    gauge = color.tone(tone, "█" * filled) + color.dim("░" * (gauge_width - filled))
    out.append("  %s  %s  %s  %s %s  %s" % (
        color.bold("JANK"), gauge, color.bold("%3d/100" % report.score),
        color.grade(report.grade), color.bold(color.tone(tone, report.label)),
        (color.green if report.policy == "pass" else color.red)("policy " + report.policy),
    ))
    bar_width = max(8, width - 48)
    for key in DIMENSIONS:
        d = report.dimensions[key]
        dfill = int(round(bar_width * d.score / 100.0))
        dtone = score_tone(d.score)
        dbar = color.tone(dtone, "█" * dfill) + color.dim("░" * (bar_width - dfill))
        out.append("  %-16s %s  %3d  %s  %s" % (
            d.label, dbar, d.score, color.grade(d.grade),
            color.grey("%d finding%s" % (d.findings, "" if d.findings == 1 else "s")),
        ))
    if report.new_code:
        nc = report.new_code
        if nc.get("warning"):
            out.append("  " + color.yellow("new code unavailable: ") + color.grey(str(nc["warning"])))
        else:
            out.append("  " + color.cyan("NEW CODE") + color.grey(
                " since %s  ·  %d findings  ·  %d/100 (%s)  ·  policy %s"
                % (nc.get("since", "?"), nc.get("findings", 0), nc.get("score", 0),
                   nc.get("grade", "A"), nc.get("policy", "pass"))))
    return out


# ---------------------------------------------------------------------------
# Changed-line discovery for the "new code" view
# ---------------------------------------------------------------------------

_HUNK_RE = re.compile(r"^@@ -\d+(?:,\d+)? \+(\d+)(?:,(\d+))? @@")


def changed_lines(root: str, since: str = "HEAD") -> Tuple[Optional[Dict[str, Set[int]]], Optional[str]]:
    """Return {relative path: changed new-line numbers} for `git diff <since>`.

    Read-only. Returns (None, warning) when git or the revision is unavailable.
    """
    try:
        proc = subprocess.run(
            ["git", "-C", root, "diff", "--unified=0", "--no-color", "--no-ext-diff",
             "--no-prefix", str(since), "--"],
            capture_output=True, text=True, timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return None, str(exc)
    if proc.returncode != 0:
        msg = (proc.stderr or "git diff failed").strip().splitlines()
        return None, msg[0] if msg else "git diff failed"
    changed: Dict[str, Set[int]] = {}
    current: Optional[str] = None
    for line in proc.stdout.splitlines():
        if line.startswith("+++ "):
            name = line[4:].strip()
            if name == "/dev/null":
                current = None
            else:
                current = name.replace("\\", "/")
                changed.setdefault(current, set())
            continue
        m = _HUNK_RE.match(line)
        if m and current:
            start = int(m.group(1))
            count = int(m.group(2)) if m.group(2) is not None else 1
            if count > 0:
                changed[current].update(range(start, start + count))
    return changed, None


def new_code_findings(findings: Sequence[Finding], changed: Dict[str, Set[int]]) -> List[Finding]:
    out: List[Finding] = []
    for f in findings:
        path = f.path.replace("\\", "/")
        lines = changed.get(path)
        if not lines:
            continue
        end = f.end_line or f.line
        if f.line in lines or any(ln in lines for ln in range(f.line, max(f.line, end) + 1)):
            out.append(f)
    return out


def changed_loc(changed: Dict[str, Set[int]]) -> int:
    return sum(len(lines) for lines in changed.values())


def compute_new_code(findings: Sequence[Finding], changed: Dict[str, Set[int]],
                     since: str) -> Tuple[ScoreReport, Dict[str, Any]]:
    subset = new_code_findings(findings, changed)
    loc = changed_loc(changed)
    report = compute(subset, loc)
    meta = {
        "since": since,
        "changed_files": len(changed),
        "changed_lines": loc,
        "findings": len(subset),
        "score": report.score,
        "grade": report.grade,
        "label": report.label,
        "policy": report.policy,
        "dimensions": {k: v.to_dict() for k, v in report.dimensions.items()},
    }
    return report, meta
