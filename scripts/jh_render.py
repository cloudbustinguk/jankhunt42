#!/usr/bin/env python3
"""TTY-first renderers for jankhunt42, with clean Markdown fallbacks."""
from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from jh_core import Finding, SEV_LABEL, SEV_WEIGHT, trim
from jh_doctor import DoctorResult
from jh_triage import LogCluster, TriageResult
import jh_score


def color_enabled(no_color: bool = False) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM", "") in ("dumb", ""):
        return False
    return sys.stdout.isatty()


@dataclass
class Colors:
    on: bool = True

    def _c(self, text: str, code: str) -> str:
        if not self.on:
            return text
        return "\x1b[%sm%s\x1b[0m" % (code, text)

    def bold(self, text: str) -> str:
        return self._c(text, "1")

    def dim(self, text: str) -> str:
        return self._c(text, "2")

    def italic(self, text: str) -> str:
        return self._c(text, "3")

    def red(self, text: str) -> str:
        return self._c(text, "38;5;203")

    def green(self, text: str) -> str:
        return self._c(text, "38;5;114")

    def yellow(self, text: str) -> str:
        return self._c(text, "38;5;221")

    def blue(self, text: str) -> str:
        return self._c(text, "38;5;75")

    def cyan(self, text: str) -> str:
        return self._c(text, "38;5;51")

    def magenta(self, text: str) -> str:
        return self._c(text, "38;5;201")

    def grey(self, text: str) -> str:
        return self._c(text, "38;5;245")

    def chip(self, severity: str) -> str:
        styles = {
            "blocker": "48;5;93;97",
            "critical": "48;5;196;97",
            "error": "48;5;160;97",
            "major": "48;5;208;30",
            "warning": "48;5;214;30",
            "minor": "48;5;220;30",
            "info": "48;5;240;252",
            "debug": "48;5;238;252",
            "trace": "48;5;236;252",
        }
        code = styles.get(severity, "48;5;240;252")
        label = " %s " % SEV_LABEL.get(severity, severity.upper())
        return self._c(label, code + ";1") if self.on else "[%s]" % severity.upper()

    def sev(self, severity: str, text: str, strong: bool = False) -> str:
        """Color text by severity, optionally in bold."""
        painter = {
            "blocker": self.magenta,
            "critical": self.red,
            "major": self.yellow,
            "minor": self.cyan,
            "info": self.grey,
        }.get(severity, self.grey)
        painted = painter(text)
        return self.bold(painted) if strong else painted

    def confidence(self, confidence: str, text: str) -> str:
        painter = {"high": self.green, "medium": self.yellow, "low": self.grey}.get(
            confidence, self.grey)
        return self.bold(painter(text))

    def gradient(self, text: str, start: int = 51, end: int = 201) -> str:
        if not self.on:
            return text
        out = []
        n = max(1, len(text) - 1)
        for i, ch in enumerate(text):
            if ch == " ":
                out.append(ch)
                continue
            mix = i / n
            code = int(start + (end - start) * mix)
            out.append("\x1b[38;5;%dm%s" % (code, ch))
        out.append("\x1b[0m")
        return "".join(out)


def _visible(text: str) -> int:
    return len(re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text))


def _pad(text: str, width: int) -> str:
    return text + " " * max(0, width - _visible(text))


def _truncate(text: str, width: int) -> str:
    plain = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", text)
    if len(plain) <= width:
        return text
    return plain[: max(0, width - 1)] + "…"


def _bar(value: int, worst: int, width: int, color: Colors, tone: Optional[str] = None) -> str:
    if worst <= 0:
        return ""
    filled = max(1, min(width, int(round(width * value / worst)))) if value else 0
    ch = "█"
    if tone == "red":
        colored = color.red(ch * filled)
    elif tone == "green":
        colored = color.green(ch * filled)
    else:
        colored = color.cyan(ch * filled)
    return colored + color.dim("░" * (width - filled))


def jank_score(findings: Sequence[Finding], loc: int) -> int:
    """Backward-compatible headline score; details live in jh_score.compute()."""
    return jh_score.compute(findings, loc).score


def score_label(score: int) -> str:
    return jh_score.label_for(score)


def score_color(score: int) -> str:
    if score <= 15:
        return "green"
    if score <= 30:
        return "cyan"
    if score <= 50:
        return "yellow"
    if score <= 70:
        return "red"
    return "red"


def _width(default: int = 78) -> int:
    try:
        cols = shutil.get_terminal_size((80, 24)).columns
    except OSError:
        cols = 80
    return max(52, min(96, cols - 4))


def _boxed(lines: Sequence[str], color: Colors, width: int, accent: str = "cyan") -> List[str]:
    out = []
    top = "╭" + "─" * (width - 2) + "╮"
    bot = "╰" + "─" * (width - 2) + "╯"
    painter = getattr(color, accent, color.cyan)
    out.append(painter(top))
    for line in lines:
        out.append(painter("│") + " " + _pad(_truncate(line, width - 4), width - 4) + " " + painter("│"))
    out.append(painter(bot))
    return out


def banner(subtitle: str, meta: str, color: Colors, width: int) -> List[str]:
    word = "J A N K H U N T 4 2"
    title = "  " + color.gradient(word) + "   " + color.dim("// " + subtitle)
    lines = [title, color.grey(meta)]
    return _boxed(lines, color, width, "magenta")


def _scan_markdown_meta(result, meta: Dict[str, object], root: str,
                       report: "jh_score.ScoreReport", findings: Sequence[Finding]) -> List[str]:
    out: List[str] = []
    if meta.get("elapsed") is not None:
        out.append("")
        out.append("_Scan time: %.2fs · rule engine %s_" % (
            float(meta["elapsed"]), "with CVE lookup" if meta.get("cve") else "offline"))
    if meta.get("cve_warnings"):
        out.append("")
        for warning in meta["cve_warnings"]:
            out.append("> CVE lookup: %s" % warning)
    if meta.get("config"):
        out.append("")
        out.append("_Config: `%s`_" % meta["config"])
    dupes = meta.get("cross_file_duplicates") or []
    if dupes:
        out.append("")
        out.append("### Cross-file duplicates")
        out.append("")
        out.append("Same defect repeated across files — fix the class, not the line.")
        out.append("")
        out.append("| Rule | Title | Sites | Locations |")
        out.append("|---|---|---:|---|")
        for d in dupes[:20]:
            locs = ", ".join("`%s:%d`" % (s["path"], s["line"]) for s in d["sites"][:6])
            if d["count"] > 6:
                locs += ", …"
            out.append("| `%s` | %s | %d | %s |" % (d["rule"], d["title"], d["count"], locs))
    calib = meta.get("calibration")
    if calib and calib.get("downgrades"):
        out.append("")
        out.append("### Calibration")
        out.append("")
        out.append("Rules downgraded from this repo's recorded suppression history "
                   "(`%s`):" % calib.get("ledger", ""))
        out.append("")
        out.append("| Rule | Observations | Suppressed | Severity |")
        out.append("|---|---:|---:|---|")
        for n in calib["downgrades"]:
            out.append("| `%s` | %d | %.0f%% | %s → %s |"
                       % (n["rule"], n["observations"], n["suppression_rate"] * 100,
                          n["from"], n["to"]))
    out.append("")
    out.append("## Summary")
    out.append("")
    out.append("| Severity | Count |")
    out.append("|---|---:|")
    counts = _counts(findings)
    for sev in ("blocker", "critical", "major", "minor", "info"):
        if counts.get(sev):
            out.append("| %s | %d |" % (sev, counts[sev]))
    if not counts:
        out.append("| — | 0 |")
    out.append("")
    out.append("### Score by dimension")
    out.append("")
    out.append("| Dimension | Score | Grade | Findings | Worst | Top rule |")
    out.append("|---|---:|---|---:|---|---|")
    for key in jh_score.DIMENSIONS:
        d = report.dimensions[key]
        top = ("`%s` ×%d" % (d.top_rules[0][0], d.top_rules[0][1])) if d.top_rules else "—"
        out.append("| %s | %d | **%s** | %d | %s | %s |"
                   % (d.label, d.score, d.grade, d.findings, d.worst, top))
    out.append("")
    out.append("_Score %s: severity × confidence × exposure, density per KLOC, "
               "severity floors, and a weakest-dimension anchor. It prioritizes; it "
               "does not certify. Gate CI on `--fail-on`._" % report.version)
    if meta.get("new_code"):
        nc = meta["new_code"]
        out.append("")
        if nc.get("warning"):
            out.append("> New-code view unavailable: %s" % nc["warning"])
        else:
            out.append("**New code since `%s`:** %d findings · **%d/100 (%s · %s)** · policy **%s**"
                       % (nc.get("since", "?"), nc.get("findings", 0), nc.get("score", 0),
                          nc.get("grade", "A"), nc.get("label", "pristine"), nc.get("policy", "pass")))
    out.append("")
    top_rules = _top_rules(findings, 8)
    if top_rules:
        out.append("### Top rules")
        out.append("")
        out.append("| Rule | Title | Count |")
        out.append("|---|---|---:|")
        for rid, title, count in top_rules:
            out.append("| `%s` | %s | %d |" % (rid, title, count))
        out.append("")
    return out


def _scan_markdown_findings(findings: Sequence[Finding], max_findings: int) -> List[str]:
    out: List[str] = []
    if findings:
        out.append("## Findings")
        out.append("")
        by_file: Dict[str, List[Finding]] = {}
        for f in findings[:max_findings]:
            by_file.setdefault(f.path, []).append(f)
        for path, items in by_file.items():
            out.append("### `%s`" % path)
            out.append("")
            for f in items:
                out.append("- **[%s] %s · %s — %s** `%s:%d` · confidence %s"
                           % (f.rule, f.severity.upper(), f.category, f.title, f.path, f.line, f.confidence))
                if f.evidence:
                    out.append("  - evidence: `%s`" % f.evidence.replace("`", "\\`"))
                if f.message:
                    out.append("  - why: %s" % f.message)
                if f.fix:
                    out.append("  - fix: %s" % f.fix)
            out.append("")
        if len(findings) > max_findings:
            out.append("_Showing %d of %d findings. Use `--json` or `--sarif` for the full set._"
                       % (max_findings, len(findings)))
    else:
        out.append("## Findings")
        out.append("")
        out.append("No findings from the built-in rule set. This is not proof of correctness: "
                   "run the project's compiler, tests, linters, and sanitizers.")
    return out


def scan_markdown(result, meta: Dict[str, object], max_findings: int = 300) -> str:
    findings: List[Finding] = result.findings
    root = str(meta.get("root", "."))
    report = jh_score.compute(findings, result.loc)
    out: List[str] = ["# JankHunt42 scan", ""]
    out.append("**Root:** `%s` · **Files:** %d · **LOC:** %d · **Findings:** %d · **Jank:** %d/100 (%s · %s) · policy **%s**"
               % (root, result.files, result.loc, len(findings), report.score,
                  report.grade, report.label, report.policy))
    out.extend(_scan_markdown_meta(result, meta, root, report, findings))
    out.extend(_scan_markdown_findings(findings, max_findings))
    return "\n".join(out)


def _counts(findings: Sequence[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def _top_rules(findings: Sequence[Finding], n: int) -> List[Tuple[str, str, int]]:
    agg: Dict[str, Tuple[str, int]] = {}
    for f in findings:
        title, count = agg.get(f.rule, (f.title, 0))
        agg[f.rule] = (title, count + 1)
    rows = [(rid, title, count) for rid, (title, count) in agg.items()]
    rows.sort(key=lambda x: (-x[2], x[0]))
    return rows[:n]


def _top_files(findings: Sequence[Finding], n: int = 5) -> List[Tuple[str, int, int]]:
    agg: Dict[str, Tuple[int, int]] = {}
    for f in findings:
        weight, count = agg.get(f.path, (0, 0))
        agg[f.path] = (weight + SEV_WEIGHT.get(f.severity, 1), count + 1)
    rows = [(path, count, weight) for path, (weight, count) in agg.items()]
    rows.sort(key=lambda x: (-x[2], -x[1], x[0]))
    return rows[:n]


def _tty_summary(counts: Dict[str, int], meta: Dict[str, object], color: "Colors") -> List[str]:
    out: List[str] = []
    sev_bits = []
    for sev in ("blocker", "critical", "major", "minor", "info"):
        if counts.get(sev):
            sev_bits.append("%s %s" % (color.chip(sev), color.bold(str(counts[sev]))))
    if sev_bits:
        out.append("  " + "   ".join(sev_bits))
    else:
        out.append("  " + color.green("no findings — suspiciously clean"))
    if meta.get("cve"):
        warn = meta.get("cve_warnings") or []
        note = "CVE lookup: %s packages" % meta.get("cve_packages", 0)
        if warn:
            note += " · " + "; ".join(str(w) for w in warn[:1])
        out.append("  " + color.magenta("CVE") + "  " + color.grey(note))
    if meta.get("config"):
        out.append("  " + color.cyan("CONFIG") + "  " + color.grey(str(meta["config"])))
    dupes = meta.get("cross_file_duplicates") or []
    if dupes:
        sites = sum(d["count"] for d in dupes)
        out.append("  " + color.yellow("DUPLICATE") + "  "
                   + color.grey("%d cluster(s) across %d sites — same bug, not one bug"
                                % (len(dupes), sites)))
    calib = meta.get("calibration")
    if calib:
        n = len(calib.get("downgrades") or [])
        if n:
            out.append("  " + color.cyan("CALIBRATED") + "  "
                       + color.grey("%d rule(s) downgraded from this repo's suppression history "
                                    "(%s)" % (n, calib.get("ledger", ""))))
        else:
            out.append("  " + color.grey("calibration: no rule crossed the suppression-rate threshold yet"))
    return out


def _tty_offenders(findings: Sequence[Finding], width: int, color: "Colors") -> List[str]:
    out: List[str] = []
    files = _top_files(findings, 5)
    if files:
        worst = files[0][2]
        out.append("  " + color.bold("TOP OFFENDERS"))
        for path, count, weight in files:
            path_col = min(42, width - 24)
            out.append("    %s %s %s" % (
                _pad(color.bold(_truncate(path, path_col)), path_col),
                _bar(weight, worst, max(8, width - 56), color, "red"),
                color.grey("%d finding%s" % (count, "" if count == 1 else "s")),
            ))
        out.append("")
    rules = _top_rules(findings, 5)
    if rules:
        worst = rules[0][2]
        out.append("  " + color.bold("TOP RULES"))
        for rid, title, count in rules:
            title_col = min(38, width - 28)
            out.append("    %s  %s %s %s" % (
                color.bold(color.cyan(rid)),
                _pad(_truncate(title, title_col), title_col),
                _bar(count, worst, max(6, width - 62), color),
                color.grey("×%d" % count),
            ))
        out.append("")
    return out


def _tty_finding_cards(findings: Sequence[Finding], max_findings: int, width: int,
                       color: "Colors") -> List[str]:
    out: List[str] = []
    for idx, f in enumerate(findings[:max_findings], 1):
        rail = color.sev(f.severity, "┃", strong=True)
        head = "  %s %s  %s  %s  %s" % (
            rail,
            color.sev(f.severity, "%02d" % idx, strong=True),
            color.chip(f.severity),
            color.sev(f.severity, f.rule, strong=True),
            color.bold(_truncate(f.title, width - 38)),
        )
        out.append(head)
        out.append("  %s     %s  %s  %s %s" % (
            rail,
            color.bold(f.path) + color.sev(f.severity, ":%d" % f.line, strong=True),
            color.blue(f.category),
            color.grey("confidence"),
            color.confidence(f.confidence, f.confidence),
        ))
        if f.evidence:
            out.append("  %s     %s%s%s" % (
                rail,
                color.dim("│ "),
                color.bold(color.grey("evidence ")),
                _truncate(f.evidence, width - 23),
            ))
        if f.message:
            out.append("  %s     %s%s%s" % (
                rail,
                color.dim("└ "),
                color.sev(f.severity, "why ", strong=True),
                _wrap(f.message, width - 22, "  " + rail + "           "),
            ))
        if f.fix:
            out.append("  %s       %s%s" % (
                rail,
                color.bold(color.green("fix ")),
                _truncate(f.fix, width - 22),
            ))
        out.append("")
    if len(findings) > max_findings:
        out.append("  " + color.yellow("… %d more findings hidden" % (len(findings) - max_findings)))
        out.append("  " + color.grey("use --json for the full set, or --max-findings N"))
        out.append("")
    return out


def scan_tty(result, meta: Dict[str, object], max_findings: int = 300) -> str:
    color = Colors(True)
    width = _width()
    findings: List[Finding] = result.findings
    counts = _counts(findings)
    root = str(meta.get("root", "."))
    elapsed = meta.get("elapsed")
    meta_line = "%s  ·  %s files  ·  %s LOC%s" % (
        root,
        f"{result.files:,}",
        f"{result.loc:,}",
        ("  ·  %.2fs" % float(elapsed)) if elapsed is not None else "",
    )
    out: List[str] = banner("code autopsy lab", meta_line, color, width)
    out.append("")
    report = jh_score.compute(findings, result.loc)
    if meta.get("new_code"):
        report.new_code = meta["new_code"]
    out.extend(jh_score.scorecard_tty(report, color, width))
    out.append("")
    out.extend(_tty_summary(counts, meta, color))
    out.append("")
    out.extend(_tty_offenders(findings, width, color))
    out.append(color.dim("  " + "─" * (width - 4)))
    worst = findings[0].severity if findings else "info"
    out.append("  " + color.bold("FINDINGS") + color.grey("  ·  ")
               + color.sev(worst, "%d" % len(findings), strong=True)
               + color.grey(" findings  ·  worst first"))
    out.append("")
    if not findings:
        out.append("  " + color.green("✦ no jank detected by the built-in rules"))
        out.append("  " + color.grey("Absence of evidence is not evidence of absence: "
                                      "run the compiler, tests, linters, and sanitizers."))
        return "\n".join(out)
    out.extend(_tty_finding_cards(findings, max_findings, width, color))
    out.append(color.dim("  " + "─" * (width - 4)))
    out.append("  " + color.grey("next: ") + color.cyan("jankhunt42 scan . --json") + color.grey("  ·  ")
               + color.cyan("jankhunt42 triage app.log") + color.grey("  ·  read references/playbooks.md"))
    return "\n".join(out)


def _wrap(text: str, width: int, indent: str) -> str:
    words = text.split()
    lines: List[str] = []
    cur = ""
    for word in words:
        if cur and len(cur) + 1 + len(word) > width:
            lines.append(cur)
            cur = word
        else:
            cur = (cur + " " + word).strip()
    if cur:
        lines.append(cur)
    return ("\n" + indent).join(lines)


def triage_tty(result: TriageResult, top: int = 30) -> str:
    color = Colors(True)
    width = _width()
    out: List[str] = []
    sources = ", ".join(result.sources)
    out.extend(banner("log autopsy", "%s  ·  %s lines  ·  %s events  ·  %s clusters"
                      % (sources, f"{result.lines:,}", f"{result.events:,}", len(result.clusters)), color, width))
    out.append("")
    counts = result.counts
    max_count = max(counts.values()) if counts else 1
    for sev in ("critical", "error", "warning", "info", "debug", "trace"):
        if counts.get(sev):
            out.append("  %s %s %s" % (color.chip(sev),
                                       color.bold("%6d" % counts[sev]),
                                       _bar(counts[sev], max_count, max(10, width - 40), color, "red" if sev in ("critical", "error") else None)))
    out.append("")
    if not result.clusters:
        out.append("  " + color.yellow("no severity-tagged or exception-like lines"))
        out.append("  " + color.grey("try --grep 'timeout|refused|panic' or inspect the raw tail"))
        return "\n".join(out)
    out.append("  " + color.dim("─" * (width - 4)))
    out.append("  " + color.bold("TOP CLUSTERS") + color.grey("  ·  fingerprint → count"))
    out.append("")
    for idx, c in enumerate(result.clusters[:top], 1):
        out.append("  %02d  %s  %s" % (idx, color.chip(c.severity), color.bold(_truncate(c.message, width - 20))))
        span = "line %d" % c.first_line
        if c.last_line and c.last_line != c.first_line:
            span += " → %d" % c.last_line
        if c.first_ts or c.last_ts:
            span += "  ·  %s → %s" % (c.first_ts or "?", c.last_ts or "?")
        out.append("      " + color.grey(span + ("  · stack attached" if c.has_stack else "")))
        for sample in c.samples[:3]:
            out.append("      " + color.grey("│ ") + color.dim(_truncate(sample, width - 10)))
        out.append("")
    return "\n".join(out)


def doctor_tty(result: DoctorResult) -> str:
    color = Colors(True)
    width = _width()
    from jh_doctor import doctor_markdown
    md = doctor_markdown(result)
    return "\n".join(banner("project doctor", result.root, color, width) + [""] + _colorize_markdown(md, color))


def _colorize_markdown(md: str, color: Colors) -> List[str]:
    out: List[str] = []
    in_code = False
    for line in md.splitlines():
        if line.startswith("```"):
            in_code = not in_code
            out.append(color.grey(line))
            continue
        if in_code:
            out.append(color.dim("  " + line))
            continue
        if line.startswith("# "):
            out.append(color.gradient(line[2:]))
        elif line.startswith("## "):
            out.append(color.cyan("▸ " + line[3:]))
        elif line.startswith("### "):
            out.append(color.blue("  " + line[4:]))
        elif line.startswith("|"):
            out.append(color.grey(line))
        elif line.startswith("- "):
            out.append("  " + color.cyan("• ") + _inline(line[2:], color))
        else:
            out.append(_inline(line, color))
    return out


def _inline(text: str, color: Colors) -> str:
    text = re.sub(r"\*\*([^*]+)\*\*", lambda m: color.bold(m.group(1)), text)
    text = re.sub(r"`([^`]+)`", lambda m: color.cyan(m.group(1)), text)
    return text


def render_scan(result, meta: Dict[str, object], tty: bool, no_color: bool,
                max_findings: int = 300) -> str:
    if tty and not no_color:
        return scan_tty(result, meta, max_findings)
    return scan_markdown(result, meta, max_findings)


def render_triage(result: TriageResult, tty: bool, no_color: bool, top: int = 30) -> str:
    if tty and not no_color:
        return triage_tty(result, top)
    from jh_triage import triage_markdown
    return triage_markdown(result, top)


def render_doctor(result: DoctorResult, tty: bool, no_color: bool) -> str:
    if tty and not no_color:
        return doctor_tty(result)
    from jh_doctor import doctor_markdown
    return doctor_markdown(result)
