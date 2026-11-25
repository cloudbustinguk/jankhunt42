#!/usr/bin/env python3
"""TTY-first renderers for jankhunt42, with clean Markdown fallbacks."""
from __future__ import annotations

import os
import re
import shutil
import sys
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Sequence, Tuple

from jh_core import Finding, SEV_LABEL, SEV_WEIGHT, safe_text
import jh_score
from jh_frameworks import OWASP_RISKS, owasp
from jh_prompt import combined


def color_enabled(no_color: bool = False) -> bool:
    if no_color or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    if os.environ.get("TERM", "") in ("dumb", ""):
        return False
    return sys.stdout.isatty()


# Terminal palettes mirror the HTML views: "scan" is the scan report's
# palette (jh_html), "explorer" the map/passport explorer's (jh_explorer),
# and "light" the explorer's light theme for light-background terminals.
PALETTES: Dict[str, Dict[str, str]] = {
    "scan": {"red": "#ff4d6d", "green": "#35d39a", "yellow": "#ffd166", "orange": "#ff9f43",
             "blue": "#5fafff", "cyan": "#4fd1ff", "magenta": "#ff4fd8", "violet": "#7c5cff",
             "grey": "#98a2b8"},
    "explorer": {"red": "#ff6b6b", "green": "#62d98b", "yellow": "#ffd166", "orange": "#ff9f43",
                 "blue": "#5fafff", "cyan": "#38e1ff", "magenta": "#ff4fd8", "violet": "#a78bfa",
                 "grey": "#8a93a8"},
    "light": {"red": "#c0392b", "green": "#1d8a4b", "yellow": "#946200", "orange": "#b35900",
              "blue": "#1f5fbf", "cyan": "#0077a8", "magenta": "#b0128f", "violet": "#6941c6",
              "grey": "#5a6275"},
}
SEV_COLOR = {"blocker": "#c77dff", "critical": "#ff4d6d", "error": "#ff4d6d", "major": "#ff9f43",
             "warning": "#ff9f43", "minor": "#ffd166", "info": "#8b95ab", "debug": "#6b7280",
             "trace": "#4b5563"}
GRADE_COLOR = {"A": "#35d39a", "B": "#4fd1ff", "C": "#ffd166", "D": "#ff9f43", "E": "#ff4d6d"}
CHIP_TEXT = "#07090e"


def truecolor() -> bool:
    return os.environ.get("COLORTERM", "").lower() in ("truecolor", "24bit")


def light_background() -> bool:
    """COLORFGBG ("fg;bg", set by many terminals) with a light background
    colour (7 or 15) selects the light palette."""
    bg = os.environ.get("COLORFGBG", "").split(";")[-1]
    return bg in ("7", "15")


def _hex(value: str) -> Tuple[int, int, int]:
    value = value.lstrip("#")
    return int(value[0:2], 16), int(value[2:4], 16), int(value[4:6], 16)


def _xterm256(rgb: Tuple[int, int, int]) -> int:
    """Nearest xterm-256 colour (6x6x6 cube or grey ramp) for an RGB triple."""
    levels = (0, 95, 135, 175, 215, 255)

    def nearest(v: int) -> int:
        return min(range(6), key=lambda i: abs(levels[i] - v))

    r, g, b = (nearest(v) for v in rgb)
    cube = (levels[r], levels[g], levels[b])
    grey_i = max(0, min(23, int(round((sum(rgb) / 3 - 8) / 10))))
    grey = 8 + grey_i * 10

    def dist(c: Tuple[int, int, int]) -> int:
        return sum((x - y) ** 2 for x, y in zip(c, rgb))

    # Low-saturation colours (the muted text greys) go to the neutral ramp;
    # the nearest cube entry would tint them teal.
    if max(rgb) - min(rgb) < 40 or dist((grey, grey, grey)) < dist(cube):
        return 232 + grey_i
    return 16 + 36 * r + 6 * g + b


@dataclass
class Colors:
    on: bool = True
    palette: str = "scan"

    def __post_init__(self) -> None:
        self.true = truecolor()
        self.pal = PALETTES["light" if light_background() else self.palette]

    def _c(self, text: str, code: str) -> str:
        if not self.on:
            return text
        return "\x1b[%sm%s\x1b[0m" % (code, text)

    def _sgr(self, rgb: Tuple[int, int, int], layer: int = 38) -> str:
        if self.true:
            return "%d;2;%d;%d;%d" % (layer, rgb[0], rgb[1], rgb[2])
        return "%d;5;%d" % (layer, _xterm256(rgb))

    def rgb(self, text: str, color: str) -> str:
        return self._c(text, self._sgr(_hex(color)))

    def badge(self, text: str, color: str) -> str:
        """Dark text on a coloured background, like the HTML pills."""
        return self._c(text, self._sgr(_hex(color), 48) + ";" + self._sgr(_hex(CHIP_TEXT)) + ";1")

    def bold(self, text: str) -> str:
        return self._c(text, "1")

    def dim(self, text: str) -> str:
        return self._c(text, "2")

    def italic(self, text: str) -> str:
        return self._c(text, "3")

    def red(self, text: str) -> str:
        return self.rgb(text, self.pal["red"])

    def green(self, text: str) -> str:
        return self.rgb(text, self.pal["green"])

    def yellow(self, text: str) -> str:
        return self.rgb(text, self.pal["yellow"])

    def orange(self, text: str) -> str:
        return self.rgb(text, self.pal["orange"])

    def blue(self, text: str) -> str:
        return self.rgb(text, self.pal["blue"])

    def cyan(self, text: str) -> str:
        return self.rgb(text, self.pal["cyan"])

    def magenta(self, text: str) -> str:
        return self.rgb(text, self.pal["magenta"])

    def violet(self, text: str) -> str:
        return self.rgb(text, self.pal["violet"])

    def grey(self, text: str) -> str:
        return self.rgb(text, self.pal["grey"])

    def tone(self, name: str, text: str) -> str:
        return self.rgb(text, self.pal.get(name, self.pal["grey"]))

    def chip(self, severity: str) -> str:
        label = " %s " % SEV_LABEL.get(severity, severity.upper())
        if not self.on:
            return "[%s]" % severity.upper()
        return self.badge(label, SEV_COLOR.get(severity, SEV_COLOR["info"]))

    def grade(self, grade: str, pad: bool = True) -> str:
        """A grade letter in its HTML badge colour."""
        color = GRADE_COLOR.get(grade, SEV_COLOR["info"])
        return self.badge(" %s " % grade, color) if pad else self.bold(self.rgb(grade, color))

    def sev(self, severity: str, text: str, strong: bool = False) -> str:
        """Color text by severity (the scan report's severity colours), optionally in bold."""
        painted = self.rgb(text, SEV_COLOR.get(severity, SEV_COLOR["info"]))
        return self.bold(painted) if strong else painted

    def confidence(self, confidence: str, text: str) -> str:
        painter = {"high": self.green, "medium": self.yellow, "low": self.grey}.get(
            confidence, self.grey)
        return self.bold(painter(text))

    def gradient(self, text: str, start: str = "cyan", end: str = "magenta") -> str:
        """Blend each visible character from one palette colour to another in
        RGB (the HTML brand gradient), not by stepping 256-colour indexes."""
        if not self.on:
            return text
        a, b = _hex(self.pal.get(start, start)), _hex(self.pal.get(end, end))
        out = []
        n = max(1, len(text) - 1)
        for i, ch in enumerate(text):
            if ch == " ":
                out.append(ch)
                continue
            mix = i / n
            rgb = tuple(int(round(x + (y - x) * mix)) for x, y in zip(a, b))
            out.append("\x1b[%sm%s" % (self._sgr(rgb), ch))  # type: ignore[arg-type]
        out.append("\x1b[0m")
        return "".join(out)


def score_tone(score: int) -> str:
    """Palette name for a 0-100 Jank Score, banded like the HTML score ring."""
    if score <= 5:
        return "green"
    if score <= 15:
        return "cyan"
    if score <= 35:
        return "yellow"
    if score <= 60:
        return "orange"
    return "red"


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
    """A filled bar: one palette tone, or by default the HTML rank-bar
    gradient (cyan to violet)."""
    if worst <= 0:
        return ""
    filled = max(1, min(width, int(round(width * value / worst)))) if value else 0
    ch = "█"
    colored = color.tone(tone, ch * filled) if tone else color.gradient(ch * filled, "cyan", "violet")
    return colored + color.dim("░" * (width - filled))


def jank_score(findings: Sequence[Finding], loc: int) -> int:
    """Backward-compatible headline score; details live in jh_score.compute()."""
    return jh_score.compute(findings, loc).score


def _width(default: int = 78) -> int:
    try:
        cols = shutil.get_terminal_size((80, 24)).columns
    except OSError:
        cols = 80
    return max(52, min(96, cols - 4))


def frame(color: Colors, accent: str, top: str, side: str, bottom: str):
    """Painters for a box's top edge, left side, right side and bottom edge.
    accent "gradient" runs the brand gradient across the edges, cyan on the
    left side and magenta on the right, like the HTML header."""
    if accent == "gradient":
        return (color.gradient(top), color.cyan(side), color.magenta(side), color.gradient(bottom))
    painter = getattr(color, accent, color.cyan)
    return painter(top), painter(side), painter(side), painter(bottom)


def _boxed(lines: Sequence[str], color: Colors, width: int, accent: str = "cyan") -> List[str]:
    top, left, right, bot = frame(color, accent, "╭" + "─" * (width - 2) + "╮", "│",
                                  "╰" + "─" * (width - 2) + "╯")
    out = [top]
    for line in lines:
        out.append(left + " " + _pad(_truncate(line, width - 4), width - 4) + " " + right)
    out.append(bot)
    return out


def banner(subtitle: str, meta: str, color: Colors, width: int) -> List[str]:
    word = "J A N K H U N T 4 2"
    title = "  " + color.gradient(word) + "   " + color.dim("// " + subtitle)
    lines = [title, color.grey(meta)]
    return _boxed(lines, color, width, "gradient")


def _sample_paths(info: Dict[str, Any]) -> str:
    paths = info["paths"][:6]
    names = ", ".join("`%s`" % safe_text(p).replace("`", "\\`") for p in paths)
    return names + (", …" if info["count"] > len(paths) else "")


SUMMARY_MAX_LINES = 60                           # a hard bound, whatever the repository holds


def render_summary(result: Any, meta: Dict[str, Any], out_path: Optional[str] = None, limit: int = 10,
                   gate: Optional[Tuple[str, bool]] = None) -> str:
    """A bounded overview for an AI agent's conversation: whatever the repository, a few dozen short lines. The full
    report goes to a file (--out) and is read selectively; printing it whole costs the conversation dearly."""
    import jh_score
    findings = list(result.findings)
    sev_counts: Dict[str, int] = {}
    for f in findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    report = jh_score.compute(findings, result.loc)
    order = ("blocker", "critical", "major", "minor", "info")
    from jh_core import VERSION
    lines = ["jankhunt42 %s summary: %d files, %d findings, Jank Score %d (%s, %s)"
             % (VERSION, result.files, len(findings), report.score, report.grade, report.label)]
    if gate:
        lines.append("gate (--fail-on %s): %s" % (gate[0], "FAIL" if gate[1] else "PASS"))
    if findings:
        lines.append("by severity: " + ", ".join("%s %d" % (s, sev_counts[s]) for s in order if sev_counts.get(s)))
        by_rule: Dict[str, List[Any]] = {}
        for f in findings:
            by_rule.setdefault(f.rule, []).append(f)
        ranked = sorted(by_rule.items(), key=lambda kv: (min(order.index(f.severity) for f in kv[1]), -len(kv[1])))
        lines.append("top rules:")
        for rid, group in ranked[:8]:
            worst = min(group, key=lambda f: order.index(f.severity))
            lines.append("  %s x%d (worst %s) %s" % (rid, len(group), worst.severity, _short(worst.title, 70)))
        if len(ranked) > 8:
            lines.append("  ... %d more rules" % (len(ranked) - 8))
        lines.append("most serious %d of %d:" % (min(limit, len(findings)), len(findings)))
        for f in findings[:limit]:                      # findings are already ordered most serious first
            lines.append("  %s %s %s:%d %s" % (f.severity, f.rule, _tail(f.path, 60), f.line, _short(f.title, 60)))
    held = set_aside_lines(meta)
    if held:
        lines.append("set aside:")
        for _, text in held:
            lines.append("  " + _short(text.replace("`", ""), 160))
    unread = list(meta.get("archive_warnings") or ())
    if unread:                                   # never a clean-looking overview when part of the project was not read
        lines.append("not read: %d item%s, e.g. %s" % (len(unread), "" if len(unread) == 1 else "s",
                                                       _short(_no_control(unread[0]), 140)))
    if out_path:
        lines.append("full report: %s (JSON; read only the parts you need)" % _tail(out_path, 120))
    else:
        lines.append("full report: rerun with --out FILE, then read only the parts you need")
    lines.append("narrow it: --rule ID, --category NAME, or a path; each finding's fix is in the JSON")
    if len(lines) > SUMMARY_MAX_LINES:
        lines = lines[:SUMMARY_MAX_LINES - 1] + ["... summary cut at %d lines; the rest is in the full report" % SUMMARY_MAX_LINES]
    return "\n".join(lines)


_CONTROL = re.compile(r"[\x00-\x1f\x7f]")


def _no_control(text: Any) -> str:
    """Control characters (a line break in a file name, for one) written as \\xNN, so one item stays one line."""
    return _CONTROL.sub(lambda m: "\\x%02x" % ord(m.group()), str(text or ""))


def _tail(path: Any, limit: int) -> str:
    """A long path keeps its end (the file name), not its start."""
    s = _no_control(path)
    return s if len(s) <= limit else "\u2026" + s[-(limit - 1):]


def _short(text: Any, limit: int) -> str:
    s = " ".join(str(text or "").split())
    return s if len(s) <= limit else s[:limit - 1] + "\u2026"


def set_aside_lines(meta: Dict[str, object]) -> List[Tuple[str, str]]:
    """(label, sentence) for each thing the run held back (meta["set_aside"]), each with the switch that shows it.
    Shared by the Markdown and terminal reports so neither can be quieter than the other."""
    aside = meta.get("set_aside") or {}
    if not isinstance(aside, dict):
        return []
    out: List[Tuple[str, str]] = []
    git_ignored = aside.get("git_ignored_read")
    if git_ignored:
        out.append(("READ", "%d untracked file(s) covered by git ignore rules were read, including %s"
                    % (git_ignored["count"], _sample_paths(git_ignored))))
    not_text = aside.get("files_not_read") or {}
    if not_text.get("unreadable"):
        out.append(("NOT READ", "%d file(s) could not be read (permission or read error), including %s; check the "
                    "account running the scan can read them" % (not_text["unreadable"]["count"],
                                                                _sample_paths(not_text["unreadable"]))))
    selection = aside.get("selection") or {}
    if selection:
        out.append(("SCOPE", "this run reported only %s; drop `--rule`/`--category` for a full scan" % " and ".join(
            "%s %s" % ("rule(s)" if k == "rules" else "categor(y/ies)", ", ".join(safe_text(x) for x in v))
            for k, v in sorted(selection.items()))))
    unparsed = aside.get("files_not_parsed") or {}
    if unparsed:
        out.append(("NOT PARSED", "%d supported file(s) could not be parsed, so their structured checks did not run, "
                    "including %s; fix the syntax and scan again" % (unparsed["count"], _sample_paths(unparsed))))
    by_name = aside.get("files_by_name") or {}
    if by_name:
        out.append(("NOT READ", "set aside by name: %s" % "; ".join(
            "%d %s file(s), including %s" % (by_name[w]["count"], w, _sample_paths(by_name[w]))
            for w in ("lockfile", "minified", "generated", "installed plugin") if by_name.get(w))))
    plain = [(why, not_text[why]["count"]) for why in ("binary", "empty") if not_text.get(why)]
    if plain:
        out.append(("NOT READ", "%s not read as text" % " and ".join("%d %s file(s)" % (n, why) for why, n in plain)))
    floor = aside.get("below_floor") or {}
    held = {k: v for k, v in floor.items() if k != "floor"}
    if held:
        parts = ", ".join("%d %s" % (held[s], s) for s in ("blocker", "critical", "major", "minor", "info") if held.get(s))
        out.append(("BELOW FLOOR", "%d finding(s) under the severity floor (%s): %s; `--min-severity info` shows them"
                    % (sum(held.values()), floor.get("floor", "minor"), parts)))
    if aside.get("inline_ignore"):
        out.append(("INLINE IGNORE", "%d finding(s) hidden by `jankhunt42: ignore` comments in the code; "
                    "`--no-inline-ignore` shows them" % aside["inline_ignore"]))
    ignored = aside.get("ignored_rules") or {}
    if ignored:
        rules = ignored.get("rules") or []
        out.append(("RULES OFF", "%d rule(s) set aside by name and not run: %s%s"
                    % (len(rules), ", ".join(rules[:12]), ", …" if len(rules) > 12 else "")))
    if aside.get("config"):
        out.append(("CONFIG", "%s set aside %d finding(s). `--no-config` shows everything held by this config"
                    % (safe_text(str(meta["config"])), aside["config"])))
    for origin, info in (aside.get("files_excluded") or {}).items():
        causes, actions = [], []
        if origin in ("--exclude", "both"):
            causes.append("`--exclude`")
            actions.append("remove the matching `--exclude`")
        if origin in ("config", "both"):
            causes.append("`%s`" % safe_text(info["source"]).replace("`", "\\`"))
            actions.append("use `--no-config`")
        out.append(("NOT READ", "%d file(s) excluded by %s, including %s. To read them, %s."
                    % (info["count"], " and ".join(causes), _sample_paths(info), " and ".join(actions))))
    if aside.get("capped"):
        out.append(("CAPPED", "%d finding(s) over the per-file or per-rule limit this run set; drop or raise "
                    "`--max-per-file-rule` / `--max-per-rule`" % aside["capped"]))
    for reason, info in sorted((aside.get("folders_not_read") or {}).items()):
        paths = [safe_text(p) + "/" for p in info.get("paths") or []]
        out.append(("NOT READ", "%d %s folder(s): %s%s; scan a folder by its path to read it" % (
            info.get("count", 0), reason, ", ".join("`%s`" % p for p in paths[:6]),
            ", …" if info.get("count", 0) > 6 else "")))
    big = aside.get("files_too_large") or {}
    if big:
        out.append(("NOT READ", "%d file(s) over the %s-byte limit: %s%s; raise `--max-file-bytes`" % (
            big.get("count", 0), big.get("limit_bytes"), ", ".join("`%s`" % safe_text(p) for p in (big.get("paths") or [])[:4]),
            ", …" if big.get("count", 0) > 4 else "")))
    if aside.get("file_limit"):
        out.append(("NOT READ", "stopped at the %d-file limit, so later files were not read; raise `--max-files`"
                    % aside["file_limit"]))
    return out


def _scan_markdown_meta(result, meta: Dict[str, object], root: str,
                       report: "jh_score.ScoreReport", findings: Sequence[Finding]) -> List[str]:
    out: List[str] = []
    if meta.get("elapsed") is not None:
        out.append("")
        out.append("_Scan time: %.2fs · rule engine offline_" % float(meta["elapsed"]))
    if meta.get("archive_warnings"):
        out.append("")
        for warning in meta["archive_warnings"]:
            out.append("> Not read: %s" % warning)
    if meta.get("config"):
        out.append("")
        out.append("_Config: `%s`_" % meta["config"])
    aside = set_aside_lines(meta)
    if aside:
        out.append("")
        out.append("### Set aside in this run")
        out.append("")
        out.extend("- %s" % text for _, text in aside)
    minified = meta.get("minified") or []
    if minified:
        names = ", ".join("`%s`" % safe_text(p).replace("`", "\\`") for p in minified[:5])
        out.append("")
        out.append("_Minified bundles, read for secrets, hidden Unicode and agent hazards only (%d): %s%s_"
                   % (len(minified), names, ", …" if len(minified) > 5 else ""))
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
                    out.append("  - evidence: `%s`" % safe_text(f.evidence).replace("`", "\\`"))
                if f.message:
                    out.append("  - why: %s" % f.message)
                if f.fix:
                    out.append("  - fix: %s" % f.fix)
                if owasp(f.rule):
                    out.append("  - owasp: %s" % ", ".join("%s %s" % (r, OWASP_RISKS[r]) for r in owasp(f.rule)))
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
    out: List[str] = ["# jankhunt42 scan", ""]
    out.append("**Root:** `%s` · **Files:** %d · **LOC:** %d · **Findings:** %d · **Jank:** %d/100 (%s · %s) · policy **%s**"
               % (root, result.files, result.loc, len(findings), report.score,
                  report.grade, report.label, report.policy))
    out.extend(_scan_markdown_meta(result, meta, root, report, findings))
    out.extend(_scan_markdown_findings(findings, max_findings))
    if findings:
        prompt = combined(findings)
        fence = "`" * max(3, 1 + max((len(run) for run in re.findall(r"`+", prompt)), default=0))
        out += ([""] if out[-1] else []) + ["## Fix with your coding agent", "",
                "Paste this into Claude Code, Cursor or Copilot (`jankhunt42 scan . --prompt` prints it alone):", "",
                fence + "text", prompt, fence]
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
        out.append("  " + color.yellow("no findings from the built-in rules — not proof of correctness"))
    for label, text in set_aside_lines(meta):
        out.append("  " + color.yellow(label) + "  " + color.grey(text.replace("`", "")))
    for warning in (meta.get("archive_warnings") or [])[:5]:
        out.append("  " + color.yellow("NOT READ") + "  " + color.grey(str(warning)))
    minified = meta.get("minified") or []
    if minified:
        out.append("  " + color.cyan("MINIFIED") + "  " + color.grey(
            "%d bundle(s) read for secrets, hidden Unicode and agent hazards only: %s%s"
            % (len(minified), safe_text(minified[0]), " …" if len(minified) > 1 else "")))
    dupes = meta.get("cross_file_duplicates") or []
    if dupes:
        sites = sum(d["count"] for d in dupes)
        out.append("  " + color.yellow("DUPLICATE") + "  "
                   + color.grey("%d cluster(s) across %d sites — same bug, not one bug"
                                % (len(dupes), sites)))
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
                _bar(weight, worst, max(8, width - 56), color),
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
            color.bold(safe_text(f.path)) + color.sev(f.severity, ":%d" % f.line, strong=True),
            color.blue(f.category),
            color.grey("confidence"),
            color.confidence(f.confidence, f.confidence),
        ))
        if f.evidence:
            out.append("  %s     %s%s%s" % (
                rail,
                color.dim("│ "),
                color.bold(color.grey("evidence ")),
                _truncate(safe_text(f.evidence), width - 23),
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
        out.append("  " + color.yellow("✦ no jank detected by the built-in rules — not proof of correctness"))
        out.append("  " + color.grey("Absence of evidence is not evidence of absence: "
                                      "run the compiler, tests, linters, and sanitizers."))
        return "\n".join(out)
    out.extend(_tty_finding_cards(findings, max_findings, width, color))
    out.append(color.dim("  " + "─" * (width - 4)))
    out.append("  " + color.grey("fix with your coding agent: ") + color.cyan("jankhunt42 scan . --prompt"))
    out.append("  " + color.grey("next: ") + color.cyan("jankhunt42 scan . --json") + color.grey("  ·  ")
               + color.cyan("jankhunt42 map .") + color.grey("  ·  ") + color.cyan("jankhunt42 passport ."))
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


def render_scan(result, meta: Dict[str, object], tty: bool, no_color: bool,
                max_findings: int = 300) -> str:
    if tty and not no_color:
        return scan_tty(result, meta, max_findings)
    return scan_markdown(result, meta, max_findings)

