#!/usr/bin/env python3
"""Self-contained HTML report renderer for jankhunt42.

The output is a single file: no external fonts, scripts, styles, or images.
All repository-derived strings are HTML-escaped before they reach the document.
"""
from __future__ import annotations

from html import escape
from typing import Dict, List, Sequence, Tuple

from jh_core import Finding, SEV_LABEL, TOOL, VERSION
import jh_score

SEV_ORDER = ("blocker", "critical", "major", "minor", "info")
SEV_COLOR = {
    "blocker": "#c77dff",
    "critical": "#ff4d6d",
    "major": "#ff9f43",
    "minor": "#ffd166",
    "info": "#8b95ab",
}
GRADE_COLOR = {
    "A": "#35d39a",
    "B": "#4fd1ff",
    "C": "#ffd166",
    "D": "#ff9f43",
    "E": "#ff4d6d",
}


def _e(value: object) -> str:
    return escape(str(value), quote=True)


def _sev(value: str) -> str:
    value = str(value or "").lower()
    return value if value in SEV_ORDER else "info"


def _score_tone(score: int) -> str:
    if score <= 5:
        return "#35d39a"
    if score <= 15:
        return "#4fd1ff"
    if score <= 35:
        return "#ffd166"
    if score <= 60:
        return "#ff9f43"
    return "#ff4d6d"


def _policy_class(policy: str) -> str:
    policy = str(policy or "warn").lower()
    return policy if policy in ("pass", "warn", "fail") else "warn"


def _counts(findings: Sequence[Finding]) -> Dict[str, int]:
    counts = {sev: 0 for sev in SEV_ORDER}
    for finding in findings:
        sev = _sev(finding.severity)
        counts[sev] += 1
    return counts


def _top_files(findings: Sequence[Finding], n: int = 5) -> List[Tuple[str, int]]:
    counts: Dict[str, int] = {}
    for finding in findings:
        counts[finding.path] = counts.get(finding.path, 0) + 1
    return sorted(counts.items(), key=lambda item: (-item[1], item[0]))[:n]


def _top_rules(findings: Sequence[Finding], n: int = 8) -> List[Tuple[str, str, int]]:
    counts: Dict[str, List[object]] = {}
    for finding in findings:
        title, count = counts.get(finding.rule, [finding.title, 0])
        counts[finding.rule] = [title, int(count) + 1]
    rows = [(rule, str(title), int(count)) for rule, (title, count) in counts.items()]
    rows.sort(key=lambda row: (-row[2], row[0]))
    return rows[:n]


def _render_hero(root: str, result, meta: Dict[str, object], report: "jh_score.ScoreReport") -> str:
    score = int(report.score)
    grade = _e(report.grade)
    tone = _score_tone(score)
    policy = _policy_class(report.policy)
    worst = report.dimensions.get(report.worst_dimension)
    worst_label = _e(worst.label if worst else "risk")
    warnings: List[str] = [str(w) for w in (meta.get("cve_warnings") or [])]
    new_code = ""
    nc = meta.get("new_code") or {}
    if nc.get("warning"):
        warnings.append("New-code view unavailable: %s" % nc["warning"])
    elif nc:
        new_code = '<span class="pill">new code %d/100 · %s</span>' % (
            int(nc.get("score", 0)), _e(nc.get("grade", "A")))
    cve = ""
    if meta.get("cve"):
        cve = '<span class="pill">CVE lookup · %s packages</span>' % _e(meta.get("cve_packages", 0))
    elapsed = meta.get("elapsed")
    elapsed_text = "%.2fs" % float(elapsed) if elapsed is not None else "—"
    warnings_html = ""
    if warnings:
        warnings_html = '<div class="warnings"><strong>notes</strong>%s</div>' % "".join(
            "<span>%s</span>" % _e(w) for w in warnings)
    return '''
    <header class="hero">
      <div class="hero__top">
        <div class="brand"><span>JANKHUNT</span><b>42</b><em>code autopsy</em></div>
        <div class="stamp">SCAN REPORT · v%s</div>
      </div>
      <div class="hero__grid">
        <div class="score-ring" style="--score:%d;--tone:%s" aria-label="Jank score %d out of 100">
          <div class="score-ring__inner"><strong>%d</strong><span>%s</span><small>/100</small></div>
        </div>
        <div class="hero__copy">
          <div class="eyebrow">Jank Score 2.0 · weakest link: %s</div>
          <h1>%s</h1>
          <div class="pill-row">
            <span class="pill policy-%s">policy %s</span>
            <span class="pill">worst dimension: %s</span>
            %s
            %s
          </div>
          <p class="lede">A transparent prioritization score built from severity × confidence × exposure. It tells you where to look first; it does not certify safety.</p>
          <div class="meta-grid">
            <span><b>%s</b> files</span>
            <span><b>%s</b> LOC</span>
            <span><b>%s</b> scan time</span>
          </div>
          <div class="root"><span>root</span><code>%s</code></div>
          %s
        </div>
      </div>
    </header>''' % (
        _e(VERSION), score, tone, score, score, grade, worst_label,
        _e(report.label), policy, policy, worst_label, new_code, cve,
        _e(result.files), _e(f"{result.loc:,}"), _e(elapsed_text), _e(root), warnings_html,
    )


def _render_stats(counts: Dict[str, int], total: int) -> str:
    cards = []
    for sev in SEV_ORDER:
        count = counts.get(sev, 0)
        share = (100.0 * count / total) if total else 0.0
        cards.append('''<article class="stat sev-%s">
          <span class="stat__label">%s</span>
          <strong>%d</strong>
          <span class="stat__share">%.0f%%</span>
          <i class="stat__bar" style="--share:%.1f"></i>
        </article>''' % (
            sev, _e(SEV_LABEL.get(sev, sev.upper())), count, share, share))
    return '<section class="stats" aria-label="Findings by severity">%s</section>' % "".join(cards)


def _render_dimensions(report: "jh_score.ScoreReport") -> str:
    cards = []
    for key in jh_score.DIMENSIONS:
        dim = report.dimensions[key]
        tone = GRADE_COLOR.get(dim.grade, "#8b95ab")
        top = ""
        if dim.top_rules:
            top = "<code>%s</code> ×%d" % (_e(dim.top_rules[0][0]), dim.top_rules[0][1])
        else:
            top = "no findings"
        cards.append('''<article class="dim" style="--value:%d;--tone:%s">
          <div class="dim__head"><span>%s</span><b class="grade grade-%s">%s</b></div>
          <div class="dim__score">%d<small>/100</small></div>
          <div class="bar"><span></span></div>
          <div class="dim__meta">%d findings · worst %s</div>
          <div class="dim__rule">top rule %s</div>
        </article>''' % (
            dim.score, tone, _e(dim.label), _e(dim.grade), _e(dim.grade),
            dim.score, dim.findings, _e(dim.worst), top))
    return '''<section class="section">
      <div class="section__head"><div class="eyebrow">Scorecard</div><h2>Four dimensions, one weak link</h2></div>
      <div class="dims">%s</div>
      <details class="method"><summary>How this score works</summary>
        <p>Each finding contributes <b>severity × confidence × exposure</b> risk points.
        Points become a density per 1,000 lines, a severity floor prevents a severe issue
        from hiding in a large tree, and per-rule saturation stops one noisy pattern from
        dominating. The headline is 70%% worst dimension + 30%% weighted average.</p>
        <p>The score is advisory. Gate CI on <code>--fail-on</code> and native tests, not on the score alone.</p>
      </details>
    </section>''' % "".join(cards)


def _render_top(findings: Sequence[Finding]) -> str:
    files = _top_files(findings, 5)
    rules = _top_rules(findings, 8)
    if not files and not rules:
        return ""
    file_rows = []
    if files:
        worst = max(count for _, count in files)
        for path, count in files:
            pct = 100.0 * count / max(1, worst)
            file_rows.append('''<div class="rank-row"><code>%s</code>
              <span class="rank-bar"><i style="width:%.1f%%"></i></span><b>%d</b></div>''' % (
                _e(path), pct, count))
    rule_rows = []
    if rules:
        worst = max(count for _, _, count in rules)
        for rule, title, count in rules:
            pct = 100.0 * count / max(1, worst)
            rule_rows.append('''<div class="rank-row"><code>%s</code><span class="rank-title">%s</span>
              <span class="rank-bar"><i style="width:%.1f%%"></i></span><b>%d</b></div>''' % (
                _e(rule), _e(title), pct, count))
    return '''<section class="section split">
      <div class="panel"><div class="section__head"><div class="eyebrow">Hot spots</div><h2>Top offenders</h2></div>%s</div>
      <div class="panel"><div class="section__head"><div class="eyebrow">Patterns</div><h2>Top rules</h2></div>%s</div>
    </section>''' % ("".join(file_rows) or '<p class="muted">No findings.</p>',
                     "".join(rule_rows) or '<p class="muted">No findings.</p>')


def _render_toolbar(counts: Dict[str, int], total: int) -> str:
    buttons = ['<button type="button" class="filter is-active" data-filter="all" aria-pressed="true">All <b>%d</b></button>' % total]
    for sev in SEV_ORDER:
        buttons.append('<button type="button" class="filter sev-%s" data-filter="%s" aria-pressed="false">%s <b>%d</b></button>'
                       % (sev, sev, _e(SEV_LABEL.get(sev, sev.upper())), counts.get(sev, 0)))
    return '''<div class="toolbar">
      <label class="search"><span>Search findings</span>
        <input id="search" type="search" placeholder="rule, path, message, evidence…" autocomplete="off">
      </label>
      <div class="filters" role="group" aria-label="Filter by severity">%s</div>
      <div class="visible"><b id="visible-count">%d</b> visible</div>
    </div>''' % ("".join(buttons), total)


def _finding_extra(finding: Finding) -> str:
    extra = finding.extra or {}
    parts: List[str] = []
    cves = extra.get("cve") or []
    if cves:
        parts.append("CVE " + ", ".join(_e(cve) for cve in cves))
    fixed = extra.get("fixed") or []
    if fixed:
        parts.append("fixed in " + ", ".join(_e(version) for version in fixed))
    advisory = extra.get("advisory")
    if advisory and not cves:
        parts.append("advisory " + _e(advisory))
    if not parts:
        return ""
    return '<div class="finding__extra">%s</div>' % " · ".join(parts)


def _render_finding_card(finding: Finding, idx: int) -> str:
    sev = _sev(finding.severity)
    searchable = " ".join([
        finding.rule, finding.title, finding.path, finding.category,
        finding.message, finding.evidence, finding.fix, " ".join(finding.tags),
    ]).lower()
    evidence = ""
    if finding.evidence:
        evidence = '<div class="evidence"><span class="label">evidence</span><code>%s</code></div>' % _e(finding.evidence)
    why = ""
    if finding.message:
        why = '<p class="why"><span class="label">why</span>%s</p>' % _e(finding.message)
    fix = ""
    if finding.fix:
        fix = '<p class="fix"><span class="label">fix</span>%s</p>' % _e(finding.fix)
    tags = ""
    if finding.tags:
        tags = '<div class="tags">%s</div>' % "".join("<span>#%s</span>" % _e(tag) for tag in finding.tags)
    return '''<article class="finding sev-%s" data-severity="%s" data-text="%s">
      <div class="finding__rail"></div>
      <div class="finding__body">
        <div class="finding__top">
          <span class="index">%02d</span>
          <span class="chip">%s</span>
          <code class="rule">%s</code>
          <span class="conf">%s confidence</span>
        </div>
        <h3>%s</h3>
        <div class="loc"><code>%s:%d</code><span>%s</span></div>
        %s%s%s%s
      </div>
    </article>''' % (
        sev, sev, _e(searchable), idx, _e(SEV_LABEL.get(sev, sev.upper())),
        _e(finding.rule), _e(finding.confidence), _e(finding.title),
        _e(finding.path), finding.line, _e(finding.category),
        evidence, why, fix, tags + _finding_extra(finding))


def _render_findings(findings: Sequence[Finding], max_findings: int) -> str:
    total = len(findings)
    if not findings:
        return '''<section class="section empty-state">
          <div class="empty-mark">✦</div>
          <h2>No findings from the built-in rules</h2>
          <p>That is good news, not a certificate. Run the compiler, tests, linters, and sanitizers.</p>
        </section>'''
    shown = findings[:max_findings]
    cards = "".join(_render_finding_card(finding, idx) for idx, finding in enumerate(shown, 1))
    more = ""
    if total > max_findings:
        more = '<p class="muted">Showing %d of %d. Use <code>--json</code> for the full set.</p>' % (
            max_findings, total)
    return '''<section class="findings" id="findings">
      <div class="section__head"><div class="eyebrow">Findings</div><h2>Ranked by severity and confidence</h2></div>
      %s
      <p class="empty-filter" id="empty" hidden>No findings match this filter.</p>
      %s
    </section>''' % (cards, more)


def _render_footer() -> str:
    return '''<footer>
      <span>Generated by <b>%s</b> v%s</span>
      <span>Advisory only · findings are leads, not verdicts</span>
    </footer>''' % (_e(TOOL), _e(VERSION))


def render_scan(result, meta: Dict[str, object], max_findings: int = 300) -> str:
    """Render a complete, self-contained HTML scan report."""
    findings: List[Finding] = list(result.findings)
    root = str(meta.get("root", "."))
    report = jh_score.compute(findings, result.loc)
    if meta.get("new_code"):
        report.new_code = meta["new_code"]
    counts = _counts(findings)
    title = "JankHunt42 · %s" % root
    return "\n".join([
        "<!DOCTYPE html>",
        '<html lang="en">',
        "<head>",
        '<meta charset="utf-8">',
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta name="color-scheme" content="dark">',
        '<meta name="generator" content="%s v%s">' % (_e(TOOL), _e(VERSION)),
        "<title>%s</title>" % _e(title),
        "<style>",
        _CSS,
        "</style>",
        "</head>",
        "<body>",
        '<div class="shell">',
        _render_hero(root, result, meta, report),
        _render_stats(counts, len(findings)),
        _render_dimensions(report),
        _render_top(findings),
        _render_toolbar(counts, len(findings)),
        _render_findings(findings, max_findings),
        _render_footer(),
        "</div>",
        "<script>",
        _JS,
        "</script>",
        "</body>",
        "</html>",
    ])


_CSS = r"""
:root {
  --bg: #07090e;
  --panel: #10141d;
  --panel-2: #151a26;
  --line: #252c3c;
  --text: #e9edf7;
  --muted: #98a2b8;
  --faint: #68738a;
  --cyan: #4fd1ff;
  --violet: #7c5cff;
  --green: #35d39a;
  --yellow: #ffd166;
  --orange: #ff9f43;
  --red: #ff4d6d;
  --mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
}
* { box-sizing: border-box; }
html { color-scheme: dark; scroll-behavior: smooth; }
body {
  margin: 0;
  color: var(--text);
  background:
    radial-gradient(900px 500px at 8% -8%, rgba(79, 209, 255, .13), transparent 60%),
    radial-gradient(900px 600px at 96% 0%, rgba(255, 77, 109, .11), transparent 55%),
    var(--bg);
  font-family: ui-sans-serif, system-ui, -apple-system, "Segoe UI", Roboto, Helvetica, Arial, sans-serif;
  line-height: 1.55;
}
a { color: var(--cyan); }
code, .mono { font-family: var(--mono); }
[hidden] { display: none !important; }
.shell { max-width: 1180px; margin: 0 auto; padding: 32px 24px 64px; }
.hero {
  position: relative; overflow: hidden; border: 1px solid var(--line);
  border-radius: 26px; padding: 26px;
  background:
    linear-gradient(135deg, rgba(124, 92, 255, .18), rgba(79, 209, 255, .06) 45%, rgba(255, 77, 109, .10)),
    var(--panel);
  box-shadow: 0 24px 80px rgba(0, 0, 0, .35);
}
.hero::after {
  content: ""; position: absolute; inset: -40%; pointer-events: none;
  background: radial-gradient(circle at 18% 20%, rgba(79, 209, 255, .14), transparent 32%),
              radial-gradient(circle at 82% 70%, rgba(255, 77, 109, .13), transparent 30%);
}
.hero__top, .hero__grid { position: relative; z-index: 1; }
.hero__top { display: flex; justify-content: space-between; gap: 16px; align-items: center; }
.brand { font-size: .78rem; font-weight: 900; letter-spacing: .28em; color: var(--muted); }
.brand b {
  font-size: 1.05rem; letter-spacing: .08em;
  background: linear-gradient(90deg, var(--cyan), var(--violet), var(--red));
  -webkit-background-clip: text; background-clip: text; color: transparent;
}
.brand em { font-style: normal; letter-spacing: .12em; color: var(--faint); margin-left: 12px; }
.stamp { color: var(--faint); font-size: .72rem; letter-spacing: .14em; white-space: nowrap; }
.hero__grid { display: grid; grid-template-columns: 190px minmax(0, 1fr); gap: 30px; align-items: center; margin-top: 22px; }
.score-ring {
  --score: 0; --tone: var(--red); width: 176px; height: 176px; border-radius: 50%;
  display: grid; place-items: center; position: relative;
  background: conic-gradient(var(--tone) calc(var(--score) * 1%), #202636 0);
  box-shadow: 0 0 60px color-mix(in srgb, var(--tone) 22%, transparent);
}
.score-ring::before { content: ""; position: absolute; inset: 12px; border-radius: 50%; background: #0a0d14; border: 1px solid var(--line); }
.score-ring__inner { position: relative; z-index: 1; text-align: center; }
.score-ring strong { display: block; font-size: 3.1rem; line-height: .95; letter-spacing: -.05em; }
.score-ring span { display: inline-block; margin-top: 6px; padding: 2px 10px; border-radius: 999px; background: var(--tone); color: #090b10; font-weight: 900; font-size: .9rem; }
.score-ring small { display: block; color: var(--faint); font-size: .7rem; letter-spacing: .12em; margin-top: 6px; }
.eyebrow { color: var(--muted); font-size: .72rem; font-weight: 800; letter-spacing: .16em; text-transform: uppercase; }
h1 { margin: 4px 0 12px; font-size: clamp(2rem, 4vw, 3.4rem); line-height: 1.02; letter-spacing: -.045em; }
.lede { color: var(--muted); max-width: 68ch; margin: 14px 0 16px; }
.pill-row { display: flex; flex-wrap: wrap; gap: 8px; }
.pill {
  display: inline-flex; align-items: center; border: 1px solid var(--line);
  background: rgba(255, 255, 255, .035); color: var(--muted); border-radius: 999px;
  padding: 4px 11px; font-size: .76rem; font-weight: 700;
}
.policy-pass { color: var(--green); border-color: color-mix(in srgb, var(--green) 45%, var(--line)); }
.policy-warn { color: var(--yellow); border-color: color-mix(in srgb, var(--yellow) 45%, var(--line)); }
.policy-fail { color: var(--red); border-color: color-mix(in srgb, var(--red) 45%, var(--line)); }
.meta-grid { display: flex; flex-wrap: wrap; gap: 18px; color: var(--muted); font-size: .8rem; }
.meta-grid b { color: var(--text); }
.root { margin-top: 12px; color: var(--faint); font-size: .78rem; display: flex; gap: 10px; align-items: baseline; min-width: 0; }
.root span { text-transform: uppercase; letter-spacing: .12em; font-size: .64rem; }
.root code { color: var(--cyan); overflow-wrap: anywhere; }
.warnings { margin-top: 14px; display: flex; flex-wrap: wrap; gap: 8px; align-items: baseline; color: var(--yellow); font-size: .78rem; }
.warnings strong { text-transform: uppercase; letter-spacing: .12em; font-size: .64rem; }
.warnings span { border: 1px solid color-mix(in srgb, var(--yellow) 35%, var(--line)); border-radius: 8px; padding: 4px 8px; background: rgba(255, 209, 102, .06); }
.stats { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 12px; margin: 18px 0 30px; }
.stat { position: relative; overflow: hidden; border: 1px solid var(--line); border-radius: 15px; padding: 14px 15px 16px; background: var(--panel); }
.stat::before { content: ""; position: absolute; inset: 0 auto 0 0; width: 4px; background: var(--sev, var(--muted)); }
.stat__label { display: block; color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
.stat strong { display: block; font-size: 1.8rem; line-height: 1.15; margin-top: 2px; }
.stat__share { color: var(--faint); font-size: .72rem; }
.stat__bar { position: absolute; left: 0; right: 0; bottom: 0; height: 3px; background: #202636; }
.stat__bar::after { content: ""; display: block; width: calc(var(--share) * 1%); height: 100%; background: var(--sev, var(--muted)); }
.section { margin: 30px 0; }
.section__head { display: flex; justify-content: space-between; align-items: end; gap: 16px; margin-bottom: 12px; }
.section__head h2 { margin: 2px 0 0; font-size: 1.28rem; letter-spacing: -.02em; }
.dims { display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; }
.dim { border: 1px solid var(--line); border-radius: 16px; padding: 15px; background: var(--panel); }
.dim__head { display: flex; justify-content: space-between; gap: 10px; align-items: center; color: var(--muted); font-size: .78rem; font-weight: 700; }
.grade { display: inline-grid; place-items: center; min-width: 26px; height: 26px; border-radius: 8px; color: #07090e; background: var(--tone, var(--muted)); font-size: .78rem; }
.dim__score { font-size: 2rem; font-weight: 900; letter-spacing: -.04em; margin-top: 4px; }
.dim__score small { color: var(--faint); font-size: .7rem; font-weight: 500; margin-left: 3px; }
.bar { height: 7px; border-radius: 999px; background: #202636; overflow: hidden; margin: 8px 0; }
.bar span { display: block; width: calc(var(--value) * 1%); height: 100%; border-radius: inherit; background: var(--tone, var(--muted)); }
.dim__meta, .dim__rule { color: var(--faint); font-size: .72rem; }
.dim__rule { margin-top: 3px; }
.dim code, .method code { color: var(--cyan); }
.method { margin-top: 12px; color: var(--muted); font-size: .8rem; border: 1px solid var(--line); border-radius: 12px; background: var(--panel); padding: 10px 14px; }
.method summary { cursor: pointer; color: var(--text); font-weight: 800; }
.method p { margin: 9px 0 0; }
.split { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
.panel { border: 1px solid var(--line); border-radius: 16px; background: var(--panel); padding: 16px; }
.panel .section__head { margin-bottom: 8px; }
.rank-row {
  display: grid; grid-template-columns: minmax(0, 1.2fr) minmax(60px, 1fr) 42px;
  gap: 10px; align-items: center; padding: 6px 0; font-size: .78rem;
  border-bottom: 1px solid rgba(37, 44, 60, .65);
}
.rank-row:last-child { border-bottom: 0; }
.rank-row code { color: var(--text); overflow-wrap: anywhere; }
.rank-row .rank-title { color: var(--muted); overflow-wrap: anywhere; }
.rank-row b { text-align: right; color: var(--text); }
.rank-bar { height: 5px; border-radius: 999px; background: #202636; overflow: hidden; }
.rank-bar i { display: block; height: 100%; background: linear-gradient(90deg, var(--cyan), var(--violet)); border-radius: inherit; }
.toolbar {
  position: sticky; top: 0; z-index: 5; display: flex; flex-wrap: wrap; gap: 12px; align-items: end;
  padding: 14px; margin: 8px 0 18px; border: 1px solid var(--line); border-radius: 16px;
  background: rgba(11, 14, 21, .88); backdrop-filter: blur(12px);
}
.search { flex: 1 1 260px; display: grid; gap: 4px; color: var(--muted); font-size: .68rem; font-weight: 800; letter-spacing: .12em; text-transform: uppercase; }
.search input { width: 100%; border: 1px solid var(--line); border-radius: 10px; background: #0a0d14; color: var(--text); font: inherit; font-size: .86rem; padding: 9px 11px; outline: none; }
.search input:focus { border-color: var(--cyan); box-shadow: 0 0 0 3px rgba(79, 209, 255, .12); }
.filters { display: flex; flex-wrap: wrap; gap: 6px; }
.filter {
  cursor: pointer; border: 1px solid var(--line); border-radius: 9px;
  background: var(--panel-2); color: var(--muted); padding: 7px 9px;
  font: inherit; font-size: .72rem; font-weight: 800; letter-spacing: .04em;
}
.filter::before { content: ""; display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--sev, var(--faint)); margin-right: 6px; vertical-align: 1px; }
.filter[data-filter="all"]::before { display: none; }
.filter b { color: var(--text); }
.filter:hover { border-color: var(--faint); }
.filter.is-active { border-color: var(--cyan); color: var(--text); box-shadow: 0 0 0 2px rgba(79, 209, 255, .10); }
.visible { color: var(--faint); font-size: .74rem; margin-left: auto; white-space: nowrap; }
.visible b { color: var(--text); }
.finding {
  --sev: var(--muted); display: grid; grid-template-columns: 5px minmax(0, 1fr);
  gap: 0; border: 1px solid var(--line); border-radius: 15px;
  background: var(--panel); margin: 10px 0; overflow: hidden;
}
.finding__rail { background: var(--sev); }
.finding__body { padding: 14px 16px; min-width: 0; }
.finding__top { display: flex; flex-wrap: wrap; gap: 9px; align-items: center; }
.index { color: var(--sev); font: 900 .8rem var(--mono); letter-spacing: .08em; }
.chip { display: inline-flex; border-radius: 7px; background: var(--sev); color: #07090e; padding: 2px 8px; font-size: .64rem; font-weight: 900; letter-spacing: .09em; }
.rule { color: var(--sev); font-size: .78rem; font-weight: 800; }
.conf { color: var(--faint); font-size: .68rem; text-transform: uppercase; letter-spacing: .08em; }
.finding h3 { margin: 7px 0 4px; font-size: 1.09rem; line-height: 1.3; overflow-wrap: anywhere; }
.loc { display: flex; flex-wrap: wrap; gap: 10px; align-items: baseline; color: var(--faint); font-size: .74rem; }
.loc code { color: var(--cyan); font-weight: 700; overflow-wrap: anywhere; }
.loc span { color: var(--muted); }
.evidence { margin-top: 10px; border: 1px solid #222a3a; border-radius: 10px; background: #0a0d14; padding: 9px 11px; display: flex; gap: 10px; align-items: baseline; }
.evidence code { color: #dfe7ff; font-size: .8rem; white-space: pre-wrap; overflow-wrap: anywhere; }
.label { color: var(--faint); font-size: .63rem; font-weight: 900; letter-spacing: .13em; text-transform: uppercase; white-space: nowrap; }
.why, .fix { margin: 9px 0 0; color: var(--muted); font-size: .82rem; }
.why .label { color: var(--sev); }
.why { display: flex; gap: 10px; align-items: baseline; }
.fix {
  display: flex; gap: 10px; align-items: baseline; padding: 7px 9px;
  border-left: 2px solid color-mix(in srgb, var(--green) 55%, var(--line));
  background: rgba(53, 211, 154, .055); border-radius: 0 8px 8px 0;
}
.fix .label { color: var(--green); }
.tags { display: flex; flex-wrap: wrap; gap: 5px; margin-top: 9px; }
.tags span { color: var(--faint); border: 1px solid var(--line); border-radius: 999px; padding: 2px 7px; font: .64rem var(--mono); }
.finding__extra { margin-top: 9px; color: var(--yellow); font-size: .74rem; overflow-wrap: anywhere; }
.empty-state { text-align: center; border: 1px dashed var(--line); border-radius: 18px; background: var(--panel); padding: 42px 24px; }
.empty-mark { font-size: 2.4rem; color: var(--green); }
.empty-state h2 { margin: 8px 0 4px; }
.empty-state p, .empty-filter, .muted { color: var(--muted); }
.empty-filter { text-align: center; border: 1px dashed var(--line); border-radius: 12px; padding: 20px; }
footer { display: flex; flex-wrap: wrap; justify-content: space-between; gap: 12px; margin-top: 34px; padding-top: 14px; border-top: 1px solid var(--line); color: var(--faint); font-size: .72rem; }
footer b { color: var(--muted); }
.sev-blocker { --sev: #c77dff; }
.sev-critical { --sev: #ff4d6d; }
.sev-major { --sev: #ff9f43; }
.sev-minor { --sev: #ffd166; }
.sev-info { --sev: #8b95ab; }
.grade-A { background: var(--green); }
.grade-B { background: var(--cyan); }
.grade-C { background: var(--yellow); }
.grade-D { background: var(--orange); }
.grade-E { background: var(--red); }
@media (max-width: 900px) {
  .hero__grid { grid-template-columns: 1fr; }
  .stats { grid-template-columns: repeat(3, minmax(0, 1fr)); }
  .dims { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .split { grid-template-columns: 1fr; }
}
@media (max-width: 620px) {
  .shell { padding: 18px 14px 46px; }
  .hero { padding: 18px; border-radius: 18px; }
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .dims { grid-template-columns: 1fr; }
  .hero__top { align-items: start; }
  .brand em { display: none; }
  .toolbar { position: static; }
  .rank-row { grid-template-columns: minmax(0, 1fr) 46px; }
  .rank-row .rank-bar { display: none; }
}
@media print {
  :root {
    --bg: #fff; --panel: #fff; --panel-2: #f6f7fb; --line: #ccc;
    --text: #111; --muted: #444; --faint: #666; --cyan: #0645ad;
    --violet: #4b2fbf; --green: #087f5b; --yellow: #8a5a00;
    --orange: #a24a00; --red: #a11;
  }
  body { background: #fff; color: #111; }
  .hero, .panel, .dim, .stat, .finding, .method {
    background: #fff; border-color: #ccc; box-shadow: none;
  }
  .hero::after { display: none; }
  .toolbar, footer { display: none; }
  .evidence { background: #f6f7fb; }
  .score-ring { box-shadow: none; }
  .finding, .dim, .stat { break-inside: avoid; page-break-inside: avoid; }
}
"""


_JS = r"""
(function () {
  const cards = Array.from(document.querySelectorAll('.finding'));
  const buttons = Array.from(document.querySelectorAll('[data-filter]'));
  const search = document.getElementById('search');
  const empty = document.getElementById('empty');
  const visible = document.getElementById('visible-count');
  let active = 'all';
  function apply() {
    const query = (search.value || '').trim().toLowerCase();
    let shown = 0;
    cards.forEach(function (card) {
      const matchesSeverity = active === 'all' || card.dataset.severity === active;
      const matchesQuery = !query || (card.dataset.text || '').indexOf(query) !== -1;
      const ok = matchesSeverity && matchesQuery;
      card.hidden = !ok;
      if (ok) shown += 1;
    });
    if (empty) empty.hidden = shown !== 0;
    visible.textContent = String(shown);
    buttons.forEach(function (button) {
      const on = button.dataset.filter === active;
      button.classList.toggle('is-active', on);
      button.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
  }
  buttons.forEach(function (button) {
    button.addEventListener('click', function () {
      active = button.dataset.filter;
      apply();
    });
  });
  search.addEventListener('input', apply);
  apply();
})();
"""
