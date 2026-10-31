#!/usr/bin/env python3
"""Shared terminal building blocks for the `map` and `passport` views.

Same personality as the scan autopsy (gradient banner, rounded cards,
severity chips) but width-aware, with an ASCII fallback for TERM=dumb or
non-UTF-8 terminals, and every repository-sourced string passed through
safe_text() before it can reach the terminal.
"""
from __future__ import annotations

import os
import sys
from typing import List, Optional, Sequence

from jh_core import safe_text
from jh_egress import destination_label
from jh_render import Colors, _pad, _truncate, _visible, frame, score_tone


def want_ascii() -> bool:
    if os.environ.get("TERM", "") == "dumb":
        return True
    enc = (getattr(sys.stdout, "encoding", "") or "").lower()
    return bool(enc) and "utf" not in enc


def view_width(columns: Optional[int] = None) -> int:
    if columns is None:
        try:
            columns = int(os.environ.get("COLUMNS", "0")) or os.get_terminal_size().columns
        except (OSError, ValueError):
            columns = 80
    return max(60, min(120, columns - 2))


class Theme:
    def __init__(self, color: bool, ascii_only: bool, width: int):
        self.c = Colors(color, "explorer")  # the HTML explorer's palette
        self.ascii = ascii_only
        self.width = width

    def box(self, lines: Sequence[str], accent: str = "cyan", title: str = "") -> List[str]:
        w = self.width
        h, v, tl, tr, bl, br = ("-", "|", "+", "+", "+", "+") if self.ascii else ("─", "│", "╭", "╮", "╰", "╯")
        if title:
            t = " %s " % title
            top = tl + h + t + h * max(0, w - 3 - len(t)) + tr
        else:
            top = tl + h * (w - 2) + tr
        top_p, left, right, bottom = frame(self.c, accent, top, v, bl + h * (w - 2) + br)
        out = [top_p]
        for line in lines:
            out.append(left + " " + _pad(_truncate(line, w - 4), w - 4) + " " + right)
        out.append(bottom)
        return out

    def banner(self, subtitle: str, meta: str) -> List[str]:
        word = "JANKHUNT42" if self.ascii else "J A N K H U N T 4 2"
        title = "  " + self.c.gradient(word) + "   " + self.c.dim("// " + subtitle)
        return self.box([title, self.c.grey(safe_text(meta))], "gradient")

    def label(self, state: str) -> str:
        """Evidence states are always spelled out; color is a second channel only."""
        paint = {"verified": self.c.green, "provider-verified": self.c.green, "tool-verified": self.c.green,
                 "supported": self.c.cyan, "observed": self.c.cyan, "declared": self.c.violet,
                 "inferred": self.c.yellow, "signature-only": self.c.yellow, "failed": self.c.red,
                 "unknown": self.c.grey, "not assessed": self.c.grey, "not-observed": self.c.grey}.get(state, self.c.grey)
        return paint("[%s]" % state)

    def level(self, text: str) -> str:
        paint = {"Critical": self.c.magenta, "High": self.c.red, "Moderate": self.c.yellow, "Low": self.c.green,
                 "Unknown": self.c.grey, "block": self.c.magenta, "insufficient-evidence": self.c.grey,
                 "review": self.c.yellow, "pass": self.c.green}.get(text, self.c.grey)
        return self.c.bold(paint(text.upper() if text in ("block", "review", "pass") else text))

    def kv(self, key: str, value: str, key_w: int = 22) -> str:
        return self.c.grey(_pad(key, key_w)) + value

    def rule(self) -> str:
        return self.c.dim(("-" if self.ascii else "─") * self.width)

    def arrow(self) -> str:
        return "->" if self.ascii else "→"


def paint_edges(lines: Sequence[str], paint, arrow: str) -> List[str]:
    """Colour each `-[kind/capability, evidence]->` segment of a wrapped path
    (the HTML explorer draws the blast radius in magenta). Runs after
    wrapping, so widths are measured on plain text; a segment may span lines."""
    out: List[str] = []
    inside = False
    for ln in lines:
        chunks, cur, i = [], "", 0
        while i < len(ln):
            if not inside and ln.startswith("-[", i):
                chunks.append((False, cur))
                cur, inside, i = "-[", True, i + 2
                continue
            if inside and ln.startswith("]" + arrow, i):
                chunks.append((True, cur + "]" + arrow))
                cur, inside, i = "", False, i + 1 + len(arrow)
                continue
            cur += ln[i]
            i += 1
        chunks.append((inside, cur))
        out.append("".join(paint(text) if painted and text.strip() else text for painted, text in chunks))
    return out


def clean(text: object) -> str:
    return safe_text(text)


def asciify(text: str) -> str:
    """ASCII fallback for TERM=dumb or non-UTF-8 terminals."""
    table = {"·": "-", "→": "->", "…": "...", "—": "-", "–": "-", "⇒": "=>", "│": "|", "└": "`", "█": "#", "░": ".", "◆": "*"}
    out = "".join(table.get(ch, ch) for ch in text)
    return out.encode("ascii", "replace").decode("ascii")


def visible(text: str) -> int:
    return _visible(text)


def _wrap(text: str, width: int, indent: str) -> List[str]:
    words = text.split(" ")
    lines: List[str] = []
    cur = ""
    for w in words:
        if cur and len(cur) + 1 + len(w) > width:
            lines.append(cur)
            cur = indent + w
        else:
            cur = (cur + " " + w) if cur else w
    if cur:
        lines.append(cur)
    return lines


def map_tty(report, color: bool = True, ascii_only: bool = False, columns: Optional[int] = None) -> str:
    import jh_n8n
    import jh_map
    import jh_graph as G
    t = Theme(color, ascii_only, view_width(columns))
    c = t.c
    s = jh_map.summary(report)
    ass = report["assessment"]
    cov = report["coverage"]
    out = t.banner("blast radius explorer",
                   "%s  ·  %s  ·  %d nodes  ·  %d edges" % (report["scope"]["name"], report["scope"]["snapshot"],
                                                          s["nodes"], s["edges"]))
    tiers = ass["evidence_tiers"]
    card = [
        t.kv("EXPOSURE", t.level(ass["exposure"]["class"]) + c.grey("  qualitative; a path is a possibility, not proof")),
        t.kv("evidence coverage", "%s  %s" % (c.bold(cov["status"]), c.grey("(%d/%d files, %d adapters)" % (
            cov["files_inspected"], cov["files_considered"], len(cov["by_adapter"]))))),
        t.kv("edge evidence", "  ".join("%d %s" % (tiers[k], t.label(k)) for k in ("verified", "supported", "inferred", "unknown"))),
        t.kv("reach", "%d known %s  ·  %d potential  ·  %d unknown-capability" % (
            s["known_reach"], t.label("verified"), s["potential_reach"], ass["unknown_capability_edges"])),
        t.kv("breadth", "%.3f over %d trust domains %s" % (ass["breadth"]["indicator"], ass["breadth"]["distinct_trust_domains"],
                                                        c.grey("(informational, never blocks)"))),
    ]
    out += [""] + t.box(card, "cyan", "what can it hurt?")
    trigger_text = jh_n8n.trigger_line(report.get('triggers'))
    if trigger_text:
        out += [''] + _wrap(clean('Declared triggers: ' + trigger_text), t.width, '')
    out += ["", c.bold("connected systems")]
    if s["by_kind"]:
        out.append("  " + "   ".join("%s %s" % (c.bold(str(v)), k) for k, v in s["by_kind"].items()))
    else:
        out.append("  0 observed " + c.grey("(not proof that none exist)"))
    out += ["", c.bold("trust-boundary crossings")]
    out.append("  " + (", ".join(clean(x).replace("->", t.arrow()) for x in s["crossings"]) or "0 observed"))
    out += ["", c.bold("highest-impact admissible paths")]
    tp = jh_map.top_paths(report)
    if not tp:
        out.append("  0 observed")
    for d in tp:
        out.append("  %s %s %s %s%s" % (t.level(d["level"]), c.bold(d["impact"]), t.label(d["tier"]), c.grey(d["rule"]),
                                       c.grey("  strength %.3f (heuristic)" % d["strength"]) if "strength" in d else ""))
        for ln in _wrap(clean(d["why"]), t.width - 6, "    "):
            out.append("    " + c.grey(ln.strip()) if not ln.startswith("    ") else c.grey(ln))
        ptxt = clean(jh_map.path_text(report, d["principal"], d["path"])).replace("->", t.arrow())
        edge = c.magenta if d["tier"] in ("verified", "supported") else (lambda x: c.dim(c.magenta(x)))
        wrapped = [("    " + ln if not ln.startswith("      ") else ln) for ln in _wrap(ptxt, t.width - 6, "      ")]
        out += paint_edges(wrapped, edge, t.arrow())
    creds = jh_map.credential_rows(report)
    if creds:
        out += ["", c.bold("credential blast radius") + c.grey("  (what each identity unlocks; informational)")]
        for r in creds:
            out.append("  %s %s%s" % (c.magenta("◆"), c.bold(clean(r["label"])),
                                      c.yellow("  " + " ".join(r["flags"])) if r["flags"] else ""))
            body = "unlocks %d (%d mutating): %s  ·  held by %s" % (
                r["unlocks"], r["mutating"], ", ".join(r["targets"]) or "nothing mapped",
                ", ".join(r["holders"]) or "no visible holder")
            out += [c.grey("    " + ln.strip()) for ln in _wrap(clean(body), t.width - 6, "    ")]
    eg = report.get("egress") or {}
    if isinstance(eg.get("boundaries"), list) and eg["boundaries"]:
        out += ["", c.bold("egress boundary") + c.grey("  (declared allowlists vs hosts the map reaches)")]
        out.append("  %d allowlist(s): %s" % (len(eg["boundaries"]), ", ".join(
            "%s%s %s" % (b["tool"], clean(" [%s]" % b["profile"]) if b.get("profile") else "",
                          clean(b["path"])) for b in eg["boundaries"][:3])))
        if eg.get("state") == "unknown":
            out.append(c.yellow("  coverage unknown: %d reached endpoint(s) unassessed" % len(eg.get("unassessed", []))))
            out.append(c.grey("  " + clean(eg.get("note", ""))))
        for o in eg["outside"][:5]:
            out.append("  %s %s %s %s" % (c.red("!"), c.bold(clean(destination_label(o))), t.label(o["tier"]),
                                          c.grey("outside: " + clean(o["why"])
                                                 + (" [%s]" % ", ".join(o["contexts"]) if len(eg.get("contexts", [])) > 1 else ""))))
        if len(eg["outside"]) > 5:
            out.append(c.grey("    +%d more outside" % (len(eg["outside"]) - 5)))
        if eg["wildcards"]:
            out.append("  %s wildcards: %s" % (c.yellow("*"), clean(", ".join(eg["wildcards"][:4]))[: t.width - 16]))
        if eg["unused"]:
            out.append(c.grey("  unused by the mapped code: %s" % clean(", ".join(eg["unused"][:4]))[: t.width - 30]))
    embedded = [e for e in report['evidence'] if 'json_pointer' in e]
    if embedded:
        out += ['', c.bold('embedded code receipts')]
        for e in embedded[:10]:
            out += _wrap(clean('%s:%d %s, code line %d' % (e['path'], e['line'],
                         e['json_pointer'], e['code_line'])), t.width, '  ')
        if len(embedded) > 10:
            out.append(c.grey('  +%d more receipts in JSON' % (len(embedded) - 10)))
    out += ["", c.bold("unknowns") + c.grey("  (unknown is not safe, and not dangerous)")]
    for u in report["unknowns"]:
        for i, ln in enumerate(_wrap("%s: %s" % (u["id"], clean(u["detail"])), t.width - 6, "    ")):
            out.append(("  %s %s" % (c.yellow("?"), ln)) if i == 0 else "  " + ln)
    if report["warnings"]:
        out += ["", c.bold("warnings")] + ["  ! " + clean(w)[: t.width - 6] for w in report["warnings"][:10]]
    if report["truncation"]["truncated"]:
        out += ["", c.red("TRUNCATED: ") + clean("; ".join(report["truncation"]["reasons"])) + " - partial, not clean"]
    if report.get("delta"):
        out += [""] + t.box([clean(l) for l in jh_map.delta_markdown(report["delta"], report).split("\n") if l.strip()],
                            "yellow", "graph delta")
    if report.get("whatif"):
        out += [""] + t.box([clean(l) for l in jh_map.whatif_markdown(report["whatif"], report).split("\n") if l.strip()],
                            "magenta", "what-if (hypothetical)")
    out += ["", c.grey("  explore: jankhunt42 map . --html > map.html   ·   data: --json   ·   shareable: --redact")]
    text = "\n".join(out)
    return asciify(text) if ascii_only else text


def sandbox_tty(r, color: bool = True, ascii_only: bool = False, columns: Optional[int] = None) -> str:
    """A sandbox run read like a firewall audit log: what the code tried, what stopped it, and how much of it ran."""
    t = Theme(color, ascii_only, view_width(columns))
    c = t.c
    counts, cov = r.get("counts") or {}, r.get("coverage") or {}
    alerts, denies = counts.get("ALERT", 0), counts.get("DENY", 0)
    name = os.path.basename(str(r.get("root") or "").rstrip("/\\")) or "repository"
    out = t.banner("sandbox run", "%s  ·  %s  ·  %s" % (name, r.get("engine", "?"), r.get("image", "?")))
    if alerts:
        verdict = c.bold(c.magenta("%d ALERT" % alerts)) + c.grey("  canaries touched or persistence attempted")
    elif denies:
        verdict = c.bold(c.yellow("%d DENY" % denies)) + c.grey("  it tried to reach the network; nothing got out")
    else:
        verdict = c.bold(c.green("nothing tried")) + c.grey("  in the steps that ran; a clean run proves little")
    card = [
        t.kv("VERDICT", verdict),
        t.kv("audit log", "%s ALERT  ·  %s DENY  ·  %d events" % (
            c.magenta(str(alerts)) if alerts else "0", c.yellow(str(denies)) if denies else "0", len(r.get("events") or []))),
        t.kv("coverage", "%s%s" % (c.bold(str(cov.get("state", "?"))),
                                   c.yellow("  %d gap(s)" % len(cov.get("gaps") or [])) if cov.get("gaps") else "")),
        t.kv("surfaces", ", ".join(r.get("surfaces") or []) or "none"),
        t.kv("sandbox", c.grey("network off · read-only root · no capabilities · canary credentials")),
        t.kv("evidence", t.label("observed") + c.grey("  adds to the static findings; never refutes them")),
    ]
    fetched = r.get("fetch")
    if fetched:
        fc = fetched.get("counts") or {}
        card.append(t.kv("fetched", "%s of %s pinned packages verified%s" % (
            fc.get("fetched", 0), fc.get("pinned", 0),
            c.yellow("  %d refused" % fc.get("refused", 0)) if fc.get("refused") else "")))
    out += [""] + t.box(card, "magenta" if alerts else "yellow" if denies else "green", "what did it try?")
    out += ["", c.bold("what ran")]
    surface_name = {"install": "install", "import": "on load", "open": "on open"}
    for s in r.get("steps") or []:
        ok = str(s.get("exit")) == "0"
        head = "  %s %s " % (c.grey(_pad(surface_name.get(s.get("surface", "install"), "?"), 8)),
                             c.bold(clean(s.get("name", "?"))))
        tail = "%s%s" % ((c.green if ok else c.yellow)("exit %s" % clean(s.get("exit", "?"))),
                         "" if s.get("traced") else c.yellow("  no trace"))
        out.append(head + c.grey(" · ") + tail)
        if s.get("note"):
            out += [c.grey("    " + ln.strip()) for ln in _wrap(clean(s["note"]), t.width - 6, "    ")]
    if not r.get("steps"):
        out.append("  nothing to run " + c.grey("(no install hooks or open-time commands found)"))
    out += ["", c.bold("audit log") + c.grey("  (every attempt the sandbox saw, most serious first)")]
    events = sorted(r.get("events") or [], key=lambda e: (e.get("verdict") != "ALERT", e.get("verdict") != "DENY",
                                                          e.get("kind", ""), e.get("detail", "")))
    if not events:
        out.append("  no network attempts, canary reads or persistence attempts " + c.grey("in the steps that ran"))
    paint = {"ALERT": lambda x: c.bold(c.magenta(x)), "DENY": c.yellow, "INFO": c.grey}
    for e in events[:30]:
        verdict = e.get("verdict", "INFO")
        who = clean(e.get("process") or "")
        where = clean(e.get("step") or "")
        line = "  %s %s %s" % (paint.get(verdict, c.grey)(_pad(verdict, 5)), c.cyan(_pad(clean(e.get("kind", "")), 13)),
                               clean(e.get("detail", "")))
        out.append(_truncate(line, t.width))
        if who or where:
            out.append(c.grey("        " + _truncate(" · ".join(x for x in (who, where) if x), t.width - 8)))
    if len(events) > 30:
        out.append(c.grey("  +%d more in --json" % (len(events) - 30)))
    if cov.get("gaps"):
        out += ["", c.bold("coverage gaps") + c.grey("  (what the sandbox could not see)")]
        for g in cov["gaps"][:8]:
            for i, ln in enumerate(_wrap(clean(g), t.width - 6, "    ")):
                out.append(("  %s %s" % (c.yellow("?"), ln)) if i == 0 else "  " + ln)
    out += [""] + [c.grey(ln) for ln in _wrap("  limits: " + "; ".join(clean(x) for x in (r.get("limits") or [])[:2]),
                                              t.width, "    ")]
    out += ["", c.grey("  data: --json   ·   into a passport: save --json outside the repository, "
                       "then passport --sandbox-run FILE")]
    text = "\n".join(out)
    return asciify(text) if ascii_only else text


def passport_tty(p, color: bool = True, ascii_only: bool = False, columns: Optional[int] = None) -> str:
    import jh_capabilities
    import jh_capability_approval
    t = Theme(color, ascii_only, view_width(columns))
    c = t.c
    a = p["assessment"]
    d = a["decision"]
    cov = p["coverage"]
    out = t.banner("software passport", "%s  ·  revision %s" % (p["subject"]["name"], (p["subject"]["revision"] or "unknown")[:12]))
    card = [
        t.kv("RELEASE ASSESSMENT", t.level(d["result"]) + "  " + c.grey(d["mode"])),
        t.kv("technical jank score", "%s  grade %s  policy %s" % (
            c.bold(c.tone(score_tone(int(a["jank"].get("score") or 0)), "%s/100" % a["jank"].get("score"))),
            c.grade(str(a["jank"].get("grade")), pad=False),
            (c.green if a["jank"].get("policy") == "pass" else c.red)(str(a["jank"].get("policy"))))),
        t.kv("exposure", t.level(a["exposure"]["class"]) + c.grey("  separate from the Jank Score")),
        t.kv("evidence coverage", "%d/%d areas observed, declared, or inferred" % (cov["evidence_areas_present"], cov["evidence_areas_total"])),
        t.kv("lifecycle", "%s  ·  acceptance %s" % (p["lifecycle"]["state"], t.label("not-supplied" if p["lifecycle"]["acceptance"]["state"] == "not-supplied" else "declared"))),
    ]
    out += [""] + t.box(card, "cyan", "can we responsibly ship it?")
    import jh_n8n
    trigger_text = jh_n8n.trigger_line(p.get('triggers'))
    if trigger_text:
        out += [''] + _wrap(clean('Declared triggers: ' + trigger_text), t.width, '')
    if p.get("capability_delta", {}).get("state", "not-requested") != "not-requested":
        out += [""]
        for line in jh_capabilities.approver_lines(p["capability_delta"]):
            out += _wrap(clean(line), t.width, "")
        approval_line = jh_capability_approval.approver_line(p.get("capability_approval") or {})
        if approval_line:
            out += _wrap(clean(approval_line), t.width, "")
    import jh_sandbox
    sandbox_line = jh_sandbox.passport_line(p.get("sandbox_run") or {})
    if sandbox_line:
        out += [""] + _wrap(clean(sandbox_line), t.width, "")
    gov = p.get("governance") or {}
    if gov.get("profile") == "citizen":
        plain: List[str] = []
        for i, line in enumerate(gov.get("brief") or []):
            body = _wrap(clean(line), t.width - 6, "  " if line.startswith("- ") else "")
            plain += [c.bold(b) if i == 0 else b for b in body]
        out += [""] + t.box(plain, "magenta", "in plain terms  ·  citizen-developer profile")
    policy_context = gov.get("agent_policy_evidence")
    if policy_context:
        out += ["", c.bold("agent policy context")]
        out += _wrap(clean(policy_context.get("note", "")), t.width - 2, "  ")
        paths = [source["path"] for source in policy_context.get("instruction_files", [])] + \
                policy_context.get("configuration_files", [])
        out += _wrap(clean("Files observed in collected scope: " + (", ".join(paths[:5]) or "none observed") +
                           (" (+%d more in JSON)" % (len(paths) - 5) if len(paths) > 5 else "")),
                     t.width - 2, "  ")
        for row in policy_context.get("finding_context", [])[:5]:
            candidates = ", ".join((row.get("candidate_instruction_files") or []) +
                                   (row.get("candidate_configuration_files") or [])) or "none observed nearby"
            text = "%s %s:%s — candidate files: %s" % (row.get("rule", ""), row.get("path", ""),
                                                       row.get("line", 0), candidates)
            out += _wrap(clean(text), t.width - 2, "  ")
        if len(policy_context.get("finding_context", [])) > 5:
            out.append("  %d more finding(s) in JSON" % (len(policy_context["finding_context"]) - 5))
    out += ["", c.bold("why") + c.grey("  (rule outcomes, not a weighted score)")]
    if not d["reasons"]:
        out.append("  no rule triggered " + c.grey("- an assessment, not an approval"))
    for r in d["reasons"]:
        head = "  %s %s%s " % (t.level(r["outcome"]), c.bold(r["rule"]), c.grey(" floor") if r["hard_floor"] else "")
        words = clean(r["message"]).split(" ")
        first = _wrap(" ".join(words), t.width - visible(head), "")
        first_line = first[0] if first else ""
        rest = " ".join(words[len(first_line.split(" ")):]) if first_line else ""
        out.append(head + first_line)
        out += ["      " + b.strip() for b in _wrap(rest, t.width - 6, "")] if rest else []
    out += ["", c.bold("evidence")]
    row = []
    for area, state in cov["evidence_areas"].items():
        disp = {"assessed": "observed", "not assessed": "not assessed"}.get(state, state)
        row.append("%s %s" % (area.replace("_", " "), t.label(disp)))
    line = "  "
    for cell in row:
        if visible(line) + visible(cell) + 3 > t.width:
            out.append(line.rstrip())
            line = "  "
        line += cell + "   "
    out.append(line.rstrip())
    own = p["ownership"]
    out.append("  owners: " + (clean(", ".join(own["owners"] + own["declared_owners"])) or "unknown"))
    cc = p.get("change_control") or {}
    if cc:
        chk = cc["checks"]
        weak = [k.replace("_", " ") for k, v in chk.items() if v["state"] == "not-met"]
        out.append("  change control: %s  review %s  app bypass %s%s" % (
            t.label(cc["state"]), chk["pull_request_review"]["state"],
            {"met": "none", "not-met": "present", "unknown": "unknown"}[chk["no_app_bypass"]["state"]],
            c.grey("  gaps: " + ", ".join(weak[:3])) if weak and cc["state"] != "unknown" else ""))
    pkg = (p.get("package_sources") or {}).get("ecosystems") or {}
    if pkg:
        bad = len(((p.get("package_sources") or {}).get("assessment") or {}).get("disallowed") or [])
        out.append("  package sources: " + ", ".join("%s %s" % (e, v["state"]) for e, v in pkg.items())
                   + (c.red("  %d not allowed" % bad) if bad else ""))
    ai = p.get("ai") or {}
    if ai.get("observed"):
        out += ["", c.bold("ai use") + c.grey("  (static inventory, not proof of use)")]
        services = ai.get("model_services") or []
        if services:
            shown = ", ".join("%s %s" % (clean(s["label"]), t.label(s["evidence"])) for s in services[:3])
            out.append("  services: " + shown + (c.grey("  +%d more" % (len(services) - 3)) if len(services) > 3 else ""))
        out.append("  agents: %d tool server(s) · %d instruction file(s) · %s" % (
            ai.get("agent_tool_servers", 0), len(ai.get("instruction_files") or []), ai.get("human_oversight", "unknown")))
        subs = list((p.get("alignment") or {}).get("subcategories") or {})
        if subs:
            body = _wrap("NIST AI RMF " + ", ".join(subs) + "  (orientation, not conformity)", t.width - 14, "")
            out.append("  frameworks: " + body[0])
            out += ["              " + b.strip() for b in body[1:]]
    if p["remediation"]:
        out += ["", c.bold("next steps")]
        for i, s in enumerate(p["remediation"][:5], 1):
            body = _wrap(clean(s), t.width - 7, "     ")
            out.append("  %d. %s" % (i, body[0]))
            out += ["     " + b.strip() for b in body[1:]]
    if p["warnings"]:
        out += ["", c.bold("warnings")] + ["  ! " + clean(w)[: t.width - 6] for w in p["warnings"][:8]]
    out += ["", c.grey("  export: jankhunt42 passport . --json | --html > passport.html   ·   shareable: --redact")]
    text = "\n".join(out)
    return asciify(text) if ascii_only else text


def agent_fuzz_tty(report, color: bool = True, ascii_only: bool = False,
                   columns: Optional[int] = None) -> str:
    """Compact, case-oriented report for policy-fuzz validation/evaluation."""
    t = Theme(color, ascii_only, view_width(columns))
    c = t.c
    validating = report.get("execution") == "not-run"
    evaluating = report.get("evaluation") == "provided-observations"
    if validating:
        summary = report.get("summary") or {}
        title = "policy-fuzz campaign validation"
        meta = "%s  ·  %s cases  ·  %s probes" % (
            summary.get("id", "campaign"), summary.get("cases", 0), summary.get("probes", 0))
        details = [
            t.kv("status", c.green("VALID") if report.get("valid") else c.red("INVALID")),
            t.kv("targets", ", ".join(summary.get("targets") or []) or "none"),
            t.kv("attack / control", "%s / %s" % (summary.get("attack_cases", 0), summary.get("control_cases", 0))),
            t.kv("execution", "not run"),
            t.kv("campaign sha256", report.get("campaign_sha256", "unavailable")),
        ]
        rows = []
    else:
        summary = report.get("summary") or {}
        title = "policy-fuzz evaluation"
        meta = "%s  ·  caller-provided observations" % report.get("campaign_id", "campaign")
        if summary.get("fail", 0):
            verdict, verdict_paint, accent = "FAIL", c.red, "magenta"
        elif summary.get("policy-not-loaded", 0) or summary.get("inconclusive", 0):
            verdict, verdict_paint, accent = "REVIEW", c.yellow, "yellow"
        else:
            verdict, verdict_paint, accent = "PASS", c.green, "green"
        counts = [("pass", c.green), ("fail", c.red), ("inconclusive", c.yellow),
                  ("policy-not-loaded", c.magenta)]
        details = [t.kv("VERDICT", c.bold(verdict_paint(verdict))),
                   t.kv("outcomes", "  ".join("%s %s" % (cfn(str(summary.get(k, 0))), k)
                                                  for k, cfn in counts)),
                    t.kv("evaluation", "provided observations; no agent was run"),
                    t.kv("campaign sha256", report.get("campaign_sha256", "unavailable")),
                    t.kv("observations sha256", report.get("observations_sha256", "unavailable"))]
        order = {"fail": 0, "policy-not-loaded": 1, "inconclusive": 2, "pass": 3}
        rows = sorted(report.get("cases") or [], key=lambda row: order.get(row.get("outcome"), 4))
    out = t.banner(title, meta) + [""] + t.box(details, accent if evaluating else "cyan", "summary")
    if rows:
        out += ["", c.bold("case results")]
        for row in rows:
            outcome = str(row.get("outcome", "unknown"))
            paint = {"pass": c.green, "fail": c.red, "inconclusive": c.yellow,
                     "policy-not-loaded": c.magenta}.get(outcome, c.grey)
            probes = row.get("probes") or []
            counts = {}
            for probe in probes:
                state = str(probe.get("outcome", "unknown"))
                counts[state] = counts.get(state, 0) + 1
            probe_summary = ", ".join("%d %s" % (n, state) for state, n in sorted(counts.items())) or "no probe detail"
            line = "%s  %s  %s" % (_pad(outcome.upper(), 18), clean(row.get("case_id", "case")),
                                    clean(probe_summary))
            wrapped = _wrap(line, t.width - 2, "    ")
            out += [("  " + part) if index == 0 else part for index, part in enumerate(wrapped)]
    elif validating:
        out += ["", c.bold("ready for adapter execution"),
                "  Campaign text remains declarative input; validation does not execute it."]
    out += ["", c.grey("  HTML: add --html and redirect to a file   ·   machine-readable: --json")]
    text = "\n".join(out)
    return asciify(text) if ascii_only else text
