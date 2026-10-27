#!/usr/bin/env python3
"""Log triage: parse, fingerprint, and rank log lines."""
from __future__ import annotations

import gzip
import json
import re
import sys
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from jh_core import TOOL, VERSION, trim

ANSI_RE = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")
SEV_RE = re.compile(
    r"\b(EMERG(?:ENCY)?|ALERT|CRITICAL|FATAL|PANIC|SEVERE|ERROR|ERR|WARNING|WARN|NOTICE|INFO|DEBUG|TRACE)\b",
    re.IGNORECASE,
)
SEV_MAP = {
    "emerg": "critical", "emergency": "critical", "alert": "critical",
    "critical": "critical", "fatal": "critical", "panic": "critical", "severe": "critical",
    "error": "error", "err": "error",
    "warning": "warning", "warn": "warning",
    "notice": "info", "info": "info", "debug": "debug", "trace": "trace",
}
TS_RES = [
    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?(?:Z|[+-]\d{2}:?\d{2})?"),
    re.compile(r"[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}"),
    re.compile(r"\d{2}:\d{2}:\d{2}(?:[.,]\d+)?"),
]
STACK_RE = re.compile(
    r"^\s+at\s|^\s*File \"|^Traceback \(most recent call last\)|^Caused by:|^panic:"
    r"|^goroutine \d+|^#\d+\s+0x|^\s+\.\.\. \d+ more|^Exception in thread|^\[error\]"
    r"|^\s*at [\w.$/]+|^Fatal error|^Segmentation fault|^\*\*\* stack smashing",
)
EXC_RE = re.compile(r"\b(?:Error|Exception|panic|fatal|Segmentation fault)\b")
UUID_RE = re.compile(r"\b[0-9a-f]{8}-[0-9a-f-]{27,}\b", re.IGNORECASE)
HEX_RE = re.compile(r"0x[0-9a-f]+", re.IGNORECASE)
IP_RE = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}(?::\d+)?\b")
PATH_RE = re.compile(r"(?:/[\w.\-]+){2,}")
NUM_RE = re.compile(r"\b\d+(?:\.\d+)?(?:ms|s|m|h|kb|mb|gb)?\b", re.IGNORECASE)
QUOTED_RE = re.compile(r'"[^"]*"|\'[^\']*\'')
WS_RE = re.compile(r"\s+")

SEV_ORDER = {"critical": 0, "error": 1, "warning": 2, "info": 3, "debug": 4, "trace": 5}


@dataclass
class LogCluster:
    severity: str
    message: str
    key: str
    count: int = 0
    first_line: int = 0
    last_line: int = 0
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None
    samples: List[str] = field(default_factory=list)
    has_stack: bool = False


@dataclass
class TriageResult:
    sources: List[str] = field(default_factory=list)
    lines: int = 0
    events: int = 0
    clusters: List[LogCluster] = field(default_factory=list)
    counts: Dict[str, int] = field(default_factory=dict)
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None


def _read(path: str) -> str:
    if path == "-":
        return sys.stdin.read()
    if path.endswith(".gz"):
        with gzip.open(path, "rb") as fh:
            return fh.read().decode("utf-8", "replace")
    with open(path, "rb") as fh:
        return fh.read().decode("utf-8", "replace")


def _timestamp(line: str) -> Optional[str]:
    for pat in TS_RES:
        m = pat.search(line)
        if m:
            return m.group(0)
    return None


def _severity(line: str) -> Optional[str]:
    m = SEV_RE.search(line)
    if not m:
        return None
    return SEV_MAP.get(m.group(1).lower())


def _clean(line: str) -> str:
    line = ANSI_RE.sub("", line)
    return line.replace("\r", "").rstrip()


def _display(line: str) -> str:
    out = _clean(line)
    for pat in TS_RES:
        out = pat.sub("", out, count=1)
    out = SEV_RE.sub("", out, count=1)
    out = re.sub(r"^\s*[\[\](){}|:,\-]+\s*", "", out)
    return trim(out, 240)


def _normalize(line: str) -> str:
    s = ANSI_RE.sub("", line)
    s = TS_RES[0].sub("<ts>", s)
    s = UUID_RE.sub("<uuid>", s)
    s = HEX_RE.sub("<hex>", s)
    s = IP_RE.sub("<ip>", s)
    s = PATH_RE.sub("<path>", s)
    s = NUM_RE.sub("<n>", s)
    s = QUOTED_RE.sub('"<str>"', s)
    s = WS_RE.sub(" ", s).strip()
    return s[:400]


def _json_event(line: str) -> Optional[Tuple[str, str, Optional[str], List[str], bool]]:
    stripped = line.strip()
    if not (stripped.startswith("{") and stripped.endswith("}")):
        return None
    try:
        obj = json.loads(stripped)
    except (ValueError, TypeError, RecursionError):
        return None
    if not isinstance(obj, dict):
        return None
    sev_raw = obj.get("level") or obj.get("severity") or obj.get("severity_text") or obj.get("lvl")
    sev = None
    if sev_raw is not None:
        sev = _severity(str(sev_raw)) or SEV_MAP.get(str(sev_raw).lower())
    msg = obj.get("message") or obj.get("msg") or obj.get("event") or obj.get("text")
    if msg is None and obj.get("error"):
        msg = obj.get("error")
        sev = sev or "error"
    if msg is None:
        return None
    if not isinstance(msg, str):
        msg = json.dumps(msg, ensure_ascii=False, default=str)
    ts = obj.get("time") or obj.get("timestamp") or obj.get("ts") or obj.get("@timestamp")
    ts = str(ts) if ts is not None else _timestamp(line)
    stack = obj.get("stack") or obj.get("traceback") or obj.get("exception") or obj.get("err")
    stack_lines: List[str] = []
    if stack:
        if isinstance(stack, (list, tuple)):
            stack_lines = [str(x) for x in stack][:8]
        else:
            stack_lines = str(stack).splitlines()[:8]
    return (sev or "info", _clean(msg), ts, stack_lines, bool(stack_lines))


class _ClusterState:
    def __init__(self, result: TriageResult) -> None:
        self.result = result
        self.by_key: Dict[str, LogCluster] = {}
        self.current: Optional[LogCluster] = None

    def cluster_for(self, severity: str, message: str, key: str) -> LogCluster:
        cluster = self.by_key.get(key)
        if cluster is None:
            cluster = LogCluster(severity=severity, message=message, key=key)
            self.by_key[key] = cluster
            self.result.clusters.append(cluster)
        return cluster

    def add_json(self, parsed, line_no: int, ts: Optional[str]) -> None:
        sev, msg, jts, stack_lines, has_stack = parsed
        key = sev + "\x00" + _normalize(msg)
        cluster = self.cluster_for(sev, msg, key)
        cluster.count += 1
        cluster.first_line = cluster.first_line or line_no
        cluster.last_line = line_no
        cluster.first_ts = cluster.first_ts or (jts or ts)
        cluster.last_ts = jts or ts or cluster.last_ts
        if not cluster.samples:
            cluster.samples.append(trim(msg, 300))
        for stack_line in stack_lines[:6]:
            if stack_line and stack_line not in cluster.samples:
                cluster.samples.append(trim(stack_line, 300))
        if has_stack:
            cluster.has_stack = True
        self.result.events += 1
        self.current = cluster

    def add_text(self, line: str, line_no: int, ts: Optional[str]) -> None:
        sev = _severity(line)
        is_stack = bool(STACK_RE.search(line))
        if sev is None and self.current is not None and (
                is_stack or line[:1].isspace() or EXC_RE.search(line)):
            if len(self.current.samples) < 8:
                self.current.samples.append(trim(line, 300))
            if is_stack:
                self.current.has_stack = True
            self.current.last_line = line_no
            self.current.last_ts = ts or self.current.last_ts
            return
        if sev is None and is_stack:
            sev = "error"
        if sev is None:
            return

        msg = _display(line)
        key = sev + "\x00" + _normalize(line)
        cluster = self.cluster_for(sev, msg, key)
        cluster.count += 1
        cluster.first_line = cluster.first_line or line_no
        cluster.last_line = line_no
        cluster.first_ts = cluster.first_ts or ts
        cluster.last_ts = ts or cluster.last_ts
        if len(cluster.samples) < 8:
            cluster.samples.append(trim(line, 300))
        if STACK_RE.search(line) or EXC_RE.search(line):
            cluster.has_stack = True
        self.result.events += 1
        self.current = cluster

    def finish(self) -> None:
        result = self.result
        result.counts = {sev: 0 for sev in SEV_ORDER}
        for cluster in result.clusters:
            result.counts[cluster.severity] = result.counts.get(cluster.severity, 0) + cluster.count
        result.clusters.sort(key=lambda c: (SEV_ORDER.get(c.severity, 9), -c.count, c.message))


def triage_paths(paths: Sequence[str], grep: Optional[str] = None) -> TriageResult:
    result = TriageResult(sources=list(paths))
    grep_re: Optional[re.Pattern] = None
    if grep:
        try:
            grep_re = re.compile(grep, re.IGNORECASE)
        except re.error as exc:
            print(f"jankhunt42: bad --grep regex: {exc}", file=sys.stderr)
            grep_re = None
    state = _ClusterState(result)

    for path in paths:
        try:
            text = _read(path)
        except OSError as exc:
            print(f"jankhunt42: cannot read {path}: {exc}", file=sys.stderr)
            continue
        for line_no, raw in enumerate(text.split("\n"), 1):
            result.lines += 1
            line = _clean(raw)
            if not line.strip():
                continue
            if grep_re and not grep_re.search(line):
                continue
            ts = _timestamp(line)
            if ts and result.first_ts is None:
                result.first_ts = ts
            if ts:
                result.last_ts = ts
            parsed = _json_event(line)
            if parsed:
                state.add_json(parsed, line_no, ts)
            else:
                state.add_text(line, line_no, ts)

    state.finish()
    return result


def triage_json(result: TriageResult, top: int = 30) -> str:
    data = {
        "tool": TOOL,
        "version": VERSION,
        "command": "triage",
        "summary": {
            "sources": result.sources,
            "lines": result.lines,
            "events": result.events,
            "clusters": len(result.clusters),
            "counts": result.counts,
            "first_timestamp": result.first_ts,
            "last_timestamp": result.last_ts,
        },
        "clusters": [asdict(c) for c in result.clusters[:top]],
    }
    return json.dumps(data, indent=2, ensure_ascii=False)


def triage_markdown(result: TriageResult, top: int = 30) -> str:
    out: List[str] = []
    out.append("# Log triage")
    out.append("")
    out.append("**Sources:** `%s` · **Lines:** %d · **Events:** %d · **Clusters:** %d"
               % (", ".join(result.sources), result.lines, result.events, len(result.clusters)))
    if result.first_ts or result.last_ts:
        out.append("")
        out.append("**Time span:** %s → %s" % (result.first_ts or "?", result.last_ts or "?"))
    out.append("")
    out.append("| Severity | Events |")
    out.append("|---|---:|")
    for sev in ("critical", "error", "warning", "info", "debug", "trace"):
        if result.counts.get(sev):
            out.append("| %s | %d |" % (sev, result.counts[sev]))
    out.append("")
    if not result.clusters:
        out.append("No severity-tagged or exception-like lines found. Try `--grep` with a symptom, or inspect the raw tail.")
        return "\n".join(out)
    out.append("## Top clusters")
    out.append("")
    for idx, c in enumerate(result.clusters[:top], 1):
        out.append("### %d. `%d×` %s — %s" % (idx, c.count, c.severity.upper(), c.message))
        span = "line %d" % c.first_line
        if c.last_line and c.last_line != c.first_line:
            span += " → %d" % c.last_line
        if c.first_ts or c.last_ts:
            span += " · %s → %s" % (c.first_ts or "?", c.last_ts or "?")
        out.append("")
        out.append("`%s`%s" % (span, " · stack trace attached" if c.has_stack else ""))
        out.append("")
        if c.samples:
            out.append("```text")
            for sample in c.samples[:6]:
                out.append(sample)
            out.append("```")
            out.append("")
    return "\n".join(out)
