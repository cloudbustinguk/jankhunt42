#!/usr/bin/env python3
"""Cross-file duplicate detection: "same bug, N sites."

jankhunt's existing `duplicate_blocks` check is file-local by construction
(it slides a window over one file's lines). That misses the pattern AI
coding assistants are shown to amplify: the same defect pasted into several
files rather than refactored into one. CRBugBench and related industry
analysis flag this as a real blind spot for diff-only reviewers -- a
reviewer that only sees one file, or one diff hunk, cannot tell "this is
the fourth copy of this exact mistake."

This groups findings that already fired (any rule, not just
duplicate_blocks) by (rule, normalized evidence) across *different* files.
It does not add new findings or change severity; it attaches a cluster
summary so a human (or an agent) can see "fix the class, not the line."
Deterministic string normalization only -- no fuzzy matching, no ML.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

MIN_EVIDENCE_LEN = 12  # below this, matching evidence is too generic to be meaningful


def _normalize(evidence: str) -> str:
    s = evidence.strip()
    s = re.sub(r"\s+", " ", s)
    s = re.sub(r"\b\d+\b", "N", s)          # collapse numeric literals
    s = re.sub(r"(['\"])(?:(?!\1).)*\1", "'S'", s)  # collapse string literals
    return s


@dataclass
class DuplicateCluster:
    rule: str
    title: str
    severity: str
    normalized_evidence: str
    sites: List[Tuple[str, int]] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "rule": self.rule,
            "title": self.title,
            "severity": self.severity,
            "count": len(self.sites),
            "sites": [{"path": p, "line": ln} for p, ln in self.sites],
        }


def find_cross_file_duplicates(findings: Sequence) -> List[DuplicateCluster]:
    groups: Dict[Tuple[str, str], DuplicateCluster] = {}
    for f in findings:
        norm = _normalize(f.evidence or "")
        if len(norm) < MIN_EVIDENCE_LEN:
            continue
        key = (f.rule, norm)
        cluster = groups.get(key)
        if cluster is None:
            cluster = DuplicateCluster(rule=f.rule, title=f.title, severity=f.severity,
                                        normalized_evidence=norm)
            groups[key] = cluster
        cluster.sites.append((f.path, f.line))

    out = []
    for cluster in groups.values():
        distinct_files = {p for p, _ in cluster.sites}
        if len(distinct_files) < 2:
            continue
        cluster.sites.sort()
        out.append(cluster)
    out.sort(key=lambda c: (-len(c.sites), c.rule, c.normalized_evidence))
    return out
