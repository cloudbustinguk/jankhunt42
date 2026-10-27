#!/usr/bin/env python3
"""Orientation crosswalk from passport rules and evidence to the NIST AI Risk
Management Framework (AI RMF 1.0) and the IAPP AIGP body of knowledge.

The crosswalk says which framework outcomes a piece of jankhunt42 evidence
*informs* when the software is, or uses, an AI system. It is orientation for
a governance programme, never a conformity assessment, certification, or
legal advice, and no rule outcome depends on it.
"""
from __future__ import annotations

from typing import Any, Dict, Iterable, List, Tuple

NIST_AI_RMF = "NIST AI 100-1, Artificial Intelligence Risk Management Framework (AI RMF 1.0), January 2023"
AIGP = ("IAPP AIGP Body of Knowledge v2.1 (effective February 2026); domain names are paraphrased, check the "
        "official document for exact wording")

AIGP_DOMAINS = {
    "I": "foundations of AI governance",
    "II": "laws, standards, and frameworks",
    "III": "governing AI development",
    "IV": "governing AI deployment and use",
}

# NIST AI 100-1 subcategory statements (a US government work), quoted.
AI_RMF = {
    "GOVERN 1.3": "Processes, procedures, and practices are in place to determine the needed level of risk "
                  "management activities based on the organization's risk tolerance.",
    "GOVERN 1.6": "Mechanisms are in place to inventory AI systems and are resourced according to organizational "
                  "risk priorities.",
    "GOVERN 2.1": "Roles and responsibilities and lines of communication related to mapping, measuring, and "
                  "managing AI risks are documented and are clear to individuals and teams throughout the "
                  "organization.",
    "GOVERN 3.2": "Policies and procedures are in place to define and differentiate roles and responsibilities for "
                  "human-AI configurations and oversight of AI systems.",
    "GOVERN 4.2": "Organizational teams document the risks and potential impacts of the AI technology they design, "
                  "develop, deploy, evaluate, and use, and they communicate about the impacts more broadly.",
    "GOVERN 6.1": "Policies and procedures are in place that address AI risks associated with third-party entities, "
                  "including risks of infringement of a third-party's intellectual property or other rights.",
    "MAP 1.1": "Intended purposes, potentially beneficial uses, context-specific laws, norms and expectations, and "
               "prospective settings in which the AI system will be deployed are understood and documented.",
    "MAP 3.5": "Processes for human oversight are defined, assessed, and documented in accordance with "
               "organizational policies from the GOVERN function.",
    "MAP 4.1": "Approaches for mapping AI technology and legal risks of its components - including the use of "
               "third-party data or software - are in place, followed, and documented, as are risks of "
               "infringement of a third party's intellectual property or other rights.",
    "MAP 4.2": "Internal risk controls for components of the AI system, including third-party AI technologies, "
               "are identified and documented.",
    "MAP 5.1": "Likelihood and magnitude of each identified impact (both potentially beneficial and harmful) based "
               "on expected use, past uses of AI systems in similar contexts, public incident reports, feedback "
               "from those external to the team that developed or deployed the AI system, or other data are "
               "identified and documented.",
    "MEASURE 1.1": "Approaches and metrics for measurement of AI risks enumerated during the MAP function are "
                   "selected for implementation starting with the most significant AI risks. The risks or "
                   "trustworthiness characteristics that will not - or cannot - be measured are properly "
                   "documented.",
    "MEASURE 2.1": "Test sets, metrics, and details about the tools used during TEVV are documented.",
    "MEASURE 2.5": "The AI system to be deployed is demonstrated to be valid and reliable. Limitations of the "
                   "generalizability beyond the conditions under which the technology was developed are "
                   "documented.",
    "MEASURE 2.7": "AI system security and resilience - as identified in the MAP function - are evaluated and "
                   "documented.",
    "MEASURE 2.8": "Risks associated with transparency and accountability - as identified in the MAP function - "
                   "are examined and documented.",
    "MEASURE 2.10": "Privacy risk of the AI system - as identified in the MAP function - is examined and "
                    "documented.",
    "MANAGE 1.1": "A determination is made as to whether the AI system achieves its intended purposes and stated "
                  "objectives and whether its development or deployment should proceed.",
    "MANAGE 1.2": "Treatment of documented AI risks is prioritized based on impact, likelihood, and available "
                  "resources or methods.",
    "MANAGE 1.3": "Responses to the AI risks deemed high priority, as identified by the MAP function, are "
                  "developed, planned, and documented. Risk response options can include mitigating, "
                  "transferring, avoiding, or accepting.",
    "MANAGE 3.1": "AI risks and benefits from third-party resources are regularly monitored, and risk controls are "
                  "applied and documented.",
}

FUNCTION_ORDER = {"GOVERN": 0, "MAP": 1, "MEASURE": 2, "MANAGE": 3}


def subcategory_key(sub: str) -> Tuple[int, List[int]]:
    """NIST order: GOVERN, MAP, MEASURE, MANAGE, then numerically."""
    function, number = sub.split()
    return FUNCTION_ORDER[function], [int(x) for x in number.split(".")]


# rule or evidence -> (AI RMF subcategories, AIGP domains)
RULES: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "P-CAP-001": (("MEASURE 2.7", "MAP 3.5", "MANAGE 1.3"), ("III", "IV")),
    "P-RUN-001": (("MEASURE 2.7", "MANAGE 1.3"), ("III", "IV")),
    "P-COV-001": (("MEASURE 1.1",), ("III",)),
    "P-OWN-001": (("GOVERN 2.1",), ("I",)),
    "P-CUS-001": (("GOVERN 2.1", "GOVERN 3.2"), ("I", "III")),
    "P-DAT-001": (("MEASURE 2.10", "MAP 4.1"), ("II", "IV")),
    "P-DAT-002": (("MEASURE 2.7", "MAP 5.1", "MANAGE 1.3"), ("IV",)),
    "P-DAT-003": (("MAP 1.1", "MEASURE 2.10"), ("III",)),
    "P-SEC-001": (("MEASURE 2.7",), ("IV",)),
    "P-AGT-001": (("GOVERN 3.2", "MAP 3.5", "GOVERN 6.1"), ("IV",)),
    "P-AI-001": (("MEASURE 2.10", "MAP 4.1", "GOVERN 6.1", "MANAGE 3.1"), ("II", "IV")),
    "P-OPS-001": (("MEASURE 2.1", "MEASURE 2.5"), ("III",)),
    "P-EVD-001": (("GOVERN 6.1", "MAP 4.1", "MANAGE 3.1"), ("IV",)),
    "P-JNK-001": (("MEASURE 2.5", "MEASURE 2.7"), ("III",)),
    "P-EXP-001": (("GOVERN 1.3", "MAP 5.1", "MANAGE 1.2"), ("I",)),
    "P-CHG-001": (("GOVERN 3.2", "MAP 3.5"), ("III",)),
    "P-SUP-001": (("GOVERN 6.1", "MAP 4.1", "MANAGE 3.1"), ("IV",)),
}
EVIDENCE: Dict[str, Tuple[Tuple[str, ...], Tuple[str, ...]]] = {
    "ai.model_services": (("GOVERN 1.6", "MAP 4.1", "MAP 4.2"), ("IV",)),
    "governance.agent": (("MAP 4.1", "MAP 4.2", "MANAGE 3.1"), ("IV",)),
    "governance.custodians": (("GOVERN 2.1",), ("I",)),
    "governance.brief": (("GOVERN 4.2", "MEASURE 2.8"), ("I",)),
    "lifecycle.acceptance": (("MANAGE 1.1", "GOVERN 2.1"), ("III",)),
    "provenance.verification": (("MANAGE 3.1", "GOVERN 6.1"), ("IV",)),
    "unknowns": (("MEASURE 1.1",), ("III",)),
}


def refs(key: str) -> Dict[str, List[str]]:
    rmf, aigp = RULES.get(key) or EVIDENCE.get(key) or ((), ())
    return {"nist_ai_rmf": list(rmf), "aigp": ["%s (%s)" % (d, AIGP_DOMAINS[d]) for d in aigp]}


def alignment(triggered: Iterable[str]) -> Dict[str, Any]:
    """The passport's `alignment` section: references for every rule and
    evidence area, and the subcategories behind the rules that triggered."""
    triggered = list(triggered)
    used = sorted({sub for rule in triggered for sub in (RULES.get(rule) or ((), ()))[0]}, key=subcategory_key)
    return {
        "note": ("orientation only: the framework outcomes each rule and evidence area informs when the software "
                 "is, or uses, an AI system; not a conformity assessment, a certification, or legal advice"),
        "frameworks": {"nist_ai_rmf": NIST_AI_RMF, "aigp": AIGP},
        "rules": {rule: refs(rule) for rule in sorted(RULES)},
        "evidence": {key: refs(key) for key in sorted(EVIDENCE)},
        "triggered": {rule: refs(rule) for rule in triggered if rule in RULES},
        "subcategories": {sub: AI_RMF[sub] for sub in used},
    }
