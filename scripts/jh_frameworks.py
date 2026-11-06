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
    "P-RUN-002": (("MEASURE 2.7", "MAP 3.5", "MANAGE 1.3"), ("III", "IV")),
    "P-RUN-003": (("MEASURE 2.7", "MAP 3.5", "MANAGE 1.3"), ("III", "IV")),
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


# ---------------------------------------------------------------------------
# OWASP orientation for scanner rules: which OWASP risk a finding is an instance of. Orientation for IT and security
# approvers who work from these lists, never a compliance claim. A rule with no clear fit has no tag.
# ---------------------------------------------------------------------------

OWASP_CD = ("OWASP Top 10 Risks for Citizen Development (owasp.org/www-project-citizen-development-top10-security-risks)")
OWASP_ASI = ("OWASP Top 10 for Agentic Applications 2026, OWASP GenAI Security Project, December 2025 (CC BY-SA 4.0)")

OWASP_RISKS = {
    "CD-SEC-01": "Blind Trust",
    "CD-SEC-02": "Account Impersonation",
    "CD-SEC-03": "Authorization Misuse",
    "CD-SEC-04": "Sensitive Data Leakage and Handling Failures",
    "CD-SEC-05": "Authentication and Secure Communication Failures",
    "CD-SEC-06": "Vulnerable and Untrusted Components",
    "CD-SEC-07": "Security Misconfiguration",
    "CD-SEC-08": "Injection Handling Failures",
    "CD-SEC-09": "Asset Management Failures",
    "CD-SEC-10": "Security Logging and Monitoring Failures",
    "ASI01": "Agent Goal Hijack",
    "ASI02": "Tool Misuse and Exploitation",
    "ASI03": "Identity and Privilege Abuse",
    "ASI04": "Agentic Supply Chain Vulnerabilities",
    "ASI05": "Unexpected Code Execution (RCE)",
    "ASI06": "Memory & Context Poisoning",
    "ASI07": "Insecure Inter-Agent Communication",
    "ASI08": "Cascading Failures",
    "ASI09": "Human-Agent Trust Exploitation",
    "ASI10": "Rogue Agents",
}

_INJECTION, _CONFIG, _AUTHN, _DATA, _COMPONENTS = ("CD-SEC-08",), ("CD-SEC-07",), ("CD-SEC-05",), ("CD-SEC-04",), ("CD-SEC-06",)
OWASP_RULES: Dict[str, Tuple[str, ...]] = {
    # code
    "JH101": ("CD-SEC-03", "CD-SEC-04"), "JH102": ("CD-SEC-08", "ASI05"), "JH103": ("CD-SEC-08", "ASI05"),
    "JH104": _INJECTION, "JH105": _AUTHN, "JH106": _INJECTION, "JH107": _AUTHN, "JH108": _CONFIG, "JH109": _CONFIG,
    "JH110": _CONFIG, "JH111": _COMPONENTS, "JH112": _AUTHN, "JH115": _AUTHN, "JH116": _CONFIG, "JH118": _INJECTION,
    "JH119": _INJECTION, "JH120": _INJECTION, "JH121": _CONFIG, "JH122": _CONFIG, "JH124": _INJECTION,
    "JH125": _INJECTION, "JH126": _INJECTION, "JH127": _INJECTION, "JH128": _INJECTION, "JH130": _CONFIG,
    # what AI-built apps get wrong
    "JH131": ("CD-SEC-01", "ASI01"), "JH132": _DATA, "JH133": _DATA, "JH134": ("CD-SEC-03", "CD-SEC-04"),
    "JH154": ("CD-SEC-03",), "JH155": ("CD-SEC-03", "CD-SEC-04"),
    # .NET
    "JH135": ("CD-SEC-03",), "JH136": _CONFIG, "JH137": _CONFIG, "JH138": _AUTHN, "JH139": _INJECTION,
    "JH140": _INJECTION, "JH141": _DATA, "JH142": _COMPONENTS, "JH143": _COMPONENTS,
    # Power Platform and Copilot Studio
    "JH144": _AUTHN, "JH145": ("CD-SEC-04", "CD-SEC-10"), "JH146": _DATA, "JH147": _DATA,
    "JH148": ("CD-SEC-05", "ASI03"), "JH149": _DATA, "JH150": ("CD-SEC-02", "ASI03"), "JH151": _AUTHN,
    "JH152": _CONFIG, "JH153": ("CD-SEC-04", "ASI01", "ASI02"),
    # n8n
    "JH156": _AUTHN, "JH157": ("CD-SEC-08", "ASI05"), "JH158": ("CD-SEC-08", "ASI02"), "JH159": _DATA,
    # errors that disappear
    "JH201": ("CD-SEC-10",), "JH217": ("CD-SEC-10",), "JH204": _CONFIG,
    # containers, Kubernetes, CI and dependencies
    "JH401": _DATA, "JH402": _COMPONENTS, "JH403": _CONFIG, "JH404": _COMPONENTS, "JH405": _CONFIG, "JH406": _CONFIG,
    "JH407": _CONFIG, "JH408": _CONFIG, "JH409": _CONFIG, "JH410": _CONFIG, "JH411": _CONFIG, "JH412": _COMPONENTS,
    "JH414": _CONFIG, "JH415": _DATA, "JH416": ("CD-SEC-01",), "JH417": _COMPONENTS, "JH418": _INJECTION,
    "JH419": _INJECTION, "JH420": ("CD-SEC-03",), "JH421": _COMPONENTS, "JH422": _COMPONENTS, "JH423": _COMPONENTS,
    "JH424": _COMPONENTS, "JH425": _CONFIG, "JH426": _COMPONENTS, "JH427": _DATA, "JH428": ("CD-SEC-03",),
    "JH429": _COMPONENTS, "JH430": _COMPONENTS, "JH431": _COMPONENTS, "JH432": ("CD-SEC-03", "ASI03"),
    # tests that prove nothing: trusting what was generated without checking it
    "JH501": ("CD-SEC-01",), "JH502": ("CD-SEC-01",), "JH504": ("CD-SEC-01",), "JH505": ("CD-SEC-01",),
    # AI agents
    "JH701": ("CD-SEC-01", "ASI01"), "JH702": ("CD-SEC-07", "ASI02", "ASI05"), "JH703": ("CD-SEC-07", "ASI02", "ASI05"),
    "JH704": ("CD-SEC-07", "ASI05"), "JH705": ("CD-SEC-06", "ASI04"), "JH706": ("CD-SEC-04", "ASI03"),
    "JH707": _AUTHN, "JH708": ("CD-SEC-08", "ASI01"), "JH709": ("CD-SEC-07", "ASI02", "ASI05"),
    "JH710": ("CD-SEC-07", "ASI05"), "JH711": ("CD-SEC-07", "ASI05"),
    "JH712": ("CD-SEC-07", "ASI02", "ASI05"),
    "JH713": ("CD-SEC-04", "CD-SEC-07", "ASI03"),
}


def owasp(rule_id: str) -> List[str]:
    """The OWASP risk IDs a rule's findings are an instance of; [] for a rule with no clear fit."""
    return list(OWASP_RULES.get(rule_id, ()))


def owasp_counts(findings: Iterable[Any]) -> Dict[str, Any]:
    """Findings per OWASP risk, in list order, for the passport's orientation line."""
    counts: Dict[str, int] = {}
    for f in findings:
        for rid in owasp(getattr(f, "rule", None) or (f.get("rule") if isinstance(f, dict) else "")):
            counts[rid] = counts.get(rid, 0) + 1
    order = list(OWASP_RISKS)
    return {
        "note": "orientation only: the OWASP risk each finding is an instance of; not a compliance assessment",
        "lists": {"citizen_development": OWASP_CD, "agentic": OWASP_ASI},
        "risks": [{"id": rid, "title": OWASP_RISKS[rid], "findings": counts[rid]}
                  for rid in sorted(counts, key=order.index)],
    }
