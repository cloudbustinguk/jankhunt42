# AI governance: NIST AI RMF and AIGP orientation

Software increasingly *is* an AI system, or calls one, and it is increasingly
*built* by one: coding agents and their MCP tool servers are AI systems an
organisation deploys. The passport records what the repository shows about
both, and says which governance outcomes that evidence informs.

This is orientation, not a conformity assessment, a certification, or legal
advice. No rule outcome depends on the crosswalk, and nothing in it claims an
organisation meets a framework.

## What the passport records

| Section | Content | Framework outcome it informs |
|---|---|---|
| `ai.model_services` | external AI model services the software can reach (OpenAI, Anthropic, Google AI, Groq, Mistral, and others the map recognizes), each with its evidence tier and the principals that reach it | NIST AI RMF GOVERN 1.6 (inventory), MAP 4.1 and 4.2 (third-party components) |
| `ai.agent_tool_servers`, `ai.instruction_files` | the coding-agent tooling the repository carries | MAP 4.1, MAP 4.2, MANAGE 3.1 |
| `ai.human_oversight` | "approval bypass observed" when `JH702`-`JH704` leads exist, "no approval bypass observed" when agent tooling exists without them, "no agent tooling observed" otherwise | GOVERN 3.2, MAP 3.5 |
| `ai.sensitive_data_with_ai` | one entry per confidential or restricted data store and AI service reachable together, with the principals that reach both (the first 20; `sensitive_data_with_ai_total` counts all, and `P-AI-001` sees all) | MEASURE 2.10 (privacy), GOVERN 6.1 (third-party risk) |
| `alignment` | for every policy rule and evidence area: NIST AI RMF subcategories and AIGP domains; for the rules behind this decision, the quoted subcategory text | |

`ai.observed` is true when any model service, agent tool server, agent
instruction file, or agent lead was found. The terminal, Markdown, and HTML
views show the AI-use and framework sections only then; the JSON always
carries them.

The inventory is static: it shows what the repository can reach, not what
runs or what data moves. A model service found through an SDK import is
`inferred`; one with a literal endpoint is `supported`.

## `P-AI-001`: sensitive data alongside an external AI service

`P-AI-001` triggers when a confidential or restricted data store and an
external AI model service are reachable from the same principal. Like every
reach in `map`, this is co-reachability, not a data flow. It still asks for
a decision, because what a provider retains, trains on, and where it
processes data are governance questions someone has to answer and record.

| Profile | Outcome |
|---|---|
| standard | review |
| citizen | block, until an operator records the decision as a profile exception |

The message names the stores and the service after a colon, so `--redact`
removes them; the redacted `ai` section also replaces service, store,
principal, and instruction-file names with ordinal placeholders. Without a
connectivity map the rule reports "not assessed" (and the coverage floor
`P-COV-001` already makes the decision `insufficient-evidence`). The remediation step asks for the provider's terms to be
checked (retention, training use, region), the decision recorded, or the
restricted data kept away from AI calls.

## The crosswalk

Sources:

- **NIST AI 100-1**, *Artificial Intelligence Risk Management Framework (AI
  RMF 1.0)*, January 2023. The passport quotes the statements of the
  subcategories it cites.
- **IAPP AIGP Body of Knowledge v2.1**, effective February 2026. Its four
  domains are paraphrased here (I foundations of AI governance; II laws,
  standards, and frameworks; III governing AI development; IV governing AI
  deployment and use). Check the official document for exact wording.

| Rule or evidence | NIST AI RMF | AIGP domain |
|---|---|---|
| `P-COV-001` coverage | MEASURE 1.1 | III |
| `P-OWN-001` owner | GOVERN 2.1 | I |
| `P-CUS-001` engineering custodian | GOVERN 2.1, GOVERN 3.2 | I, III |
| `P-DAT-001` sensitive external export | MEASURE 2.10, MAP 4.1 | II, IV |
| `P-DAT-002` authority over critical assets | MEASURE 2.7, MAP 5.1, MANAGE 1.3 | IV |
| `P-DAT-003` data classification | MAP 1.1, MEASURE 2.10 | III |
| `P-SEC-001` public exposure | MEASURE 2.7 | IV |
| `P-AGT-001` agent guardrails | GOVERN 3.2, MAP 3.5, GOVERN 6.1 | IV |
| `P-AI-001` sensitive data with an AI service | MEASURE 2.10, MAP 4.1, GOVERN 6.1, MANAGE 3.1 | II, IV |
| `P-OPS-001` tests and CI | MEASURE 2.1, MEASURE 2.5 | III |
| `P-EVD-001` supply-chain evidence | GOVERN 6.1, MAP 4.1, MANAGE 3.1 | IV |
| `P-JNK-001` Jank Score policy | MEASURE 2.5, MEASURE 2.7 | III |
| `P-EXP-001` exposure ceiling | GOVERN 1.3, MAP 5.1, MANAGE 1.2 | I |
| AI-use inventory | GOVERN 1.6, MAP 4.1, MAP 4.2 | IV |
| agent tooling | MAP 4.1, MAP 4.2, MANAGE 3.1 | IV |
| plain-language brief | GOVERN 4.2, MEASURE 2.8 | I |
| acceptance record | MANAGE 1.1, GOVERN 2.1 | III |
| verification results | MANAGE 3.1, GOVERN 6.1 | IV |
| unknowns | MEASURE 1.1 | III |

The test suite checks that every policy rule has an entry, that every cited
subcategory has its quoted statement, and that every AIGP domain cited
exists.

## OWASP risks for scanner findings

Security approvers often work from two OWASP lists. Each scanner rule names
the risks its findings are an instance of:

- the **OWASP Top 10 Risks for Citizen Development** (`CD-SEC-01` to
  `CD-SEC-10`), from the project's published list;
- the **OWASP Top 10 for Agentic Applications 2026** (`ASI01` to `ASI10`),
  OWASP GenAI Security Project, December 2025, CC BY-SA 4.0.

**Where the risks appear:**
- the rule catalog: an OWASP column in `jankhunt42 rules`, and `owasp` in
  `rules --json`;
- the scan reports: `owasp` on each finding in `--json`, the risk IDs among
  each rule's SARIF tags (so code scanning can filter on them), a line per
  finding in Markdown and HTML;
- the passport: `assessment.owasp` counts findings per risk, and the
  Markdown passport has a "Risks by OWASP category" line.

Like the crosswalk above, this is orientation: it says which risk a finding
belongs to, not that a project meets or fails either list. A rule with no
clear fit carries no risk. Five reliability rules are in that position:
`JH208`, `JH210`, `JH212`, `JH213` and `JH306`.

| OWASP risk | Rules |
|---|---|
| CD-SEC-01 Blind Trust | `JH131`, `JH416`, `JH501`, `JH502`, `JH504`, `JH505`, `JH701` |
| CD-SEC-02 Account Impersonation | `JH150` |
| CD-SEC-03 Authorization Misuse | `JH101`, `JH134`, `JH135`, `JH154`, `JH155`, `JH420`, `JH428`, `JH432` |
| CD-SEC-04 Sensitive Data Leakage and Handling Failures | `JH101`, `JH132`, `JH133`, `JH134`, `JH141`, `JH145`, `JH146`, `JH147`, `JH149`, `JH153`, `JH155`, `JH159`, `JH401`, `JH415`, `JH427`, `JH706` |
| CD-SEC-05 Authentication and Secure Communication Failures | `JH105`, `JH107`, `JH112`, `JH115`, `JH138`, `JH144`, `JH148`, `JH151`, `JH156`, `JH707` |
| CD-SEC-06 Vulnerable and Untrusted Components | `JH111`, `JH142`, `JH143`, `JH402`, `JH404`, `JH412`, `JH417`, `JH421`, `JH422`, `JH423`, `JH424`, `JH426`, `JH429`, `JH430`, `JH431`, `JH705` |
| CD-SEC-07 Security Misconfiguration | `JH108`, `JH109`, `JH110`, `JH116`, `JH121`, `JH122`, `JH130`, `JH136`, `JH137`, `JH152`, `JH204`, `JH403`, `JH405`, `JH406`, `JH407`, `JH408`, `JH409`, `JH410`, `JH411`, `JH414`, `JH425`, `JH702`, `JH703`, `JH704`, `JH709`, `JH710`, `JH711`, `JH712` |
| CD-SEC-08 Injection Handling Failures | `JH102`, `JH103`, `JH104`, `JH106`, `JH118`, `JH119`, `JH120`, `JH124`, `JH125`, `JH126`, `JH127`, `JH128`, `JH139`, `JH140`, `JH157`, `JH158`, `JH418`, `JH419`, `JH708` |
| CD-SEC-09 Asset Management Failures | none |
| CD-SEC-10 Security Logging and Monitoring Failures | `JH145`, `JH201`, `JH217` |
| ASI01 Agent Goal Hijack | `JH131`, `JH153`, `JH701`, `JH708` |
| ASI02 Tool Misuse and Exploitation | `JH153`, `JH158`, `JH702`, `JH703`, `JH709`, `JH712` |
| ASI03 Identity and Privilege Abuse | `JH148`, `JH150`, `JH432`, `JH706` |
| ASI04 Agentic Supply Chain Vulnerabilities | `JH705` |
| ASI05 Unexpected Code Execution (RCE) | `JH102`, `JH103`, `JH157`, `JH702`, `JH703`, `JH704`, `JH709`, `JH710`, `JH711`, `JH712` |
| ASI06 Memory & Context Poisoning | none |
| ASI07 Insecure Inter-Agent Communication | none |
| ASI08 Cascading Failures | none |
| ASI09 Human-Agent Trust Exploitation | none |
| ASI10 Rogue Agents | none |

The test suite checks this table against the rules.

## Limits

- The crosswalk maps evidence to outcomes it can inform. Most AI RMF
  outcomes (impact assessment, testing for bias or validity, incident
  response, stakeholder engagement) need evidence a repository cannot show.
- A recognized model service is matched by SDK or host. A self-hosted model
  or an unknown provider stays an ordinary external endpoint.
- AIGP domain names are paraphrased, and both frameworks change; the crosswalk
  names the versions it was written against.
