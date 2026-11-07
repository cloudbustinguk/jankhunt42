# The impact model

How jankhunt42 judges what software could hurt, and why it never turns that into a probability or a weighted sum.
This page covers the model as released (evidence tiers, the exposure class, the Agents Rule of Two in 4.16.0) and the
design adopted for the next releases (`jankhunt.impact.v2`), marked as planned.

## Three separate answers

| Answer | Scale | What it is built from |
|---|---|---|
| Jank Score ([scoring.md](scoring.md)) | 0 to 100, grades A to E | scanner findings: severity, confidence, density per thousand lines |
| Exposure class ([connectivity.md](connectivity.md)) | Low < Moderate < High < Critical (or Unknown) | what each principal can reach, and how strongly that is established |
| Passport decision ([passport.md](passport.md)) | pass, review, insufficient-evidence, block | named rules, each with its own evidence |

The three never offset each other: a clean Jank Score does not lower the exposure class, and neither is a release
decision. Only the Jank Score uses arithmetic, and only over counts of findings. Impact is ordinal: Critical is worse
than High, but not "twice" anything. Ordinal scales support comparison, maximum and minimum, and nothing else
(Dubois and Prade, possibility theory; Krisper, "Problems with Risk Matrices Using Ordinal Scales", 2021), so every
impact rule here is built from those operations alone.

## Evidence tiers and reach (released)

Every edge in the connectivity map carries an evidence tier:

    verified (3) > supported (2) > inferred (1) > unknown (0)

A path is as strong as its weakest edge, and a principal reaches an asset as strongly as its best path:

    reach(p, a) = max over paths π from p to a of ( min over edges e in π of tier(e) )

This is the max-min composition of possibility theory. It needs no probabilities, gives the same answer under any
relabelling of the tiers that keeps their order, and adding an edge or strengthening one can only raise a reach.

## The exposure class (released)

Each principal (a workload, a workflow, an identity, an agent) gets the highest class whose condition holds; the
application gets the highest class over its principals:

    class(app) = max over principals p of class(p)

| Class | Condition (any of) |
|---|---|
| Critical | verified write, delete or admin over a critical or restricted asset; verified export of sensitive data to an external destination |
| High | possible write, delete or admin over a production, high or critical, or sensitive asset; supported read of restricted data; a sensitive source and an external destination reachable from the same principal |
| Moderate | any possible reach to a non-local system whose capability or classification is not established |
| Low | only local assets reached, or nothing reached with coverage |

Every condition is upward-closed, so the class is monotone: adding authority, sensitivity, criticality, evidence or
reach never lowers it (tested exhaustively). The breadth indicator `1 + 0.5·(1 − e^(−(n−1)/4))` over distinct trust
domains is shown for context only and never changes the class.

## The Agents Rule of Two (released in 4.16.0)

Simon Willison's "lethal trifecta" (June 2025) and Meta's "Agents Rule of Two" (October 2025) describe one danger:
an AI agent that combines

- **[A] untrusted input:** text anyone can write reaches it (web pages, public chat, an open webhook, email, public
  issues);
- **[B] sensitive data:** it reaches private systems or data (a database, private repositories, a home folder, a
  mailbox);
- **[C] a way to act:** it can change state or communicate externally (writes, a shell, sending messages, opening
  pull requests, or fetching an address it chooses, since data can leave in the URL).

A prompt injection in [A] can make it read [B] and send or change it through [C]. Invariant Labs showed in May 2025
that a single GitHub MCP server can supply all three: an issue on a public repository steered an agent into copying a
private repository into a public pull request.

`JH714` reads each agent a repository configures (an MCP client configuration with the Claude Code or VS Code
settings beside it, or an n8n AI Agent node with its triggers and tools). Each part of the agent (a server, a tool, a
trigger, a built-in tool such as WebFetch) contributes to each property on a three-step scale:

    none < possible < yes

"possible" marks what the configuration cannot show, such as which repositories a GitHub token reaches. Then, per
agent:

    holds(k)  = max over parts of part[k]                for k in A, B, C
    all three = min(holds(A), holds(B), holds(C)) > none
    certain   = min(holds(A), holds(B), holds(C)) = yes

Supervision is judged where the harm happens, at [C]: the agent is **unsupervised** when some part that gives [C]
runs without a person approving it (bypass mode, a broad allow entry, an acting tool in autoApprove or alwaysAllow,
an n8n tool not behind a human review node). Denials win over pre-approvals, as in Claude Code.

| Verdict | Condition | Finding | P-AGT-002 |
|---|---|---|---|
| K3 | all three, unsupervised | critical (major when not certain) | the rule's action: review, block in the citizen profile |
| K4 | all three, every acting part approved | minor (info when not certain) | review at most; an uncertain K4 is left out |
| none | at least one property missing | nothing | pass |

The three must hold for the same agent: two agents that hold two properties each never add up to a finding. That is
the same anchoring the exposure class uses (per principal, then the maximum), and it avoids reporting a combination
no single agent has.

What a part contributes comes from a table of servers and tools built from each one's own documentation. A server
the table does not know counts for nothing and is named in the finding's `unknown_servers`. The table is the main
limit on recall: on public repositories that commit MCP configurations, most servers are still outside it.

## jankhunt.impact.v2 (adopted design, planned for 4.17.0)

v2 extends the exposure class with the same conjunctive structure the Rule of Two uses, so that combinations raise
the class, not only single conditions. Per principal it reads five ingredients, each as an evidence tier:

| Ingredient | Meaning |
|---|---|
| entry | who can start it, as a ladder: schedule < internal < signed-in < anyone; lowered only by explicit counter-evidence (an authentication setting, an IP allowlist), never by missing evidence |
| untrusted input | it reads text from outside |
| reach | its existing reach over assets, with their sensitivity, criticality and environment |
| way out | external communication, or a state change on a non-local asset |
| unsupervised | no approval stands before the step that acts |

Toxic combinations, each the minimum of its ingredients' tiers:

| Combination | Ingredients | Level |
|---|---|---|
| K1 open destruction | entry = anyone, write/delete/admin over a production, critical, restricted or confidential asset | Critical |
| K2 open sensitive read | entry = anyone, read of restricted or confidential data | High |
| K3 trifecta, unsupervised | untrusted input, sensitive reach, a way out, unsupervised | Critical |
| K4 trifecta, supervised | untrusted input, sensitive reach, a way out | High |

    sat_k(p)  = min over the ingredients of k of tier(ingredient, p)
    level(p)  = max( class_v1(p), max { level(k) : sat_k(p) > unknown } )
    level(app) = max over principals p of level(p)

Each driver of a level (a v1 condition or a combination) reports its own weakest tier, so a Critical that rests on an
unknown ingredient says so; the level's evidence is its best-supported driver. Properties:

- **Monotone:** every ingredient is upward-closed (entry is a ladder, so refining it needs counter-evidence) and only
  max and min combine them.
- **Ordinal:** only comparisons, max and min; any order-preserving relabelling of tiers gives the same result.
- **Conservative extension:** `level ≥ class_v1` for every principal, by construction (v1's conditions are kept as
  drivers).

**Remediation levers (planned for 4.18.0).** To bring the level down, remove one ingredient from every top-level
combination instance: a minimum hitting set, with adding an approval as a lever alongside removing an ingredient, and
a minimum edge cut where the ingredient is reach over several paths. Each lever shows the code behind it and the
level that remains after it, so a change that clears one combination but leaves another is visible.

## What this is not

- Not a probability of compromise, and not calibrated against incident data.
- Not a CVSS or AIVSS score. Their weighted sums add factors, so three strong factors score the same whether or not
  they complete a dangerous combination; jankhunt42 reports the combination itself. Its evidence for single factors
  (the tools an agent holds, its approvals, the credentials it acts with) can still inform such a score.
- Not proof of access: a combination built from inferred or possible evidence says what the configuration allows,
  not what any session did.

## Sources

- Simon Willison, "The lethal trifecta for AI agents: private data, untrusted content, and external communication",
  16 June 2025.
- Meta, "Agents Rule of Two: A Practical Approach to AI Agent Security", October 2025.
- Invariant Labs, "GitHub MCP Exploited: Accessing private repositories via MCP", 26 May 2025.
- D. Dubois and H. Prade, possibility theory and qualitative (max-min) decision.
- T. Krisper, "Problems with Risk Matrices Using Ordinal Scales", 2021.
- OWASP Artificial Intelligence Vulnerability Scoring System (AIVSS), v0.8.
