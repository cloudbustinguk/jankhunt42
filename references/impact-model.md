# The impact model

How jankhunt42 judges what software could hurt, and why it never turns that into a probability or a weighted sum.
This page covers the model as released (evidence tiers, the exposure class with its v2 combinations in 4.20.0, the
Agents Rule of Two in 4.16.0) and what is still planned.

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

```math
\text{verified}\ (3) > \text{supported}\ (2) > \text{inferred}\ (1) > \text{unknown}\ (0)
```

A path is as strong as its weakest edge, and a principal reaches an asset as strongly as its best path:

```math
\operatorname{reach}(p, a) = \max_{\text{paths } \pi \text{ from } p \text{ to } a} \Bigl( \min_{\text{edges } e \text{ in } \pi} \operatorname{tier}(e) \Bigr)
```

This is the max-min composition of possibility theory. It needs no probabilities, gives the same answer under any
relabelling of the tiers that keeps their order, and adding an edge or strengthening one can only raise a reach.

## The exposure class (released)

Each principal (a workload, a workflow, an identity, an agent) gets the highest class whose condition holds; the
application gets the highest class over its principals:

```math
\operatorname{class}(\text{app}) = \max_{\text{principals } p} \operatorname{class}(p)
```

| Class | Condition (any of) |
|---|---|
| Critical | verified write, delete or admin over a critical or restricted asset; verified export of sensitive data to an external destination |
| High | possible write, delete or admin over a production, high or critical, or sensitive asset; supported read of restricted data; a sensitive source and an external destination reachable from the same principal |
| Moderate | any possible reach to a non-local system whose capability or classification is not established |
| Low | only local assets reached, or nothing reached with coverage |

Every condition is upward-closed, so the class is monotone: adding authority, sensitivity, criticality, evidence or
reach never lowers it (tested exhaustively). The breadth indicator $`1 + 0.5 \cdot \left(1 - e^{-(n-1)/4}\right)`$
over distinct trust domains is shown for context only and never changes the class.

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

```math
\text{none} < \text{possible} < \text{yes}
```

"possible" marks what the configuration cannot show, such as which repositories a GitHub token reaches. Then, per
agent:

```math
\begin{aligned}
\operatorname{holds}(k) &= \max_{\text{parts}} \mathrm{part}[k] && \text{for } k \in \{A, B, C\}
\\ \text{all three} &= \min\bigl(\operatorname{holds}(A), \operatorname{holds}(B), \operatorname{holds}(C)\bigr) > \text{none}
\\ \text{certain} &= \min\bigl(\operatorname{holds}(A), \operatorname{holds}(B), \operatorname{holds}(C)\bigr) = \text{yes}
\end{aligned}
```

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

Two boundaries are deliberate. A fixed address (an HTTP tool whose URL is written into the workflow) is treated
like an internal service: its owner writes it, not anyone, so it is neither untrusted input nor a way out. And
`JH714` reads the agents an MCP configuration or an n8n workflow defines; Claude Code's own tools (WebFetch, the
shell) count alongside an MCP configuration, while a project whose settings bypass approvals with no MCP
configuration is `JH703`'s finding. `bypassPermissions` in project settings is honoured only by older Claude Code
versions, so a K3 that rests on it alone is major, not critical.

What a part contributes comes from a table of servers and tools built from each one's own documentation. A server
the table does not know counts for nothing and is named in the finding's `unknown_servers`. The table is the main
limit on recall: on public repositories that commit MCP configurations, most servers are still outside it.

## jankhunt.exposure.v2 (released in 4.20.0)

v2 extends the exposure class with the same conjunctive structure the Rule of Two uses, so that a combination raises
the class, not only a single condition. The map's model id is `jankhunt.exposure.v2`. Per principal it reads these
ingredients, each with an evidence tier:

| Ingredient | Meaning | Where it comes from in 4.20.0 |
|---|---|---|
| entry | who can start it, as a ladder: schedule < internal < signed-in < anyone | n8n triggers: an open webhook or form, a public chat with no authentication, and mail or Telegram triggers are *anyone*; authentication or an IP allowlist is *signed-in* (a step after the trigger never lowers it: seeming to check a header proves no rejection); a chat that is not public, editor and workflow triggers are *internal*; timers are *schedule*. Each node takes the most open trigger that reaches it along the workflow's connections; a disabled node is not credited and passes data on from its first output only, as n8n does, and when several exports declare the same node the most open entry counts. A principal no known trigger reaches has no entry: unknown is evidence neither way |
| reach | its existing reach over assets, with their sensitivity, criticality and environment | the map, as in v1 |
| untrusted input, sensitive data, a way to act, unsupervised | the Agents Rule of Two | `JH714`'s verdict for MCP agents and n8n AI Agent nodes, judged with the settings files the map collected; an open trigger followed by a step that seems to check a header is possible untrusted input, never none |

An n8n trigger is a declaration in the export, so entry rests on the *supported* tier; whether the workflow is active
on a server is not known.

Toxic combinations, each the minimum of its ingredients' tiers:

| Combination | Ingredients | Level |
|---|---|---|
| K1 open destruction | entry = anyone, and write, delete or admin over a production, high- or critical-criticality, confidential or restricted asset | Critical |
| K2 open sensitive read | entry = anyone, and read of confidential or restricted data | High |
| K3 trifecta, unsupervised | an agent's Rule of Two verdict K3 (supported when certain, inferred when part is possible) | Critical |
| K4 trifecta, supervised | an agent's Rule of Two verdict K4, certain only (an uncertain K4 is information only) | High |

```math
\begin{aligned}
\operatorname{sat}_k(p) &= \min_{\text{ingredients of } k} \operatorname{tier}(\text{ingredient}, p)
\\ \operatorname{level}(p) &= \max\Bigl( \operatorname{class}_{\mathrm{v1}}(p),\ \max\{\, \operatorname{level}(k) : \operatorname{sat}_k(p) > \text{unknown} \,\} \Bigr)
\\ \operatorname{level}(\text{app}) &= \max_{\text{principals } p} \operatorname{level}(p)
\end{aligned}
```

Each driver of a level reports its own weakest tier, and each combination also lists its ingredients, so a
Critical that rests on inferred evidence says so. Two principals never combine: open entry on one and sensitive
authority on another is not K1. An asset whose sensitivity, criticality and environment are not known never
satisfies K1 or K2: the v1 conditions already treat it as at least Moderate, and a combination is claimed only on
evidence. Properties, each
tested:

- **Monotone:** every ingredient is upward-closed (a more open entry, a stronger tier, more authority, more
  sensitivity) and only max and min combine them. Entry is lowered only by counter-evidence in the export itself.
- **Ordinal:** only comparisons, max and min; any order-preserving relabelling of tiers gives the same result.
- **Conservative extension:** $`\operatorname{level} \ge \operatorname{class}_{\mathrm{v1}}`$ for every principal, by
  construction (v1's conditions stay drivers).

**Policy.** The passport's `P-EXP-001` compares this class with `max_exposure`. The citizen profile's maximum is
Moderate, so there a K1, K2, K3 or certain K4 blocks through `P-EXP-001`, including a K4, for which `P-AGT-002`
alone asks for review at most. The standard profile sets no maximum, so `P-EXP-001` does not act there, but
`P-OWN-001` asks for an owner from High up in every profile: a repository with no owner whose class a combination
raises to High or Critical moves from pass to review.

**Considered and not adopted.**

- *A one-step uplift from AIVSS's agentic amplification factors.* For an agent that already holds the three parts,
  the factors are almost always present: the way to act is the tool-control factor, an unsupervised step is the
  autonomy factor, and every language-model agent has a natural-language interface. The uplift would turn every K4
  into a Critical and erase the difference between supervised and unsupervised that the Rule of Two exists to make.
- *A per-finding business-impact factor in the Jank Score.* The score is computed from findings and never sees the
  map, so a finding cannot be tied to the data its code reaches without new plumbing; and on public repositories a
  declared confidential or restricted asset is rare. The Jank Score and the exposure class stay separate answers.

**Still planned.** Entry for other platforms (Power Automate HTTP triggers, Copilot Studio agents without
authentication, anonymous web routes). Remediation levers: to bring the level down, remove one ingredient from every
top-level combination instance (a minimum hitting set, with adding an approval as a lever alongside removing an
ingredient, and a minimum edge cut where the ingredient is reach over several paths); each lever shows the code
behind it and the level that remains after it.

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
