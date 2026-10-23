# The method: evidence-driven debugging

This is the long-form doctrine behind `SKILL.md`. Read it when the bug is
expensive, ambiguous, intermittent, or politically charged. The short version is
simple: **find the causal chain, prove each arrow, then change the smallest thing
that breaks it.**

## 1. The evidence ladder

Not all evidence is equal. Label every claim with the strongest rung it actually
reaches.

| Level | Evidence | What it can support |
|---|---|---|
| E0 | Intuition, pattern match, "looks wrong" | A hypothesis only. Never a root cause. |
| E1 | Code reading, static trace, configuration diff | A plausible mechanism and the next check. |
| E2 | Logs, metrics, traces, error messages, git history | Correlation and timing. Still not causation. |
| E3 | Controlled runtime observation: debugger, profiler, `strace`, targeted probe | A mechanism observed in the running system. |
| E4 | Minimal reproduction with a known-good control | A causal claim strong enough to fix. |
| E5 | Fix removes the cause; original repro passes; regression test fails before and passes after | A verified fix. |

If a claim is E0 or E1, say `HYPOTHESIS`. If it is E2, say `CORRELATED`. Do not
dress a correlation as a cause because the story sounds good.

## 2. Intake template

Write this before touching code. Keep it in the report or issue.

```text
Symptom:        expected vs actual, one sentence
First seen:     timestamp / release / commit / deploy
Frequency:      always / intermittent (x of y) / one host / one user
Repro:          exact command, cwd, input, environment, versions
Last known good: commit / image / config / dependency version
Blast radius:   one function / one service / all users / data at risk
Constraints:    no restart, no data loss, maintenance window, compliance
Unknowns:       what we cannot observe yet
```

If the user is present, ask only questions that change the next action. If not,
write assumptions explicitly:

```text
ASSUMPTION: the failing job runs the image tagged :latest, not the SHA in the repo.
```

## 3. The hypothesis ledger

Keep a table. It prevents circular reasoning and makes handoffs useful.

| ID | Hypothesis | Prediction if true | Cheapest test | Result | Status |
|---|---|---|---|---|---|
| H1 | Connection pool exhausted by retry storm | Pool wait time rises before latency; active connections hit max | Export pool metrics for the incident window | wait time flat, connections at 40% | rejected |
| H2 | DNS resolver rotates to a dead server | Failures correlate with resolver IP; `dig` against that IP fails | Query each resolver directly | one resolver times out | supported |
| H3 | New deploy changed the timeout from 30s to 3s | Config diff shows the change; reverting restores behavior | Diff config between revisions | no diff | rejected |

Rules:

- One hypothesis per row. "It's the network" is not a hypothesis.
- Every hypothesis needs a prediction that could be false.
- Run the cheapest test that separates two live hypotheses, not the most
  satisfying one.
- Record rejections. They are the map of what you do not need to revisit.

## 4. Differential diagnosis

Compare a working case with a broken case. The difference is the suspect set.

- **Code:** diff the working and failing revisions. Read the diff, not just the
  commit message.
- **Dependencies:** compare lockfiles, resolved versions, native extensions, and
  transitive packages.
- **Environment:** interpreter, venv, `node_modules`, container image, kernel,
  libc, locale, time zone, ulimits, cgroup limits, proxy, DNS.
- **Data:** shape, size, encoding, nulls, duplicates, ordering, permissions,
  tenant, feature flags.
- **Infrastructure:** instance type, zone, network policy, load balancer, cert,
  clock, storage class, quota.
- **Time:** deploy window, traffic pattern, cron, certificate expiry, token
  lifetime, daylight saving, leap second.

If the bug is "only on one machine", the environment is part of the bug. If it is
"only for one user", the data or permissions are part of the bug.

## 5. Bisection

Bisection is not only for git. Bisect any ordered space:

- **Commits:** `git bisect start`, mark good/bad, automate with a script that
  returns 0/1. Keep the bisect script deterministic.
- **Dependencies:** pin versions or use a lockfile bisect. Change one package at a
  time.
- **Configuration:** start from the working config and add suspect keys until it
  breaks.
- **Input:** shrink the payload while preserving failure. Delete halves, then
  lines, then fields.
- **Code path:** disable one feature flag or middleware at a time.
- **Infrastructure:** compare one replica, one zone, one node pool.

Stop when the remaining interval is small enough to read. A bisect that lands on a
merge commit still needs a causal explanation.

## 6. Intermittent and probabilistic bugs

One green run proves nothing. Measure.

- Run a stress loop and record pass/fail counts, not impressions:
  ```sh
  for i in $(seq 1 100); do
    ./run-case >/tmp/out.$i 2>&1 && echo pass >> /tmp/results || echo fail >> /tmp/results
  done
  sort /tmp/results | uniq -c
  ```
- Add timestamps, request IDs, thread IDs, and tenant IDs to the relevant path.
- Increase scheduling pressure deliberately: `GOMAXPROCS`, thread count, parallel
  test workers, artificial latency, CPU contention.
- Use deterministic seeds and a fake clock where possible.
- Check for shared state: global caches, singletons, connection pools, temp file
  names, environment mutation, static mutable objects.
- Look for timeouts and retries that turn a slow dependency into a failure storm.
- If the failure rate changes after a code change, that is a clue, not proof.
  Compare rates with a confidence interval or at least a larger sample.

## 7. Causal chains and falsification

Write the chain explicitly:

```text
trigger -> mechanism -> symptom
```

Example:

```text
retry policy has no jitter
  -> all clients retry at the same 1s boundary
  -> connection pool saturates
  -> healthy requests queue behind retries
  -> p99 latency crosses the load balancer timeout
  -> 504s, which trigger more retries
```

For every arrow, ask:

- What observation would be different if this arrow were false?
- Is there a guard, cache, retry, or framework behavior that breaks the chain?
- Does the timing match? A cause must precede the symptom.
- Does the magnitude match? A 2% CPU rise rarely explains a 10x latency drop.
- Is there a simpler chain with fewer unproven arrows?

A root cause that cannot be falsified is a belief, not a diagnosis.

## 8. Instrumentation discipline

Instrument narrowly, then remove the instrumentation.

- Prefer existing telemetry before adding logs.
- Log at boundaries: input, output, state transition, external call, error path.
- Include correlation IDs and durations, not just "here".
- Never log secrets, tokens, passwords, full credit-card numbers, or personal data.
- Use sampling for high-volume paths.
- For native code, use sanitizers before guessing. For managed runtimes, use the
  profiler and heap dump before adding counters.
- Keep a copy of the raw evidence (log file, trace, profile) outside the repo.

Instrumentation changes behavior. If adding a log line makes the bug disappear,
that is a timing clue, not a fix.

## 9. Fix discipline

- Fix the cause, not the symptom. A retry around a deterministic bug hides it.
- Make the smallest correct change that matches local style.
- Check sibling call sites: the same bug usually has relatives.
- Preserve error semantics. Do not convert a loud failure into a silent one.
- Do not weaken validation, TLS, authorization, assertions, or tests to make the
  symptom go away.
- Consider rollback and mixed-version behavior. A fix that breaks old clients is
  not a fix.
- Add a regression test that fails against the old code. If that is impractical,
  document the exact repro and the manual check.

## 10. Verification

A fix is not done until all of these are true:

1. The original repro passes end to end.
2. The regression test fails before the fix and passes after it.
3. The targeted test suite passes.
4. The full suite, build, typecheck, and lint pass (or the pre-existing failures
   are documented).
5. The failure path is tested, not only the happy path.
6. Performance and resource use are not worse in a way that matters.
7. No debug artifacts, temporary flags, or secrets remain.
8. The causal explanation still matches the evidence after the fix.

## 11. Stop conditions

Stop and escalate when:

- The next experiment needs access you do not have.
- The next experiment risks data, production, or another team's system.
- Two hypotheses remain and the discriminating test is too expensive; report both.
- The evidence points outside the repo (platform, network, vendor, hardware).
- The fix requires a product decision, not a code change.
- You have spent the timebox without narrowing the suspect set.

Escalation report:

```text
Proven:
Ruled out:
Best current hypothesis:
Cheapest next experiment:
Access/artifact needed:
Risk if we wait:
```

## 12. Reporting and privacy

Use `templates/report.md`. The report should be readable by someone who was not in
the debugging session.

- Lead with impact and status, not the journey.
- Show the causal chain and the evidence for each arrow.
- Include the repro command and the verification command.
- Separate confirmed facts, supported inferences, and open questions.
- Record what was ruled out; it prevents repeat work.
- Redact secrets, tokens, personal data, customer names, and internal URLs that
  should not be published.
- Do not paste raw prompts or private conversation text into a public report.

## 13. When to switch to a deep hunt

Use the single-agent method for most bugs. Switch to the opt-in deep hunt
(`references/deep-hunt.md`) when independent adversarial review is worth the cost:

- A security-sensitive change or a suspected exploitable defect.
- A release gate or a migration with irreversible risk.
- A bug that has survived two normal debugging attempts.
- A postmortem where the team disagrees on the cause.
- A codebase or dependency you do not trust yet.

A deep hunt does not replace this method. It multiplies it: independent
investigators, a devil's advocate, cross-examination, and an evidence-weighted
consensus board.
