# Domain playbooks

Start with the symptom, not the stack. Each playbook gives the first moves, the
evidence to capture, common causes, and the experiment that usually separates
them. Commands are examples; adapt them to the project and keep them read-only
until you have consent.

## Crash / process exits

**First moves**

1. Capture the full stderr, stdout, exit code, and signal:
   ```sh
   set +e
   ./app > /tmp/app.out 2> /tmp/app.err
   rc=$?
   echo "exit=$rc"
   tail -n 100 /tmp/app.err
   ```
2. Find the first cause, not the last symptom. In a Java/Python/Node stack trace,
   read the innermost frame in your code and the first `Caused by`.
3. Check for an OOM kill, signal, or supervisor restart:
   ```sh
   dmesg -T | tail -n 50
   journalctl -u <service> --since "30 min ago" --no-pager
   ```
4. Reproduce with the same binary/image, interpreter, environment, and input.

**Common causes:** null/undefined, unhandled exception, missing file or permission,
OOM, stack overflow, ABI mismatch, missing native library, bad config, exit code
from a child process, signal from a supervisor.

**Discriminating experiments:** run under a debugger; set `ulimit -c unlimited`
and inspect the core; run with sanitizers; compare the exact artifact hash between
working and failing hosts.

## Wrong result / data corruption

**First moves**

1. Write the smallest input with a known correct output.
2. Compare the working and failing path at the boundary: input parsing, units,
   encoding, rounding, time zone, ordering, null handling.
3. Check the data, not only the code: duplicates, stale rows, partial writes,
   schema drift, migration state.
4. Add a temporary assertion at the boundary and remove it afterwards.

**Common causes:** off-by-one, integer overflow/underflow, float rounding, locale
or collation, timezone/DST, encoding, null vs empty vs missing, stale cache,
eventual consistency, non-idempotent retry, lost update, race.

**Discriminating experiments:** freeze time and seed; run with a single worker;
replay the same request twice; compare a read from the primary and a replica;
diff the serialized payload before and after the boundary.

## Hang / no progress

**First moves**

1. Identify whether it is CPU-bound, I/O-bound, blocked on a lock, or waiting on a
   child process.
2. Capture stacks of the live process:
   ```sh
   ps -eo pid,ppid,stat,wchan:32,cmd | grep -E '<name>|<pid>'
   cat /proc/<pid>/stack 2>/dev/null
   py-spy dump --pid <pid>          # Python, if installed
   jstack <pid>                     # JVM
   gdb -p <pid> -batch -ex 'thread apply all bt'
   ```
3. Check file descriptors, sockets, locks, and child processes:
   ```sh
   ls -l /proc/<pid>/fd | tail
   ss -tanp | grep <pid>
   lsof -p <pid>
   ```
4. Look for a timeout that is longer than the observer's patience, or a retry loop
   with no backoff.

**Common causes:** deadlock, lock convoy, connection pool exhaustion, DNS hang,
blocking call in an async event loop, unbounded queue, waiting on a child that
never exits, filesystem stall, NFS, swap thrash.

**Discriminating experiments:** send `SIGQUIT` (JVM) or dump stacks twice 10s
apart; compare lock ownership; run with one worker; strace the syscall that never
returns; test the dependency directly with a short timeout.

## Performance regression

**First moves**

1. Define the metric and the workload: p50/p95/p99 latency, throughput, CPU, memory,
   allocations, queries per request.
2. Measure before changing anything. Capture a baseline on the same hardware and
   dataset.
3. Profile, do not guess:
   ```sh
   perf record -F 99 -g -- ./app
   perf report --stdio
   py-spy record -o profile.svg --pid <pid>
   node --prof app.js && node --prof-process isolate-*.log
   go tool pprof http://localhost:6060/debug/pprof/profile
   ```
4. Compare the slow and fast traces. Find the first divergence, not the biggest
   number in the flame graph.

**Common causes:** N+1 queries, missing index, repeated parsing, accidental
quadratic loop, lock contention, cache stampede, excessive logging, JSON
serialization of large objects, cold cache, noisy neighbor, GC pressure.

**Discriminating experiments:** reduce the dataset; disable one stage; add a
counter at the suspected boundary; compare query plans; run with the cache warm
and cold; pin CPU and repeat.

## Memory growth / leak

**First moves**

1. Distinguish a leak from a cache that is supposed to grow. Measure RSS and heap
   over time under a steady workload.
2. Capture a heap profile or dump:
   ```sh
   python -m tracemalloc                 # in-process, or use memray
   jcmd <pid> GC.heap_dump /tmp/heap.hprof
   go tool pprof http://localhost:6060/debug/pprof/heap
   ```
3. Look for unbounded maps, caches, queues, listeners, timers, and retained
   closures.
4. Check native memory separately from managed heap (buffers, JNI, mmap).

**Common causes:** unbounded cache, event listener leak, global list, retained
request context, thread-local growth, connection leak, native buffer leak, huge
object graph, string interning.

**Discriminating experiments:** force GC and re-measure; cap the cache and observe;
take two heap snapshots and diff the retained set; run a long soak with a fixed
input.

## Concurrency / race

**First moves**

1. Identify the shared state and the synchronization that is supposed to protect it.
2. Run with race detection:
   ```sh
   go test -race -count=1 ./...
   cargo test
   TSAN_OPTIONS=halt_on_error=1 ./app
   ```
3. Increase interleavings: more workers, random delays, `GOMAXPROCS`, parallel test
   workers, CPU contention.
4. Look for lost updates, check-then-act, double-checked locking, lock ordering,
   and `await` inside a critical section.

**Common causes:** unprotected shared mutable state, non-atomic read-modify-write,
lock inversion, missing `await`, callback after cancellation, double delivery,
retry without idempotency, thread-unsafe library, shared connection.

**Discriminating experiments:** serialize the operation and see if the bug
disappears; add a deterministic barrier at the suspect point; run the same test
with one worker and many; inspect the lock graph.

## Network / timeout / TLS

**First moves**

1. Capture the exact error, destination, port, and timing.
2. Test each layer separately: DNS, TCP, TLS, proxy, HTTP, application.
   ```sh
   getent hosts <host>
   dig +short <host>
   nc -vz -w 3 <host> <port>
   curl -v --max-time 10 https://<host>/health
   openssl s_client -connect <host>:443 -servername <host> </dev/null
   ```
3. Compare from the failing host, not only from your workstation.
4. Check certificate expiry, clock skew, proxy env vars, and egress policy.

**Common causes:** DNS, firewall/security group, proxy, cert chain, SNI, clock
skew, MTU, connection pool, keep-alive mismatch, IPv6 preference, retry storm,
upstream timeout shorter than the client timeout.

**Discriminating experiments:** curl the IP directly with a Host header; bypass
the proxy; test IPv4 vs IPv6; compare `date -u` on both hosts; trace with
`strace -f -e trace=network`.

## Data / database

**First moves**

1. Capture the query, plan, bind values, and isolation level.
2. Check for locks, long transactions, replication lag, and connection saturation.
3. Compare the schema and migration state across environments.
4. Test idempotency by replaying the same write twice.

**Common causes:** missing index, bad statistics, lock contention, deadlock,
long transaction, N+1, unbounded result set, schema drift, nullable surprise,
collation, timezone, lost update, non-idempotent consumer, partial write.

**Discriminating experiments:** `EXPLAIN (ANALYZE, BUFFERS)` before and after;
query `pg_stat_activity`/`SHOW PROCESSLIST`; run the write twice; read from primary
and replica; restore a backup into a scratch database and replay.

## Build / tooling

**First moves**

1. Capture the full command, environment, tool versions, and the first error.
2. Verify the toolchain is the one you think it is:
   ```sh
   which python3 node go java cargo
   python3 --version
   node --version
   go version
   java -version
   env | sort
   ```
3. Clean only the suspect artifact, not the world. Compare a clean checkout.
4. Check lockfile drift, peer dependencies, native toolchain, and generated code.

**Common causes:** wrong interpreter/venv, stale `node_modules`, missing system
library, PATH shadowing, lockfile mismatch, cache corruption, case-sensitive
filesystem, line endings, generated file out of date, disk full.

**Discriminating experiments:** build in a fresh container; `git clean -xfd` in a
throwaway clone; run the failing command with `bash -x`; compare `env` between
working and failing shells.

## Tests / flaky suite

**First moves**

1. Reproduce the failure in isolation, then in the full suite.
2. Run the same test repeatedly and record the failure rate:
   ```sh
   pytest -q tests/test_x.py::test_y --count=50    # pytest-repeat
   go test -run TestX -count=50 ./pkg
   npx vitest run tests/x.test.ts --repeat 50
   ```
3. Look for shared state: database rows, temp files, ports, environment, global
   caches, time, randomness, ordering, network.
4. Check the test's assumptions, not only the code under test.

**Common causes:** order dependence, shared fixture, fixed port, sleep-based
synchronization, real clock, real network, leaked process, unclosed handle,
parallel isolation, non-deterministic iteration, timezone.

**Discriminating experiments:** run alone; run in reverse order; run with one
worker; freeze time; randomize order with a seed; inspect leftover state after the
test.

## CI/CD pipeline

**First moves**

1. Read the workflow as code: triggers, permissions, secrets, matrix, cache,
   artifacts, and reusable workflows.
2. Compare the failing job's image, runner, env, and checkout with the local
   reproduction.
3. Check whether the failure is in the code, the pipeline, or the infrastructure.
4. Reproduce with the same container image and command.

**Common causes:** unpinned action/image, mutable cache, missing secret, permission
scope, runner image drift, network egress, matrix gap, shell quoting, expression
injection, `continue-on-error`, stale artifact, concurrent deploy.

**Discriminating experiments:** rerun with `--debug`/verbose; run the same command
in the job's container locally; disable cache; pin the image digest; compare the
resolved workflow with the repository file.

## Containers / Kubernetes

**First moves**

1. Get the pod state, events, and previous logs:
   ```sh
   kubectl get pod <pod> -o yaml
   kubectl describe pod <pod>
   kubectl logs <pod> --previous
   kubectl get events --sort-by=.lastTimestamp
   ```
2. Check resources, probes, security context, service account, network policy,
   and volume mounts.
3. Reproduce the container locally with the same image and env.
4. Distinguish scheduling, image pull, startup, readiness, runtime, and dependency
   failures.

**Common causes:** OOMKilled, evicted, image pull secret, readiness probe too
strict, liveness probe killing a slow start, missing config/secret, service
account permission, network policy, PVC, node pressure, deprecated API.

**Discriminating experiments:** `kubectl exec` and test the dependency; run the
image with `docker run --rm -it`; compare a working pod's spec; check
`kubectl get --raw` for API discovery; inspect the admission controller.

## Security review

**First moves**

1. Map trust boundaries: user, tenant, PR, webhook, dependency, network, admin.
2. Trace untrusted input to sinks: SQL, shell, template, deserialization, file
   path, HTTP client, HTML, expression evaluator.
3. Check authentication and object-level authorization separately.
4. Look for secrets in code, history, artifacts, logs, and CI output.
5. Verify the exploit preconditions before calling something critical.

**Common causes:** concatenated SQL/shell, missing object-level authz, JWT
verification disabled, permissive CORS, debug mode, unsafe deserialization,
path traversal, SSRF, weak crypto, hardcoded secret, overbroad CI token,
`pull_request_target` checkout, privileged container, wildcard IAM.

**Discriminating experiments:** write a harmless proof of concept against a local
instance; add a test that asserts the guard; inspect the framework's actual
default; verify the reachable route with a request, not a grep.

## Incident / production

**First moves**

1. Stabilize first: stop the bleeding, preserve evidence, communicate.
2. Establish the timeline in UTC. Separate detection, start, peak, mitigation,
   recovery.
3. Capture logs, metrics, traces, config, and deploy state before they rotate.
4. Find the last known good and the first bad.
5. Do not run destructive remediation without an owner and a rollback plan.

**Common causes:** recent deploy, config change, dependency outage, certificate
expiry, capacity, data corruption, credential rotation, network policy, human
error.

**Discriminating experiments:** compare canary vs stable; roll back one change;
shift traffic; disable one feature flag; test the dependency from inside the
network.

## Legacy / unknown codebase

**First moves**

1. Map the entry points, data stores, external calls, and deploy path.
2. Run the existing tests and build before changing anything.
3. Use `jankhunt42 scan`, `scan --score`, `doctor`, and `triage` for a fast inventory.
   The scorecard tells you which dimension to inspect first; it is not a verdict.
4. Read the code path end to end for the specific symptom; do not audit the whole
   repo.
5. Write characterization tests around the behavior you are about to touch.

**Common causes:** hidden coupling, generated code, dead code that is still
reachable, undocumented config, multiple sources of truth, stale vendored code.

**Discriminating experiments:** add a temporary boundary log; run one request with
a debugger; compare the running artifact with the repo; search for the config key
in every environment.

## Language quick hits

| Stack | High-value tools | Common trap |
|---|---|---|
| Python | `python -X dev`, `pytest -x -vv --tb=long`, Ruff, mypy, `py-spy`, `tracemalloc`, `faulthandler` | venv/interpreter mismatch, mutable default, blocking call in async |
| JS/TS | `tsc --noEmit`, ESLint, Vitest/Jest, `node --inspect`, `--trace-warnings` | stale `node_modules`, unhandled promise, `this` binding |
| Go | `go vet`, `go test -race -count=1`, pprof, `GOTRACEBACK=all` | goroutine leak, loop variable capture, context cancellation |
| Rust | `cargo clippy`, `cargo test`, `RUST_BACKTRACE=full`, Miri | borrow/lifetime workaround hiding a logic bug, panic in Drop |
| JVM | `jstack`, heap dump, async-profiler, `-XX:+HeapDumpOnOutOfMemoryError` | GC pressure, thread pool starvation, classpath conflict |
| C/C++ | ASan/UBSan/TSan, Valgrind, gdb/lldb, `-Wall -Wextra` | UB, use-after-free, ABI mismatch |
| Shell | `shellcheck`, `bash -x`, `set -euo pipefail` | unquoted expansion, ignored exit code, `cd` failure |
| SQL | `EXPLAIN (ANALYZE, BUFFERS)`, lock views, `pg_stat_activity` | N+1, missing index, long transaction |
