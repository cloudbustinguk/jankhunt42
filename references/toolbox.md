# Toolbox: copy-paste commands

These are starting points, not a mandate. Prefer the project's native tools and
record the exact command, cwd, environment, and exit code.

**Safety:** commands marked **DESTRUCTIVE** or **PRIVILEGED** can delete data,
interrupt service, or change the host. Do not run them without explicit consent.
Most commands below are read-only.

## JankHunt42

```sh
SKILL_DIR=~/.config/opencode/skills/jankhunt42
JH="python3 $SKILL_DIR/scripts/jankhunt"

$JH scan .                              # TTY autopsy; Markdown when piped
$JH scan . --json > jank.json           # full machine-readable report
$JH scan . --sarif > jank.sarif         # SARIF 2.1.0
$JH scan . --html > jankhunt.html       # self-contained visual report
$JH scan . --since origin/main          # new-code view
$JH scan . --cve                        # OSV.dev advisories (network, opt-in)
$JH review .                            # working tree + untracked files
$JH review . --staged                   # index only
$JH review . --commit HEAD              # committed tree
$JH review . --base origin/main         # BASE...HEAD; scan HEAD tree
$JH review . --pr 123                   # checked-out GitHub PR
$JH review . --base origin/main --json > review.json
$JH review . --base origin/main --sarif > review.sarif
$JH review . --base origin/main --brief > review-brief.md
$JH review . --base origin/main \\
  --baseline .jankhunt/baseline.json --fail-on major
$JH review . --base origin/main --json --save-baseline .jankhunt/baseline.json
$JH supply-chain . --json
$JH supply-chain . --require-sbom --require-attestation
$JH supply-chain . --jfrog-evidence apptrust-evidence.json
$JH score .                             # dimension scorecard
$JH score . --json                      # score breakdown for CI
$JH triage app.log --top 25             # fingerprint and rank log clusters
$JH doctor --system                     # repo + host health
$JH report . --logs app.log --out report.md
$JH hunt . --focus security --json > hunt.json
$JH hunt . --md --prompts > hunt-brief.md
$JH merge panel-*.json --md
$JH rules --category security
```

`--html` is one portable file with embedded CSS/JS and no external assets. It
is mutually exclusive with `--md`, `--json`, and `--sarif`; `--max-findings`
caps the HTML view. Repository strings are escaped and secrets stay redacted.

`review` receipts are `supported` or `unverified`; they are never `confirmed`
without a repro or runtime evidence. `--fail-on` gates new supported findings
only; baseline persisting findings are excluded unless you change the baseline.
`supply-chain` is offline/read-only. `provider-verified` means the exporter
recorded a successful verification, not that JankHunt42 verified a signature.
Use `gh`, `cosign`, or `jf` for independent verification.

## Logs and evidence

```sh
# Capture, do not scroll.
./app > /tmp/app.out 2> /tmp/app.err; echo "exit=$?"
tail -n 200 /tmp/app.err
head -n 50 /tmp/app.err

# Time-bounded journal.
journalctl -u <service> --since "30 min ago" --no-pager
journalctl -u <service> --since "2026-01-01 10:00" --until "2026-01-01 10:15" -o short-iso

# Kernel and hardware.
dmesg -T | tail -n 100
dmesg -T | grep -iE 'oom|killed|error|fail|reset|timeout'

# JSONL logs: filter without jq if needed.
python3 - <<'PY'
import json
for line in open("app.jsonl"):
    try: row = json.loads(line)
    except ValueError: continue
    if row.get("level") in ("error", "fatal"):
        print(row.get("ts"), row.get("msg"), row.get("err"))
PY
```

## Processes and resources

```sh
ps -eo pid,ppid,stat,%cpu,%mem,rss,etime,wchan:32,cmd --sort=-%cpu | head -n 30
ps -eo pid,ppid,stat,wchan:32,cmd | grep -E '<name>|<pid>'
top -H -p <pid>
cat /proc/<pid>/status
cat /proc/<pid>/limits
ls -l /proc/<pid>/fd | tail -n 30
lsof -p <pid>
ss -tanp | grep <pid>
free -h
df -h
df -i
ulimit -a
```

**DESTRUCTIVE:** `kill -9 <pid>` can lose in-flight work. Prefer `SIGTERM`, then
inspect why it did not exit.

## CPU, memory, and syscalls

```sh
perf stat -p <pid> sleep 10
perf record -F 99 -g -p <pid> -- sleep 20
perf report --stdio

strace -f -tt -T -p <pid>
strace -f -e trace=network,file -o /tmp/trace.txt ./app
ltrace ./app

# Python
py-spy dump --pid <pid>
py-spy record -o /tmp/profile.svg --pid <pid>
python3 -X dev ./app
python3 -m tracemalloc

# JVM
jstack <pid>
jcmd <pid> GC.heap_info
jcmd <pid> GC.heap_dump /tmp/heap.hprof

# Go
go tool pprof http://localhost:6060/debug/pprof/profile
go tool pprof http://localhost:6060/debug/pprof/heap

# Node
node --inspect app.js
node --prof app.js && node --prof-process isolate-*.log
```

## Network and TLS

```sh
getent hosts <host>
dig +short <host>
dig +trace <host>
nc -vz -w 3 <host> <port>
curl -v --max-time 10 https://<host>/health
curl -vk --resolve <host>:443:<ip> https://<host>/health
openssl s_client -connect <host>:443 -servername <host> </dev/null
openssl x509 -in cert.pem -noout -dates -subject -issuer
ss -ltnp
ss -s
ip route
ip -6 route
```

Check proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`, `NO_PROXY`) and
the actual resolver in `/etc/resolv.conf` before blaming DNS.

## Git and change archaeology

```sh
git status --short
git log --oneline --decorate -n 30
git log -p -S '<symbol>' -- <path>
git log --since='2 weeks ago' --stat
git diff <good>..<bad> -- <path>
git bisect start
git bisect good <good>
git bisect bad <bad>
git bisect run ./bisect.sh
git blame -L <start>,<end> -- <path>
git show <commit> --stat
git tag --contains <commit>
```

Read the diff, not just the message. A revert that makes the symptom disappear is
a clue, not a root cause.

## Build and toolchains

```sh
which python3 node go java cargo rustc
python3 --version
node --version
npm --version
go version
java -version
cargo --version
env | sort
python3 -m pip freeze
npm ls --depth=0
go list -m all
cargo tree
mvn dependency:tree
gradle dependencies
```

**DESTRUCTIVE:** `git clean -xfd`, `rm -rf node_modules`, `cargo clean`, and
`docker system prune` delete local state. Do them in a throwaway clone or with
explicit consent.

## Tests

```sh
pytest -x -vv --tb=long
pytest -q tests/test_x.py::test_y --count=50
pytest -q -p no:randomly
go test -race -count=1 ./...
go test -run TestX -count=50 ./pkg
cargo test
cargo test -- --nocapture
npx vitest run --repeat 50
npm test -- --runInBand
```

For flaky tests: run alone, in reverse order, with one worker, with a fixed seed,
with a frozen clock, and with fresh fixtures. Compare the failure rate, not one run.

## Containers

```sh
docker ps --format 'table {{.ID}}\t{{.Image}}\t{{.Status}}\t{{.Names}}'
docker inspect <container>
docker logs --timestamps --tail 200 <container>
docker logs --since 30m <container>
docker stats --no-stream
docker exec -it <container> sh
docker run --rm -it <image> sh
docker image inspect <image> --format '{{.RepoDigests}}'
```

**DESTRUCTIVE:** `docker system prune`, `docker volume rm`, and `docker rm -f`
delete state. Confirm before running.

## Kubernetes

```sh
kubectl config current-context
kubectl get pods -A -o wide
kubectl get pod <pod> -o yaml
kubectl describe pod <pod>
kubectl logs <pod> --tail=200
kubectl logs <pod> --previous
kubectl get events --sort-by=.lastTimestamp
kubectl get deploy,rs,sts,ds -A
kubectl rollout status deploy/<name>
kubectl rollout history deploy/<name>
kubectl auth can-i --list
kubectl top pod
kubectl get --raw /readyz?verbose
```

**PRIVILEGED / DESTRUCTIVE:** `kubectl delete`, `kubectl drain`, `kubectl
rollout restart`, `kubectl exec` with writes, and `kubectl apply` change the
cluster. Do not run them without an owner and a rollback plan.

## Databases

```sh
# PostgreSQL
psql -c "select version();"
psql -c "select pid, state, wait_event_type, wait_event, now()-query_start as age, query from pg_stat_activity order by age desc limit 20;"
psql -c "select * from pg_locks where not granted;"
psql -c "explain (analyze, buffers) <query>;"

# MySQL / MariaDB
mysql -e "show processlist;"
mysql -e "show engine innodb status\G"
mysql -e "explain analyze <query>;"

# Redis
redis-cli info memory
redis-cli --latency
redis-cli slowlog get 20
```

**DESTRUCTIVE:** writes, migrations, `VACUUM FULL`, `FLUSHALL`, and failover
commands change state. Use a scratch replica or explicit consent.

## Security review

```sh
# Secrets in the working tree (read-only; confirm before rotating).
git grep -nE '(api[_-]?key|secret|token|password|passwd|private[_-]?key)' -- .
git log -p --all -- .env '*.pem' '*.key' | head -n 200

# Dependency audit (network; opt-in).
npm audit --json
pip-audit
govulncheck ./...
cargo audit

# Container/IaC scanning, if installed.
trivy fs .
trivy image <image>
semgrep --config auto .
kubeconform -strict manifests/
```

Do not paste secrets into a chat, issue, or report. Rotate first if a live secret
was exposed; then purge history and artifacts.

## CI/CD

```sh
# GitHub Actions: inspect the resolved workflow and run.
gh run list --limit 20
gh run view <run-id> --log
gh workflow view <workflow>
gh api repos/<owner>/<repo>/actions/runs/<run-id>/jobs

# GitLab CI
glab ci list
glab ci view <pipeline-id>
glab ci trace <job-id>
```

Check triggers, permissions, secrets, cache keys, artifacts, matrix, reusable
workflows, and expression interpolation. Treat PR-controlled text as hostile.

## System limits and host health

```sh
ulimit -a
cat /proc/sys/fs/file-max
cat /proc/sys/net/core/somaxconn
cat /proc/sys/vm/overcommit_memory
cat /proc/pressure/cpu /proc/pressure/memory /proc/pressure/io
systemctl --failed
systemctl status <unit> --no-pager
journalctl -k --since "1 hour ago" --no-pager
```

## Time and clocks

```sh
date -u
timedatectl
chronyc tracking
ntpq -p
zdump -v <Zone>/<City> | tail
```

Clock skew breaks TLS, JWT, TOTP, cache freshness, and distributed ordering.
Compare the failing host with a known-good host, not just your workstation.

## When a command is missing

Do not install tools without asking. Use the stdlib, the project's existing
toolchain, or a read-only alternative. Record the missing tool and the workaround
in the report.
