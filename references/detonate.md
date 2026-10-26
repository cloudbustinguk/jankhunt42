# detonate: run the install hooks in a sandbox

Static analysis says what code *could* do. `jankhunt42 detonate` runs a
repository's own install hooks in a disposable sandbox and reports what they
*try* to do: connect to the network, read credentials, start programs, or
change startup files. It is opt-in and never runs as part of `scan`, `map`
or `passport`.

```sh
podman build -t localhost/jankhunt42-detonate:0.1 -f templates/detonate.Containerfile templates   # once
jankhunt42 detonate .            # Markdown audit log
jankhunt42 detonate . --json     # schema jankhunt.detonate.v1
```

## What runs

- **npm:** the `preinstall`, `install`, `postinstall` and `prepare` scripts
  in `package.json`, as `npm run --if-present <hook>`.
- **Python:** `setup.py egg_info`, or, with only `pyproject.toml`, a wheel
  build with the backend already in the image.
- **Dependencies are not installed,** because the network is off. Their own
  install hooks therefore do not run, and coverage says so.

## The sandbox

- **The engine:** rootless podman, or docker, with the image named by
  `--image`. The image is never pulled, and jankhunt42 never builds a
  repository's own Dockerfile.
- **No network:** `--network=none`. Every connection attempt fails and is
  recorded. A DNS sink on the sandbox's own loopback logs each name looked
  up and answers that it does not exist.
- **Locked down:** a read-only root filesystem, every capability dropped,
  `no-new-privileges`, limits on processes, memory and CPU, and a time limit
  per hook.
- **A snapshot:** the repository is copied without `.git` and without
  following links, then mounted read-only and copied again to a scratch area
  inside the sandbox.
- **Canary credentials:** a throwaway, read-only home holds fresh, never
  issued AWS, GitHub, npm, SSH and `.env` values for each run. Each value
  carries a `JH42CANARY` marker.
- **Afterwards,** the sandbox, the snapshot and the canaries are deleted.
  Only the report is kept.

## The audit log

| Verdict | Means |
|---|---|
| **ALERT** `canary-read` | a hook read a canary credential file |
| **ALERT** `canary-passed` | a program was started with a canary value or canary file in its arguments |
| **ALERT** `canary-sent` | a canary value was written to a network socket or pipe |
| **ALERT** `persistence` | a write or rename into a shell startup file, an SSH `authorized_keys`, an autostart or user-service folder, or a cron path |
| **DENY** `network` | an attempted connection (host and port) |
| **DENY** `dns` | a name looked up |
| **INFO** | expected behaviour, such as npm reading its own `~/.npmrc` |

Each event names the command that caused it and the hook it ran under.
**Reports never contain canary values,** only canary IDs such as
`canary-aws`. Exit code 1 means at least one ALERT; 2 means the sandbox
could not run.

## Evidence and limits

The evidence tier is `sandbox-observed`. It adds to static findings and
never refutes them:
- A run that did not reach a path says nothing about that path.
- Only the hooks listed ran, and coverage is `partial` when dependencies
  were missing, a hook timed out, or a trace is missing.
- The tracer runs as the same user as the code it watches, so code written
  to evade tracing can hide.
- An encrypted or transformed canary is not recognised when sent.
- The network is off, so behaviour that depends on a server's reply is not
  reached.
