# detonate: run what a repository runs, in a sandbox

Static analysis says what code *could* do. `jankhunt42 detonate` runs the
commands a repository runs by itself, both when it is installed and when it
is opened, in a disposable sandbox. It reports what they *try* to do:
connect to the network, read credentials, start programs, or change startup
files. It is opt-in and never runs as part of `scan`, `map` or `passport`.

```sh
podman build -t localhost/jankhunt42-detonate:0.1 -f templates/detonate.Containerfile templates   # once
jankhunt42 detonate .                   # Markdown audit log
jankhunt42 detonate . --json            # schema jankhunt.detonate.v1
jankhunt42 detonate . --surface open    # only what runs when the repository is opened
```

## What runs when it is installed (`--surface install`)

- **npm:** the `preinstall`, `install`, `postinstall` and `prepare` scripts
  in `package.json`, as `npm run --if-present <hook>`.
- **Python:** `setup.py egg_info`, or, with only `pyproject.toml`, a wheel
  build with the backend already in the image.
- **Dependencies are installed only from a cache you supply,** because the
  network is off. Without one, their install hooks do not run, and coverage
  says so. See "Dependencies" below.

## What runs when it is opened (`--surface open`)

Opening a repository in an agent or an editor can run commands once the
folder is trusted (VS Code also asks before it runs automatic tasks).
detonate runs each of them once:

- **Agent hooks and helpers:** command hooks in `.claude/settings.json`,
  `.claude/settings.local.json` and `.gemini/settings.json`. Each hook gets
  a synthetic event on standard input, and nothing from a real session. The
  helper commands (`apiKeyHelper`, `statusLine` and the AWS and telemetry
  helpers) also run. URL hooks send data, so they are left to `scan`.
- **Dev container commands:** `initializeCommand` and the `onCreate`,
  `updateContent`, `postCreate`, `postStart` and `postAttach` commands, in
  string, list or named form. The report marks `initializeCommand`, because
  in real use it runs on the host machine, outside any container.
- **VS Code tasks** that run on folder open (`runOptions.runOn:
  folderOpen`), written the way VS Code writes them for a POSIX shell. An
  argument is quoted only when it has an unquoted space, so `$VAR` and
  `$(...)` stay live, as they are in the editor; an escaped space (`\ `) is
  left alone, and strong quoting wraps the value as VS Code does.
  `${workspaceFolder}` becomes the repository.

  **Dependencies:** the tasks a folder-open task `dependsOn` run first, in
  order, and the report marks each one. Dependencies VS Code would run in
  parallel run one after another here, and coverage says so.

  **Not applied:** shell, environment and working-folder options (for one
  task or for the whole file), other `${...}` variables, an old-format file
  with a global command, and a dependency that is not defined in the file.
  Each is a coverage gap.
- **MCP stdio servers** from the project's MCP configuration files. Each
  gets one `initialize` request and is stopped after 20 seconds, because a
  server runs until it is stopped. Its configured environment is not
  applied, and coverage says so.

These files are read only at their usual places in the repository and never
through a link: a repository's `.claude` could point at your own settings.
Every command is written to its own file and run by `sh` under the tracer,
so text from the repository never becomes part of the runner. In the
report, commands are shown redacted and cut to one line.

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
  inside the sandbox. What runs is planned from the snapshot, so it is
  exactly what was read.
- **Canary credentials:** a throwaway, read-only home holds fresh, never
  issued AWS, GitHub, npm, SSH and `.env` values for each run. Each value
  carries a `JH42CANARY` marker.
- **Afterwards,** the sandbox, the snapshot and the canaries are deleted.
  Only the report is kept.
- **Untrusted output:** the sandbox's output folder is writable by the code
  under test, so everything in it is read as untrusted:
  - through the folder's descriptor, never through a link;
  - regular files with a single link only;
  - traces capped at 64 MB, and the DNS log at 1 MB;
  - an exit status must be a plain number, and every DNS line a host name;
  - a step counts as observed only if its trace shows the step starting.

  Anything else makes coverage partial.

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

Each event names the command that caused it and the step it ran under.
**Reports never contain canary values,** only canary IDs such as
`canary-aws`. Exit code 1 means at least one ALERT; 2 means the sandbox
could not run.

## Dependencies (`--npm-cache`, `--wheelhouse`)

Most install-time attacks hide in a dependency's install hook, not in the
repository itself. To run those hooks too, supply the dependencies as a
cache made outside the repository. detonate never fetches anything itself.

```sh
jankhunt42 detonate . --npm-cache /path/outside/npm-cache
jankhunt42 detonate . --wheelhouse /path/outside/wheelhouse
```

**npm:** with a cache and a `package-lock.json` (or `npm-shrinkwrap.json`),
detonate runs one traced step:

    npm ci --offline --cache /cache/npm --foreground-scripts --ignore-scripts=false \
           --include=dev --include=optional --include=peer

Those command-line settings override the repository's own `.npmrc`. A
repository cannot switch scripts off, or leave its dev dependencies, and
their hooks, out of the install.

- **Which hooks run:** the package's own hooks and those of every
  dependency npm installs (dev, optional and peer included) run inside it,
  once, in place of the separate root-hook steps.
- **When something is missing:** a package missing from the cache, a git or
  URL dependency, or a missing lockfile makes coverage partial.

**Python:** with a wheelhouse, `requirements.txt` installs offline into the
sandbox (`python3 -I -m pip install --no-index --find-links`), and a
pyproject's build backend comes from the wheelhouse. The `-I` keeps a
`pip.py` in the repository from standing in for pip. A wheel runs no code when installed. Only
source packages in the wheelhouse are built, so only their setup code runs.

**The copy:** each cache must be a real directory outside the repository,
with no link in its path. detonate copies it into the run's private
folder, so your directory is never written to or relabeled. The copy can't
be steered while it runs:
- every folder is opened from its parent, and never through a link;
- every file is opened without following links, and must be a regular file;
- the 768 MB limit counts the bytes actually copied.

Links, FIFOs and devices are left out. An unreadable cache, or a temporary
folder inside the cache, stops the run.

**Making a cache is a fetch, and it can run code.** The repository's
lockfile and requirements decide what is downloaded, and from where. Some
downloads also run package code on the machine doing them:
- **pip:** a requirements file can switch a package to source
  (`--no-binary :all:`), even against `--only-binary` on the command line,
  and building a source package's metadata runs its setup code;
- **npm:** a git dependency is packed by running its own scripts.

So treat making a cache like running the repository:
1. **Check the sources first,** for example with
   `jankhunt42 passport . --policy POLICY` and `allowed_registries`. That
   tells you where packages come from, not that fetching them is safe.
2. **Fetch in a disposable environment:** a throwaway container or VM with
   no credentials, whose network reaches only your registry or proxy, and
   never your workstation. Copy only the resulting cache out.
3. **Fetch from a list you control:** a normalized, hash-locked list of
   exact wheels, not the repository's own requirements file:

```sh
# inside the disposable environment
npm ci --ignore-scripts --cache /cache/npm                # in a clean checkout of the repository
pip download --only-binary=:all: --no-deps --require-hashes -d /cache/wheels -r /reviewed/wheels.lock
```

A cache made this way is the one input detonate trusts you for. It still
never fetches anything itself.

## Use it in a passport

A run can become passport evidence. Save the result outside the repository,
then pass it to `passport`:

```sh
jankhunt42 detonate . --json > /path/outside/run.json
jankhunt42 passport . --detonation /path/outside/run.json --md
```

**When it counts:** every result records a digest of the tree it ran on:
each file's content, whether it is executable (as git records it), and
each link's target, without `.git`. The passport compares that digest
with the tree it assesses:
- **The same tree:** the run counts, and the passport shows a "Sandbox run"
  section with its ALERTs.
- **Any other tree:** if a file changed since the run, or the run was on
  another checkout, it is shown as not used and changes nothing.

With `--base`, the assessed tree is the committed `HEAD`. Its digest comes
from the commit's own objects, so run detonate on a clean checkout of that
commit. A tree, or a commit, that cannot be read in full matches no run.
Results made before 3.6.1 use an older digest and must be re-run.

**What it can change:** sandbox evidence can only add an outcome.
- An ALERT makes `P-RUN-001` review (block in the citizen profile), as a
  hard floor.
- A clean run passes `P-RUN-001` but never relieves any other rule, and
  adds no assurance about paths it did not reach.

**The file itself:** it must be a regular file outside the repository, of
at most 4 MB, with no links, read like the other operator inputs.
`--redact` removes alert details.

## Evidence and limits

The evidence tier is `sandbox-observed`. It adds to static findings and
never refutes them:
- A run that did not reach a path says nothing about that path.
- Only the commands listed ran. Coverage is `partial` when dependencies were
  missing, a command timed out, a trace is missing, or a hook needed more
  than a synthetic event.
- The tracer runs as the same user as the code it watches, so code written
  to evade tracing can hide, and it can alter its own trace and DNS log.
- An encrypted or transformed canary is not recognised when sent.
- The network is off, so behaviour that depends on a server's reply is not
  reached.
