# sandbox: run what a repository runs, and watch what it tries

Static analysis says what code *could* do. `jankhunt42 sandbox` runs the
commands a repository runs by itself, when it is installed, when its
dependencies are loaded, and when it is opened, in a disposable sandbox. It reports what they *try* to do:
connect to the network, read credentials, start programs, or change startup
files. It is opt-in and never runs as part of `scan`, `map` or `passport`.

```sh
podman build -t localhost/jankhunt42-sandbox:0.1 -f templates/sandbox.Containerfile templates   # once
jankhunt42 sandbox .                   # Markdown audit log
jankhunt42 sandbox . --json            # schema jankhunt.sandbox.v1
jankhunt42 sandbox . --surface open    # only what runs when the repository is opened
jankhunt42 sandbox . --surface import --fetch https://registry.npmjs.org/   # install, then load each dependency
```

## What runs when it is installed (`--surface install`)

- **npm:** the `preinstall`, `install`, `postinstall` and `prepare` scripts
  in `package.json`, as `npm run --if-present <hook>`.
- **Python:** `setup.py egg_info`, or, with only `pyproject.toml`, a wheel
  build with the backend already in the image.
- **Dependencies are installed only from a cache you supply,** because the
  network is off. Without one, their install hooks do not run, and coverage
  says so. See "Dependencies" below.

## What runs when its dependencies are loaded (`--surface import`)

A package can wait until it is loaded: code at the top of its `index.js`
or `__init__.py` runs when the application first imports it, with no
install hook at all. After the install step, the sandbox loads each direct
dependency once, as the application would, and logs what it tries under
that dependency's own step:

- **npm:** every package in `dependencies`, `optionalDependencies` and
  `devDependencies`, loaded with Node's `import()` from the repository, so
  CommonJS and ES modules both load. Type packages (`@types/...`) hold no
  code and are skipped.
- **Python:** every named requirement in `requirements.txt`. A small
  loader shipped with jankhunt42 finds the modules the distribution
  installed (from its `top_level.txt` or `RECORD`) and imports each.
- **Only what was installed loads,** so this needs the dependencies on
  disk (`--fetch` or `--npm-cache` with a lockfile, or `--wheelhouse`).
  Without them, coverage says the dependencies were not loaded.
  `--surface import` runs the install steps first.
- After each load the sandbox waits two seconds, so a timer or thread the
  package deferred runs where it is seen, even one that would let the
  process exit first. Installed `.pth` files, which a real install runs at
  every Python start, run once in a step of their own.
- Each load has 20 seconds, and at most 40 dependencies load. A package
  that is a command-line tool, or fails to load, is marked in the report;
  what it tried before that is still logged.
- Package names reach the runner only as quoted arguments, and only when
  they are valid package names; anything else is a coverage gap.

## What runs when it is opened (`--surface open`)

Opening a repository in an agent or an editor can run commands once the
folder is trusted (VS Code also asks before it runs automatic tasks).
the sandbox runs each of them once:

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
  issued AWS, GitHub (Git credentials and the GitHub CLI), npm, SSH, Docker,
  Kubernetes, PyPI and `.env` values for each run. Each value
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

## Dependencies (`--fetch`, `--npm-cache`, `--wheelhouse`, `--nuget-cache`)

Most install-time attacks hide in a dependency's install hook, not in the
repository itself. To run those hooks too, the sandbox needs the
dependencies on disk. `--fetch` gets npm lockfile packages and hash-pinned
Python requirements for you; or you supply a cache.

```sh
jankhunt42 sandbox . --fetch https://registry.npmjs.org/    # fetch the pinned npm packages, verified
jankhunt42 sandbox . --fetch https://pypi.org/ --fetch https://files.pythonhosted.org/  # Python
jankhunt42 sandbox . --npm-cache /path/outside/npm-cache     # or bring your own cache
jankhunt42 sandbox . --wheelhouse /path/outside/wheelhouse   # Python
```

### Fetching npm dependencies (`--fetch`)

`--fetch URL` is the only sandbox option that uses the network, and only to
download from the origins you name. The usual way to fetch dependencies,
`npm install`, runs the package manager online, and it can run package code
while it fetches. `--fetch` never does:

1. **It reads the lockfile.** One artifact per pinned package: the tarball
   URL and its `sha512` integrity, from `package-lock.json` or
   `npm-shrinkwrap.json` (lockfile version 2 or later).
2. **jankhunt42 downloads each one itself,** and only when:
   - the URL is HTTPS, under an origin you named with `--fetch`, with no
     credentials, query, dot segments or encoded separators;
   - the host resolves to a public address. Private, loopback,
     link-local, cloud-metadata and reserved ranges are refused. The
     connection goes to the address that was checked, so a DNS rebind
     cannot redirect it;
   - the server answers `200`. Redirects are refused;
   - the size is under 128 MB per package and 768 MB in total. Every byte
     received counts, headers and framing included, and a download stops
     the moment it reaches the limit;
   - the bytes match the lockfile's `sha512`. Anything else is deleted.
3. **The cache is built offline.** `npm cache add` runs on the verified
   tarballs inside this same sandbox, with no network. npm only reads the
   tarballs; no script runs.
4. **The cache lives only for this run,** in a private folder that is
   deleted afterwards. The result's `fetch` section records the lockfile's
   `sha256`, the origins, the counts and every refused package.

**What `--fetch` does not do:**
- **Judge the packages.** The lockfile is the repository's choice, so a
  malicious package it pins is fetched faithfully. `--fetch` proves the
  bytes are the pinned ones, from an origin you approved; the run shows
  what they do.
- **Fetch git, file, link or plain-http dependencies,** any without a
  `sha512` integrity, or a URL the lockfile pins to two different hashes. Each one is listed as refused, and coverage is
  partial.
- **Fetch packages for other platforms.** The sandbox is linux/x64.
- **Use a proxy or a registry login** (not yet). Use a public registry, or
  a mirror that needs no credentials.
### Fetching Python dependencies (`--fetch`)

The Python path reads `requirements.txt` itself. It never invokes pip or
opens downloaded archives on the host. Each requirement must be
`name==version` with one or more `--hash=sha256:<64 hex digits>` options.
Comments, backslash continuations and `--require-hashes` are supported.
URLs, paths, editable installs, includes, constraints, unhashed or unpinned
entries, markers, extras and other pip options are refused with a reason;
refusals make the run's coverage partial.

For each normalized name, it requests `/simple/<name>/` using the
[PEP 691 JSON simple API](https://packaging.python.org/en/latest/specifications/simple-repository-api/).
An approved URL ending in `/simple/` is used directly as the API base;
otherwise `simple/` is appended. Index metadata and downloads share the
npm path's origin, public-address and wire-byte limits; each index also
has a 32 MB limit. If npm and Python are both present, their downloads
share one 768 MB allowance.

Only files matching the pinned name, exact version and sha256 are chosen.
Pinned wheels take priority. All matching wheels from the first index
with pinned wheels are fetched, so the sandbox's pip can choose its own
compatible tags without assuming the host's interpreter matches it.
Only when no queried index lists a pinned wheel is one pinned source
archive chosen. A failed or unapproved wheel download does not authorize
falling back to a source build. Source archives are marked `kind: sdist`
and `build_runs_code: true` in the receipt, and listed in the result's
`fetch.source_builds`: their build code runs inside the sandbox.

The bytes are sha256-verified before they enter a wheelhouse, mounted
read-only at `/cache/wheels` for this run and deleted afterwards. PyPI
hosts its files on `files.pythonhosted.org`, so approve both origins as
shown above; approving the index never implicitly approves its file host.
No transitive or build dependency is fetched unless it has its own pin.
An incompatible wheel or a missing build backend can still make the
offline install fail; the fetch receipt establishes byte identity, not
installability. `--fetch` cannot combine with a supplied `--npm-cache` or
`--wheelhouse`.

### Using a cache

**npm:** with a cache and a `package-lock.json` (or `npm-shrinkwrap.json`),
the sandbox runs one traced step:

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
with no link in its path. The sandbox copies it into the run's private
folder, so your directory is never written to or relabeled. The copy can't
be steered while it runs:
- every folder is opened from its parent, and never through a link;
- every file is opened without following links, and must be a regular file;
- the 768 MB limit counts the bytes actually copied.

Links, FIFOs and devices are left out. An unreadable cache, or a temporary
folder inside the cache, stops the run.

**Making a cache by hand is a fetch that can run code.** A pip
requirements file can switch a package to a source build (even against
`--only-binary`), and building a source package's metadata runs its setup
code. An npm git dependency is packed by running its own scripts. If you
make a cache by hand, as you must for Python today:
- do it in a disposable environment with no credentials, whose network
  reaches only your registry;
- fetch from a hash-locked list you control, not the repository's own
  requirements file:

```sh
pip download --only-binary=:all: --no-deps --require-hashes -d /cache/wheels -r /reviewed/wheels.lock
```

## Use it in a passport

A run can become passport evidence. Save the result outside the repository,
then pass it to `passport`:

```sh
jankhunt42 sandbox . --json > /path/outside/run.json
jankhunt42 passport . --sandbox-run /path/outside/run.json --md
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
from the commit's own objects, so run the sandbox on a clean checkout of that
commit. A tree, or a commit, that cannot be read in full matches no run.
Results made before 3.6.1 use an older digest and must be re-run.

**Declared versus attempted:** the passport also compares every
destination the run tried to reach (each DNS name it looked up, each
address it connected to) with what is declared. That means:
- the hosts in the repository's own map, and
- the operator's network ceiling, when `--sandbox-network-ceiling` is
  given (exact hosts and ports).

A connection must match the port too, whenever the declaration names one;
the ceiling always does. DNS carries no port, so a name matches by host
alone. Every attempt is compared, however many there are; the passport
lists the first 100 and counts the rest. An attempt to reach
anything else is behaviour the repository does not admit to:
`P-RUN-002` asks for review (block in the citizen profile). The passport
lists those destinations, and `--redact` replaces their names.

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


## .NET and NuGet

For a .NET repository, `sandbox` selects `localhost/jankhunt42-sandbox-dotnet:0.1`
when that image exists. Build it once from the trusted template:

```sh
podman build -t localhost/jankhunt42-sandbox-dotnet:0.1 -f templates/sandbox-dotnet.Containerfile templates
jankhunt42 sandbox . --fetch https://api.nuget.org/ --json
jankhunt42 sandbox . --nuget-cache /path/outside/nuget-feed --json
```

The SDK image uses .NET 10 and also contains Python, the distribution's Node/npm,
strace, curl and wget. Non-.NET repositories continue to use the normal runner.
If the SDK is unavailable, .NET restore/build is skipped and coverage is partial.

NuGet acquisition reads each project's default `packages.lock.json` (format 1 or 2).
It requires a literal, unconditional `RestoreLockedMode=true` in the project or
nearest `Directory.Build.props`/`Directory.Build.targets`; missing locks, conditional
settings, custom imports and custom lock paths are refused with reasons. Project
references are skipped; direct and transitive packages across target frameworks
are deduplicated by normalized id/version. Conflicting hashes are refused.
Discovery is bounded to 100 projects and 20,000 entries, excludes build/cache
folders, and does not follow links. No MSBuild evaluation happens on the host.

The flat-container path is constructed beneath an explicitly approved origin:
`v3-flatcontainer/<lower-id>/<normalized-lower-version>/<id>.<version>.nupkg`.
Downloads use the existing checked HTTPS transport, public-address restrictions
and wire-byte caps. npm, Python metadata/wheels and NuGet share one allowance.
The archive's sha512 must match the lock's base64 `contentHash`. No downloaded
archive is opened on the host. Packages are kept in a hierarchical folder feed
for this run, avoiding ambiguous flat filenames.

With `--nuget-cache` or a fetched feed, each discovered C# project (or a solution
when no project is discoverable) gets traced install steps: `dotnet restore
--locked-mode --source /cache/nuget`, followed by `dotnet build --no-restore`.
The source feed is read-only, restored packages live in `/work`, and network
access remains disabled. Build/restore failures make coverage partial.
SDK telemetry is disabled. The canary home remains read-only except for an
empty, ephemeral `.dotnet` tmpfs required by .NET's named mutexes; credential
files stay read-only. SDK cache/state also uses `/tmp` and `/work`.

Pins establish byte identity, not package safety or a build's success. SDKs,
workloads and platforms missing from this image are not fetched during the run.
