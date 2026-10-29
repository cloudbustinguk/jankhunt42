"""acquire: fetch pinned npm and Python artifacts from origins the operator approves. npm caches are built
offline in the sandbox; Python artifacts go straight into a verified wheelhouse for the sandbox.

No package manager and no package code touches the network. jankhunt42 itself downloads each artifact by the URL and
integrity hash the lockfile or requirements.txt records, and only when:
- the URL is HTTPS, has no credentials, and sits under an origin the operator approved (--origin);
- the host resolves to a global address, and the connection goes to that checked address (no rebinding);
- the server answers 200 without a redirect, within the size budget;
- the bytes match the lockfile's sha512 (npm) or sha256 (Python requirements).

The verified tarballs are then added to an npm cache by `npm cache add` inside the network-none sandbox. Nothing is
extracted or run on the host. What the lockfile pins is still the repository's choice: acquire proves the bytes are
the pinned ones from an approved origin, not that the packages are safe; the sandbox is how you find out what they do.
Python simple-API metadata goes through the same checked transport; no package manager runs on the host.
"""
from __future__ import annotations

import base64
import hashlib
import http.client
import io
import ipaddress
import json
import os
import shutil
import socket
import ssl
import stat
import subprocess
import tempfile
from typing import Any, Callable, Dict, Iterator, List, Optional, Tuple
from urllib.parse import urlsplit

import jh_ceiling
import jh_sandbox

SCHEMA = "jankhunt.acquire.v1"
MAX_LOCK_BYTES = 32 * 1024 * 1024
MAX_ARTIFACTS = 5000
MAX_ARTIFACT_BYTES = 128 * 1024 * 1024
MAX_TOTAL_BYTES = jh_sandbox.MAX_CACHE_BYTES
TIMEOUT = 60
READ_BYTES = 1 << 20                          # one read's worth of body
# the sandbox image is linux/x64: platform-specific optional packages for other systems are not needed offline
_PLATFORM = {"os": "linux", "cpu": "x64"}


class AcquireError(RuntimeError):
    pass


def _origin(url: str) -> Tuple[str, str, int, str]:
    u = urlsplit(url)                         # ValueError for a malformed URL or port: callers refuse it
    host = (u.hostname or "").lower()
    port = u.port or 443
    path = u.path if u.path.endswith("/") else u.path + "/"
    return u.scheme.lower(), host, port, path


def parse_origins(values: List[str]) -> List[Tuple[str, str, int, str]]:
    """Operator-approved origins: https URLs without credentials, query or fragment."""
    out = []
    for value in values:
        try:
            u = urlsplit(value)
            if u.scheme.lower() != "https" or not u.hostname or u.username or u.password or u.query or u.fragment:
                raise ValueError(value)
            out.append(_origin(value))
        except ValueError:
            raise AcquireError("--fetch must be an https URL without credentials, query or fragment: %s" % value)
    if not out:
        raise AcquireError("give at least one --fetch origin, for example --fetch https://registry.npmjs.org/")
    return out


def approved(url: str, origins: List[Tuple[str, str, int, str]]) -> bool:
    try:
        u = urlsplit(url)
        scheme, host, port, _ = _origin(url)
    except ValueError:
        return False                          # a malformed URL or port
    if u.scheme.lower() != "https" or not u.hostname or u.username or u.password or u.query or u.fragment:
        return False
    # the server resolves dot segments and encoded separators: a prefix match on the raw path would let
    # https://mirror/npm/../other/ out of an origin approved as https://mirror/npm/. An encoded percent sign
    # (%25) is refused too, for a server or proxy that decodes twice.
    low = u.path.lower()
    if "\\" in u.path or any(code in low for code in ("%2e", "%2f", "%5c", "%25")) or \
            any(seg in (".", "..") for seg in u.path.split("/")):
        return False
    return any(scheme == o[0] and host == o[1] and port == o[2] and (u.path or "/").startswith(o[3]) for o in origins)


def _platform_ok(entry: Dict[str, Any]) -> bool:
    for field, ours in _PLATFORM.items():
        allowed = entry.get(field)
        if isinstance(allowed, list) and allowed:
            negated = {a[1:] for a in allowed if isinstance(a, str) and a.startswith("!")}
            positive = {a for a in allowed if isinstance(a, str) and not a.startswith("!")}
            if ours in negated or (positive and ours not in positive):
                return False
    return True


def _sha512(integrity: Any) -> Optional[str]:
    """The sha512 digest from an SRI integrity string (several hashes may be listed); None without one."""
    if not isinstance(integrity, str):
        return None
    for part in integrity.split():
        if part.startswith("sha512-"):
            try:
                raw = base64.b64decode(part[7:], validate=True)
            except ValueError:
                return None
            return raw.hex() if len(raw) == 64 else None
    return None


def _read_lockfile(path: str, name: str) -> bytes:
    """One open that cannot be steered: no link is followed, it must be a regular file, and the size bound is
    enforced on the bytes read, not on an earlier look that the checkout could change before the read."""
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    except OSError as exc:
        raise AcquireError("%s cannot be opened without following a link: %s" % (name, exc.strerror or exc))
    with os.fdopen(fd, "rb") as fh:
        if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
            raise AcquireError("%s is not a regular file" % name)
        raw = fh.read(MAX_LOCK_BYTES + 1)
    if len(raw) > MAX_LOCK_BYTES:
        raise AcquireError("%s is larger than %d MB" % (name, MAX_LOCK_BYTES // (1024 * 1024)))
    return raw


def plan_npm(root: str) -> Dict[str, Any]:
    """What the npm lockfile pins: one artifact per registry tarball with a sha512 integrity. Everything that cannot
    be fetched that way (git, file and link sources, missing integrity, old lockfiles) is listed as refused."""
    lock = next((f for f in jh_sandbox.NPM_LOCKFILES if os.path.lexists(os.path.join(root, f))), None)
    if lock is None:
        raise AcquireError("no package-lock.json or npm-shrinkwrap.json")
    raw = _read_lockfile(os.path.join(root, lock), lock)
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=jh_ceiling._unique)
    except (UnicodeError, ValueError, RecursionError):
        raise AcquireError("%s is not valid, unambiguous JSON" % lock)
    packages = data.get("packages") if isinstance(data, dict) else None
    if not isinstance(packages, dict) or not isinstance(data.get("lockfileVersion"), int) or data["lockfileVersion"] < 2:
        raise AcquireError("%s is lockfileVersion 1; regenerate it with npm 7 or later" % lock)
    artifacts: Dict[Tuple[str, str], Dict[str, Any]] = {}
    refused: List[Dict[str, str]] = []
    skipped = 0
    for key, entry in sorted(packages.items()):
        if "node_modules/" not in key or not isinstance(entry, dict):
            continue                          # the root, or a workspace folder in the repository itself
        name = key.rsplit("node_modules/", 1)[-1]
        if entry.get("link") or entry.get("inBundle") or entry.get("bundled"):
            continue                          # a workspace link or a package inside its parent's tarball
        if not _platform_ok(entry):
            skipped += 1
            continue
        resolved, digest = entry.get("resolved"), _sha512(entry.get("integrity"))
        try:
            scheme = urlsplit(resolved).scheme.lower() if isinstance(resolved, str) else ""
        except ValueError:
            scheme = "malformed"
        if not isinstance(resolved, str) or not resolved:
            refused.append({"package": name, "reason": "no resolved URL (a git, file or missing source)"})
        elif scheme == "malformed":
            refused.append({"package": name, "reason": "a malformed resolved URL"})
        elif scheme != "https":
            refused.append({"package": name, "reason": "not an https URL (git, file or plain http)"})
        elif digest is None:
            refused.append({"package": name, "reason": "no sha512 integrity in the lockfile"})
        else:
            artifacts.setdefault((resolved, digest), {"ecosystem": "npm", "package": name,
                                                       "version": str(entry.get("version", "?")), "url": resolved,
                                                       "sha512": digest})
    pins: Dict[str, int] = {}
    for url, _digest in artifacts:
        pins[url] = pins.get(url, 0) + 1
    for (url, digest), artifact in list(artifacts.items()):
        if pins[url] > 1:                     # one URL pinned to different bytes: no pin can be trusted
            del artifacts[(url, digest)]
            refused.append({"package": artifact["package"], "reason": "the lockfile pins this URL to more than one hash"})
    if len(artifacts) > MAX_ARTIFACTS:
        raise AcquireError("the lockfile pins more than %d packages" % MAX_ARTIFACTS)
    return {"lockfile": lock, "lockfile_sha256": hashlib.sha256(raw).hexdigest(),
            "artifacts": sorted(artifacts.values(), key=lambda a: (a["package"], a["version"])),
            "refused": refused, "skipped_platform": skipped}


def check_address(ip: str) -> None:
    """Only a global address: never loopback, private, link-local, metadata or reserved ranges."""
    addr = ipaddress.ip_address(ip)
    if getattr(addr, "ipv4_mapped", None):
        addr = addr.ipv4_mapped
    if not addr.is_global or addr.is_multicast:
        raise AcquireError("refused: %s resolves to a non-public address" % ip)


def resolve(host: str, port: int) -> str:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError as exc:
        raise AcquireError("cannot resolve %s: %s" % (host, exc))
    for info in infos:
        ip = info[4][0]
        try:
            check_address(ip)
            return ip
        except AcquireError:
            continue
    raise AcquireError("refused: %s has no public address" % host)


class BudgetSpent(OSError):
    """The download's byte allowance is used up: nothing more is read from the connection."""


class _CountingRaw(io.RawIOBase):
    """The connection's unbuffered byte stream, counting every byte received and never reading past `limit`. Both
    sit below the buffered reader and the HTTP parser: a read that fails part-way cannot hide bytes it took, and
    headers, chunk framing and trailers share the payload's limit."""

    def __init__(self, raw: Any, limit: Optional[int] = None) -> None:
        super().__init__()
        self._raw, self.count, self.limit = raw, 0, limit

    def readable(self) -> bool:
        return True

    def readinto(self, buffer: Any) -> int:
        if self.limit is not None:
            room = self.limit - self.count
            if room <= 0:
                raise BudgetSpent("the download budget is spent")
            buffer = memoryview(buffer)[:room]
        n = self._raw.readinto(buffer) or 0
        self.count += n
        return n

    def close(self) -> None:
        try:
            self._raw.close()
        finally:
            super().close()


class _MeteredResponse(http.client.HTTPResponse):
    """An HTTPResponse that reads through _CountingRaw: `counter.count` is every byte this response received."""

    def __init__(self, sock: Any, *args: Any, limit: Optional[int] = None, **kwargs: Any) -> None:
        super().__init__(sock, *args, **kwargs)
        self.fp.close()                       # replaced before anything is read
        self.counter = _CountingRaw(sock.makefile("rb", buffering=0), limit)
        self.fp = io.BufferedReader(self.counter)


class _PinnedHTTPS(http.client.HTTPSConnection):
    """TLS to the hostname's certificate, over a connection to the address that was checked. Its response is metered
    from the moment it is made, so bytes taken while parsing headers count even when parsing fails."""

    def __init__(self, host: str, ip: str, port: int, timeout: float, limit: Optional[int] = None) -> None:
        super().__init__(host, port, timeout=timeout, context=ssl.create_default_context())
        self._ip, self.limit = ip, limit
        self.metered: Optional[_MeteredResponse] = None
        self.response_class = self._metered_response

    def _metered_response(self, sock: Any, *args: Any, **kwargs: Any) -> "_MeteredResponse":
        self.metered = _MeteredResponse(sock, *args, limit=self.limit, **kwargs)
        return self.metered

    def received(self) -> int:
        return self.metered.counter.count if self.metered is not None else 0

    def connect(self) -> None:
        sock = socket.create_connection((self._ip, self.port), self.timeout)
        self.sock = self._context.wrap_socket(sock, server_hostname=self.host)


def _stream(url: str, limit: int, usage: Dict[str, int], accept: str = "*/*") -> Iterator[bytes]:
    """The artifact's bytes. usage["received"] is kept current with every byte the connection has received (headers,
    framing and read-ahead included) before each yield and on every way out, so the budget can charge it all."""
    u = urlsplit(url)
    host, port = (u.hostname or "").lower(), u.port or 443
    conn = _PinnedHTTPS(host, resolve(host, port), port, TIMEOUT, limit)   # every byte received counts toward limit

    def record(resp: Any = None) -> None:
        counter = getattr(resp, "counter", None)
        received = counter.count if counter is not None else getattr(conn, "received", lambda: 0)()
        usage["received"] = max(usage.get("received", 0), received)

    resp = None
    # a malformed status line, header or chunk size can surface from the parser as a ValueError
    failures = (OSError, http.client.HTTPException, ValueError)
    try:
        conn.request("GET", u.path or "/", headers={"User-Agent": "jankhunt42-acquire", "Accept": accept})
        try:
            resp = conn.getresponse()
        except failures as exc:
            raise AcquireError("download failed: %s" % exc)
        record(resp)
        if resp.status != 200:
            raise AcquireError("HTTP %d%s" % (resp.status, " (redirects are refused)" if 300 <= resp.status < 400 else ""))
        length = resp.getheader("Content-Length")
        if length and length.isdigit() and int(length) > limit:
            raise AcquireError("larger than the size limit")
        while True:
            try:
                chunk = resp.read(READ_BYTES)
            except failures as exc:                   # IncompleteRead included
                raise AcquireError("the response was cut short" if isinstance(exc, http.client.IncompleteRead)
                                   else "download failed: %s" % exc)
            record(resp)
            if not chunk:
                return
            yield chunk
    finally:
        record(resp)                                  # every way out counts what arrived
        try:
            handed_off = getattr(conn, "metered", None) or resp
            if handed_off is not None:
                handed_off.close()                    # with Connection: close, the response owns the socket
        finally:
            conn.close()
            conn.__dict__.pop("response_class", None)     # break the cycle with its bound response factory


def fetch(artifact: Dict[str, Any], origins: List[Tuple[str, str, int, str]], dest: str, limit: int,
          stream: Callable[[str, int, Dict[str, int]], Iterator[bytes]] = _stream) -> Tuple[int, int]:
    """Download one artifact to dest, verifying its pinned hash as it arrives; nothing is kept unless it matches. Returns
    the bytes kept and the bytes received; a failure carries the bytes received as `received`. The budget charges
    bytes received, kept or not."""
    if not approved(artifact["url"], origins):
        raise AcquireError("refused: the URL is not under an approved origin")
    digest, size, usage = (hashlib.sha256() if "sha256" in artifact else hashlib.sha512()), 0, {"received": 0}
    part = dest + ".part"
    chunks = None
    try:
        chunks = stream(artifact["url"], limit, usage)
        with open(part, "wb") as out:
            for chunk in chunks:
                size += len(chunk)
                if size > limit:
                    raise AcquireError("larger than the size limit")
                digest.update(chunk)
                out.write(chunk)
        if "sha256" in artifact:
            if digest.hexdigest() != artifact["sha256"]:
                raise AcquireError("the bytes do not match requirements.txt's sha256")
        else:
            if digest.hexdigest() != artifact["sha512"]:
                raise AcquireError("the bytes do not match the lockfile's sha512")
        os.replace(part, dest)
    except (AcquireError, OSError, http.client.HTTPException, ValueError) as exc:
        close_stream(chunks)                      # the stream's own cleanup records its last bytes first
        err = exc if isinstance(exc, AcquireError) else AcquireError("download failed: %s" % exc)
        err.received = max(size, usage["received"])
        raise err
    finally:
        close_stream(chunks)                      # the connection closes now, not when collected
        if os.path.exists(part):
            os.remove(part)
    return size, max(size, usage["received"])


def close_stream(chunks: Any) -> None:
    close = getattr(chunks, "close", None)
    if close is not None:
        close()


def build_npm_cache(tarballs: str, cache: str, engine: str, image: str) -> None:
    """npm cache add on the verified tarballs, inside the network-none sandbox: npm reads them, nothing runs."""
    z = ",Z" if engine == "podman" else ""
    script = ('set -e; cd /in; ls | grep "\\.tgz$" | xargs -r -n 100 '
              'npm cache add --cache /cache --ignore-scripts --offline --no-audit --no-fund >/dev/null')
    user = [] if engine == "podman" else ["--user", "%d:%d" % (os.getuid(), os.getgid())]
    proc = subprocess.run([engine, "run", "--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                           "--security-opt=no-new-privileges", *jh_sandbox.LIMITS, *user,
                           "--tmpfs", "/tmp:rw,size=256m,mode=1777", "-e", "HOME=/tmp",
                           "-e", "npm_config_update_notifier=false",
                           "-v", "%s:/in:ro%s" % (tarballs, z), "-v", "%s:/cache:rw%s" % (cache, z),
                           image, "sh", "-c", script], capture_output=True, text=True, timeout=1800)
    _own(cache, engine)
    if proc.returncode != 0:
        raise AcquireError("npm cache add failed in the sandbox: %s" % (proc.stderr.strip().splitlines() or ["?"])[-1][:200])


def _own(path: str, engine: Optional[str]) -> None:
    """Files written in rootless podman belong to a mapped user; hand them back to the caller."""
    if engine == "podman" and os.path.exists(path):
        subprocess.run(["podman", "unshare", "chown", "-R", "0:0", path], capture_output=True, timeout=600)


def run(root: str, origins: List[str], out: str, image: str = jh_sandbox.DEFAULT_IMAGE,
        engine: Optional[str] = None, stream: Callable[[str, int, Dict[str, int]], Iterator[bytes]] = _stream,
        build: Callable[[str, str, str, str], None] = build_npm_cache,
        index_stream: Any = None) -> Dict[str, Any]:
    root = os.path.abspath(root)
    approved_origins = parse_origins(origins)
    if os.path.lexists(out) and (not os.path.isdir(out) or os.listdir(out)):
        raise AcquireError("the cache folder must be new or empty")
    if jh_ceiling.inside_repository(out, root):
        raise AcquireError("the cache folder must be outside the repository (set TMPDIR to a folder outside it)")
    import jh_pyfetch
    import jh_nuget
    dotnet_tree = jh_nuget.discover(root)
    nuget_plan = jh_nuget.plan(root, dotnet_tree) if any(dotnet_tree[k] for k in ("projects", "solutions", "locks")) else None
    python_plan = jh_pyfetch.plan_requirements(root) if os.path.lexists(os.path.join(root, "requirements.txt")) else None
    has_npm = any(os.path.lexists(os.path.join(root, f)) for f in jh_sandbox.NPM_LOCKFILES)
    needs_npm = has_npm or (python_plan is None and nuget_plan is None)
    plan = plan_npm(root) if needs_npm else dict(python_plan or nuget_plan, artifacts=[], refused=[])
    engine = jh_sandbox.find_engine(engine) if needs_npm else None
    if needs_npm and not engine:
        raise AcquireError("no container engine (podman or docker) is installed for the offline cache step")
    result: Dict[str, Any] = {"schema": SCHEMA, "ecosystem": "npm", "lockfile": plan["lockfile"],
                              "lockfile_sha256": plan["lockfile_sha256"],
                              "origins": ["%s://%s:%d%s" % o for o in approved_origins],
                              "fetched": [], "refused": list(plan["refused"]),
                              "skipped_platform": plan["skipped_platform"]}
    out = os.path.abspath(out)
    parent = os.path.dirname(out)
    os.makedirs(parent, exist_ok=True)
    stage = tempfile.mkdtemp(prefix=".jh-acquire-", dir=parent)
    try:
        tarballs = os.path.join(stage, "tarballs")
        cache = os.path.join(stage, "out", "npm")
        os.makedirs(tarballs)
        os.makedirs(cache)
        os.chmod(tarballs, 0o755)
        os.chmod(cache, 0o777)
        total = received = 0                  # bytes kept, and every byte downloaded: the budget counts both
        for i, artifact in enumerate(plan["artifacts"]):
            name = "%05d.tgz" % i                 # our own names: nothing from the lockfile becomes a path
            if received >= MAX_TOTAL_BYTES:
                result["refused"].append({"package": artifact["package"],
                                          "reason": "not fetched: the download budget is spent"})
                continue
            try:
                size, used = fetch(artifact, approved_origins, os.path.join(tarballs, name),
                                   min(MAX_ARTIFACT_BYTES, MAX_TOTAL_BYTES - received), stream)
            except AcquireError as exc:
                received += getattr(exc, "received", 0)
                result["refused"].append({"package": artifact["package"], "reason": str(exc)[:200]})
                continue
            os.chmod(os.path.join(tarballs, name), 0o644)
            received += used
            total += size
            result["fetched"].append({"package": artifact["package"], "version": artifact["version"],
                                      "sha512": artifact["sha512"], "bytes": size})
        if result["fetched"]:
            build(tarballs, cache, engine, image)
        python_result = None
        if python_plan is not None:
            python_result = jh_pyfetch.acquire(python_plan, approved_origins, os.path.join(stage, "out", "wheels"),
                                                MAX_TOTAL_BYTES - received, stream,
                                                index_stream or jh_pyfetch.json_stream)
            result["ecosystem"] = "npm+python" if has_npm else "python"
            result["lockfiles"] = [{"path": p["lockfile"], "sha256": p["lockfile_sha256"]}
                                   for p in ([plan] if has_npm else []) + [python_plan]]
            result["fetched"].extend(python_result["fetched"])
            result["refused"].extend(python_result["refused"])
            result["source_builds"] = [a["package"] for a in python_result["fetched"] if a["kind"] == "sdist"]
            received += python_result["downloaded"]
            total += python_result["bytes"]
        nuget_result = None
        if nuget_plan is not None:
            nuget_result = jh_nuget.acquire(nuget_plan, approved_origins, os.path.join(stage, "out", "nuget"),
                                            MAX_TOTAL_BYTES - received, stream)
            result["fetched"].extend(nuget_result["fetched"])
            result["refused"].extend(nuget_result["refused"])
            received += nuget_result["downloaded"]
            total += nuget_result["bytes"]
            result["ecosystem"] = "+".join(e for e, yes in (("npm", needs_npm), ("python", python_plan is not None),
                                                             ("nuget", True)) if yes)
            result["lockfiles"] = ([{"path": plan["lockfile"], "sha256": plan["lockfile_sha256"]}] if needs_npm else []) + \
                ([{"path": python_plan["lockfile"], "sha256": python_plan["lockfile_sha256"]}] if python_plan else []) + \
                nuget_plan["lockfiles"]
        receipt = os.path.join(stage, "out", "receipt.json")
        result["counts"] = {"pinned": len(plan["artifacts"]) + (python_result["pinned"] if python_result else 0) +
                                      (nuget_result["pinned"] if nuget_result else 0),
                            "fetched": len(result["fetched"]),
                            "refused": len(result["refused"]), "bytes": total, "downloaded": received}
        result["state"] = "complete" if not result["refused"] else "partial"
        with open(receipt, "w", encoding="utf-8") as fh:
            json.dump(result, fh, indent=2, sort_keys=True)
        if os.path.isdir(out):
            os.rmdir(out)                         # empty, checked above
        os.replace(os.path.join(stage, "out"), out)
    finally:
        _own(stage, engine)
        shutil.rmtree(stage, ignore_errors=True)
    result["cache"] = os.path.join(out, "npm") if needs_npm else None
    if python_plan is not None:
        result["wheelhouse"] = os.path.join(out, "wheels")
    if nuget_plan is not None:
        result["nuget_cache"] = os.path.join(out, "nuget")
    return result


def summary(r: Dict[str, Any]) -> Dict[str, Any]:
    """What sandbox --fetch reports about the fetch: the receipt without the cache path."""
    return {k: r[k] for k in ("state", "counts", "origins", "lockfile", "lockfile_sha256", "skipped_platform")} | \
        {k: r[k] for k in ("lockfiles", "source_builds") if k in r} | {"refused": r["refused"][:50]}
