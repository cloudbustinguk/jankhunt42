"""detonate --fetch (jh_acquire): planning, origin and address checks, verified downloads and publishing, on invented
lockfiles with a fake network; one opt-in live run against the public npm registry."""
import base64
import gc
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import subprocess
import tempfile
import unittest
import weakref
from unittest import mock

import _util  # noqa: F401
import jh_acquire as A
import jh_detonate


def sri(data):
    return "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()


TARBALL = b"invented tarball bytes"


class Base(unittest.TestCase):
    def tree(self, files=None):
        root = tempfile.mkdtemp(prefix="jh-acq-")
        self.addCleanup(shutil.rmtree, root, True)
        for rel, text in (files or {}).items():
            path = os.path.join(root, rel)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as fh:
                fh.write(text if isinstance(text, str) else json.dumps(text))
        return root

    def lock(self, packages, version=3):
        return {"name": "app", "version": "1.0.0", "lockfileVersion": version, "requires": True,
                "packages": dict({"": {"name": "app", "version": "1.0.0"}}, **packages)}


class Planning(Base):
    def test_what_the_lockfile_pins_and_what_it_cannot(self):
        root = self.tree({"package-lock.json": self.lock({
            "node_modules/ok": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz",
                                "integrity": sri(TARBALL)},
            "node_modules/@s/scoped": {"version": "2.0.0", "integrity": "sha1-abc= " + sri(b"x"),
                                       "resolved": "https://registry.npmjs.org/@s/scoped/-/scoped-2.0.0.tgz"},
            "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+ssh://git@example.invalid/x.git#abc"},
            "node_modules/weak": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/weak/-/weak-1.0.0.tgz",
                                  "integrity": "sha1-AAAA"},
            "node_modules/nosrc": {"version": "1.0.0"},
            "node_modules/mac-only": {"version": "1.0.0", "os": ["darwin"], "optional": True,
                                      "resolved": "https://registry.npmjs.org/m/-/m-1.0.0.tgz", "integrity": sri(b"m")},
            "packages/ws": {"version": "1.0.0"}, "node_modules/ws": {"link": True, "resolved": "packages/ws"},
            "node_modules/ok/node_modules/inner": {"inBundle": True, "version": "1.0.0"}})})
        plan = A.plan_npm(root)
        self.assertEqual([a["package"] for a in plan["artifacts"]], ["@s/scoped", "ok"])
        self.assertEqual(sorted(r["package"] for r in plan["refused"]), ["gitdep", "nosrc", "weak"])
        self.assertEqual(plan["skipped_platform"], 1)

    def test_old_and_missing_lockfiles_are_refused(self):
        with self.assertRaisesRegex(A.AcquireError, "lockfileVersion 1"):
            A.plan_npm(self.tree({"package-lock.json": {"lockfileVersion": 1, "dependencies": {}}}))
        with self.assertRaisesRegex(A.AcquireError, "no package-lock.json"):
            A.plan_npm(self.tree({"package.json": "{}"}))
        with self.assertRaisesRegex(A.AcquireError, "unambiguous JSON"):
            A.plan_npm(self.tree({"package-lock.json": '{"lockfileVersion": 3, "lockfileVersion": 3}'}))


class Origins(Base):
    def test_only_approved_https_origins(self):
        o = A.parse_origins(["https://registry.npmjs.org/", "https://mirror.example.invalid:8443/npm"])
        good = ("https://registry.npmjs.org/ok/-/ok-1.0.0.tgz", "https://MIRROR.example.invalid:8443/npm/a/-/a-1.tgz")
        bad = ("http://registry.npmjs.org/ok/-/ok-1.0.0.tgz", "https://registry.npmjs.org.evil.invalid/x.tgz",
               "https://user:pw@registry.npmjs.org/x.tgz", "https://registry.npmjs.org:444/x.tgz",
               "https://mirror.example.invalid:8443/npm/../other/x.tgz", "https://mirror.example.invalid:8443/npm/%2e%2e/x",
               "https://mirror.example.invalid:8443/npmx/a.tgz", "https://registry.npmjs.org/x.tgz?redirect=1")
        self.assertTrue(all(A.approved(u, o) for u in good))
        self.assertFalse(any(A.approved(u, o) for u in bad))
        for value in ("http://registry.npmjs.org/", "https://u:p@host/", [], "https://host/?q=1"):
            with self.assertRaises(A.AcquireError):
                A.parse_origins(value if isinstance(value, list) else [value])

    def test_only_public_addresses(self):
        for ip in ("127.0.0.1", "10.1.2.3", "192.168.0.1", "172.16.0.1", "169.254.169.254", "::1", "fe80::1",
                   "::ffff:127.0.0.1", "100.64.0.1", "0.0.0.0", "224.0.0.1"):
            with self.subTest(ip=ip), self.assertRaises(A.AcquireError):
                A.check_address(ip)
        for ip in ("93.184.216.34", "2606:4700:4700::1111"):
            A.check_address(ip)


class Fetching(Base):
    ORIGINS = A.parse_origins(["https://registry.npmjs.org/"])
    ART = {"package": "ok", "version": "1.0.0", "url": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz",
           "sha512": hashlib.sha512(TARBALL).hexdigest()}

    def test_bytes_must_match_and_fit(self):
        dest = os.path.join(self.tree(), "a.tgz")
        self.assertEqual(A.fetch(self.ART, self.ORIGINS, dest, 1000, lambda u, n, *_: iter([TARBALL[:5], TARBALL[5:]])),
                         (len(TARBALL), len(TARBALL)))
        with open(dest, "rb") as fh:
            self.assertEqual(fh.read(), TARBALL)
        for stream, why in ((lambda u, n, *_: iter([b"tampered"]), "do not match"),
                            (lambda u, n, *_: iter([TARBALL]), "size limit")):
            dest2 = os.path.join(self.tree(), "b.tgz")
            with self.subTest(why=why), self.assertRaisesRegex(A.AcquireError, why):
                A.fetch(self.ART, self.ORIGINS, dest2, 1000 if why != "size limit" else 4, stream)
            self.assertFalse(os.path.exists(dest2) or os.path.exists(dest2 + ".part"))

    def test_an_unapproved_url_is_never_requested(self):
        called = []
        art = dict(self.ART, url="https://elsewhere.invalid/ok.tgz")
        with self.assertRaisesRegex(A.AcquireError, "approved origin"):
            A.fetch(art, self.ORIGINS, os.path.join(self.tree(), "c.tgz"), 1000, lambda u, n, *_: called.append(u) or iter([]))
        self.assertEqual(called, [])


class Publishing(Base):
    def app(self):
        return self.tree({"package.json": {"name": "app", "version": "1.0.0", "dependencies": {"ok": "1.0.0"}},
                          "package-lock.json": self.lock({
                              "node_modules/ok": {"version": "1.0.0", "integrity": sri(TARBALL),
                                                  "resolved": "https://registry.npmjs.org/ok/-/ok-1.0.0.tgz"},
                              "node_modules/gitdep": {"version": "1.0.0", "resolved": "git+https://example.invalid/x"}})})

    def test_a_receipt_and_cache_outside_the_repository(self):
        root, built = self.app(), []
        out = os.path.join(self.tree(), "acq")
        # no engine is needed: the cache build is faked, and docker needs no ownership hand-back
        with mock.patch.object(jh_detonate, "find_engine", lambda engine=None: "docker"):
            r = A.run(root, ["https://registry.npmjs.org/"], out, stream=lambda u, n, *_: iter([TARBALL]),
                      build=lambda t, c, e, i: built.append(sorted(os.listdir(t))))
        self.assertEqual(built, [["00000.tgz"]])          # our own names, never the lockfile's
        self.assertEqual((r["state"], r["counts"]["fetched"], r["counts"]["refused"]), ("partial", 1, 1))
        with open(os.path.join(out, "receipt.json")) as fh:
            self.assertEqual(json.load(fh)["lockfile_sha256"], r["lockfile_sha256"])
        self.assertTrue(os.path.isdir(os.path.join(out, "npm")))

    def test_the_output_must_be_new_and_outside(self):
        root = self.app()
        with self.assertRaisesRegex(A.AcquireError, "outside the repository"):
            A.run(root, ["https://registry.npmjs.org/"], os.path.join(root, "cache"))
        full = self.tree({"x": "1"})
        with self.assertRaisesRegex(A.AcquireError, "new or empty"):
            A.run(root, ["https://registry.npmjs.org/"], full)


class AuditFindings(Base):
    """The 4.0.0 pre-ship audit's acquisition findings, each pinned."""

    def test_rejected_bytes_spend_the_download_budget(self):
        entries = {"node_modules/p%d" % i: {"version": "1.0.0", "resolved": "https://registry.npmjs.org/p%d.tgz" % i,
                                            "integrity": sri(b"expected-%d" % i)} for i in range(4)}
        root, streamed = self.tree({"package-lock.json": self.lock(entries)}), []

        def stream(url, limit, usage):
            streamed.append(url)
            yield b"DATA"                                 # never the pinned bytes
        with mock.patch.object(jh_detonate, "find_engine", lambda engine=None: "docker"), \
                mock.patch.object(A, "MAX_TOTAL_BYTES", 6):
            r = A.run(root, ["https://registry.npmjs.org/"], os.path.join(self.tree(), "out"), stream=stream,
                      build=lambda *a: None)
        self.assertEqual(len(streamed), 2)                # 4 + 4 bytes spend the 6-byte budget; the rest wait
        self.assertEqual((r["counts"]["bytes"], r["counts"]["downloaded"]), (0, 8))
        self.assertEqual(sum("budget is spent" in x["reason"] for x in r["refused"]), 2)

    def test_a_response_cut_short_spends_the_budget(self):
        # the real HTTP parser over three truncated chunked bodies: after a whole chunk, inside a chunk, and
        # inside a chunk after a whole one; each stops the 6-byte budget after the first request
        import http.client
        for body in (b"4\r\nDATA\r\n", b"8\r\nDATA", b"3\r\nABC\r\n8\r\nDATA"):
            with self.subTest(body=body):
                self.cut_short(http.client, b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + body,
                               len(body))

    def cut_short(self, client, wire, consumed):
        requests = []

        class Socket:
            def makefile(self, mode="rb", buffering=None):
                return io.BytesIO(wire if buffering == 0 else b"")    # the response reads the unbuffered one

        class Connection:
            def __init__(self, *args):
                pass

            def request(self, method, path, headers=None):
                requests.append(path)

            def getresponse(self):
                response = A._MeteredResponse(Socket(), method="GET")
                response.begin()
                return response

            def close(self):
                pass

        entries = {"node_modules/p%d" % i: {"version": "1.0.0", "resolved": "https://registry.npmjs.org/p%d.tgz" % i,
                                            "integrity": sri(b"expected-%d" % i)} for i in range(3)}
        root = self.tree({"package-lock.json": self.lock(entries)})
        with mock.patch.object(jh_detonate, "find_engine", lambda engine=None: "docker"), \
                mock.patch.object(A, "MAX_TOTAL_BYTES", 6), mock.patch.object(A, "_PinnedHTTPS", Connection), \
                mock.patch.object(A, "resolve", lambda host, port: "192.0.2.1"):
            r = A.run(root, ["https://registry.npmjs.org/"], os.path.join(self.tree(), "out"), build=lambda *a: None)
        self.assertEqual(len(requests), 1)                # the first cut spends more than the 6-byte budget
        self.assertGreaterEqual(r["counts"]["downloaded"], consumed)
        self.assertIn("cut short", r["refused"][0]["reason"])
        self.assertEqual([x["reason"] for x in r["refused"][1:]], ["not fetched: the download budget is spent"] * 2)


    def test_a_read_that_fails_part_way_spends_what_it_took(self):
        # the real buffered reader under the HTTP parser: 393,216 body bytes arrive, then the connection fails
        # inside a single read; none of them is returned, and all of them must be charged
        import http.client

        class Raw(io.RawIOBase):
            def __init__(self, data, then):
                super().__init__()
                self.data, self.then, self.pos = data, then, 0

            def readable(self):
                return True

            def readinto(self, buffer):
                if self.pos >= len(self.data):
                    raise self.then
                n = min(len(buffer), len(self.data) - self.pos, 65536)
                buffer[:n] = self.data[self.pos:self.pos + n]
                self.pos += n
                return n

        body = b"x" * 393216
        for name, head, then in (
                ("length", b"Content-Length: 400000\r\n\r\n", ConnectionResetError("reset")),
                ("chunked", b"Transfer-Encoding: chunked\r\n\r\nf4240\r\n", TimeoutError("timed out"))):
            wire, requests = b"HTTP/1.1 200 OK\r\n" + head + body, []

            class Socket:
                def makefile(self, mode="rb", buffering=None):
                    return Raw(wire, then) if buffering == 0 else io.BytesIO(b"")

            class Connection:
                def __init__(self, *args):
                    pass

                def request(self, method, path, headers=None):
                    requests.append(path)

                def getresponse(self):
                    response = A._MeteredResponse(Socket(), method="GET")
                    response.begin()
                    return response

                def close(self):
                    pass

            entries = {"node_modules/p%d" % i: {"version": "1.0.0",
                                                "resolved": "https://registry.npmjs.org/p%d.tgz" % i,
                                                "integrity": sri(b"expected-%d" % i)} for i in range(3)}
            root = self.tree({"package-lock.json": self.lock(entries)})
            with self.subTest(body=name), \
                    mock.patch.object(jh_detonate, "find_engine", lambda engine=None: "docker"), \
                    mock.patch.object(A, "MAX_TOTAL_BYTES", 800000), \
                    mock.patch.object(A, "_PinnedHTTPS", Connection), \
                    mock.patch.object(A, "resolve", lambda host, port: "192.0.2.1"):
                r = A.run(root, ["https://registry.npmjs.org/"], os.path.join(self.tree(), "out"),
                          build=lambda *a: None)
                failed = sum(x["reason"].startswith("download failed") for x in r["refused"])
                self.assertGreaterEqual(failed, 1)
                # every failed read is charged all 393,216 bytes it took, though it returned none of them
                self.assertGreaterEqual(r["counts"]["downloaded"], failed * len(body))

    def real_connection(self, wire, opened=None):
        # the real _PinnedHTTPS and HTTPResponse over an in-memory socket: no TLS, no network
        sent = []

        class Socket:
            def sendall(self, data):
                sent.append(data)

            def makefile(self, mode="rb", buffering=None):
                f = io.BytesIO(wire if buffering == 0 else b"")
                if opened is not None:
                    opened.append(f)
                return f

            def close(self):
                pass

        def connect(conn):
            conn.sock = Socket()
        return sent, mock.patch.object(A._PinnedHTTPS, "connect", connect)

    def test_every_refusal_closes_the_response(self):
        # with Connection: close the response owns the socket; a refusal must still close it, without waiting for GC
        close = b"Connection: close\r\n"
        for name, wire, limit in (
                ("status", b"HTTP/1.1 403 Forbidden\r\n" + close + b"Content-Length: 4\r\n\r\nDATA", 1000),
                ("declared size", b"HTTP/1.1 200 OK\r\n" + close + b"Content-Length: 400000\r\n\r\nDATA", 1000),
                ("bad hash", b"HTTP/1.1 200 OK\r\n" + close + b"Content-Length: 4\r\n\r\nDATA", 1000)):
            opened, kept, connections = [], [], []
            _, connect = self.real_connection(wire, opened)

            class Kept(A._MeteredResponse):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    kept.append(self)                 # held here: only an explicit close can close it

            class Tracked(A._PinnedHTTPS):
                def __init__(self, *args, **kwargs):
                    super().__init__(*args, **kwargs)
                    connections.append(weakref.ref(self))

            art = {"package": "x", "version": "1.0.0", "url": "https://registry.npmjs.org/x.tgz",
                   "sha512": hashlib.sha512(b"other").hexdigest()}
            gc.disable()                              # nothing may wait for the cycle collector
            try:
                with self.subTest(refusal=name), connect, \
                        mock.patch.object(A, "resolve", lambda host, port: "192.0.2.1"), \
                        mock.patch.object(A, "_MeteredResponse", Kept), mock.patch.object(A, "_PinnedHTTPS", Tracked):
                    try:
                        A.fetch(art, A.parse_origins(["https://registry.npmjs.org/"]), os.path.join(self.tree(), "x"),
                                limit)
                    except A.AcquireError:
                        pass
                    else:
                        self.fail("expected a refusal")
                    self.assertTrue(kept and opened and all(f.closed for f in opened), name)
                    if name == "bad hash":
                        # refused by fetch itself, so no exception traceback holds the stream's frame: only the
                        # connection's own reference cycle could keep it alive
                        self.assertIsNone(connections[0](), name)
            finally:
                gc.enable()

    def test_a_malformed_chunk_size_is_a_refusal_that_counts(self):
        # the parser raises ValueError on a negative chunk size; it becomes a refusal charged every byte received
        chunk = b"1;" + b"e" * 60000 + b"\r\nx\r\n"
        wire = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n" + chunk * 3 + b"-2\r\n"
        _, connect = self.real_connection(wire)
        art = {"package": "x", "version": "1.0.0", "url": "https://registry.npmjs.org/x.tgz",
               "sha512": hashlib.sha512(b"xxx").hexdigest()}
        with connect, mock.patch.object(A, "resolve", lambda host, port: "192.0.2.1"), \
                self.assertRaises(A.AcquireError) as ctx:
            A.fetch(art, A.parse_origins(["https://registry.npmjs.org/"]), os.path.join(self.tree(), "x"), 10 ** 7)
        self.assertGreaterEqual(ctx.exception.received, len(wire))

    def test_headers_that_fail_to_parse_still_spend_the_budget(self):
        # 101 headers: the parser reads them all, then refuses; every byte it read is charged
        import http.client
        header = b"X-Padding: " + b"p" * 1000 + b"\r\n"
        wire = b"HTTP/1.1 200 OK\r\n" + header * (http.client._MAXHEADERS + 1) + b"\r\n"
        sent, connect = self.real_connection(wire)
        entries = {"node_modules/p%d" % i: {"version": "1.0.0", "resolved": "https://registry.npmjs.org/p%d.tgz" % i,
                                            "integrity": sri(b"expected-%d" % i)} for i in range(3)}
        root = self.tree({"package-lock.json": self.lock(entries)})
        with connect, mock.patch.object(jh_detonate, "find_engine", lambda engine=None: "docker"), \
                mock.patch.object(A, "MAX_TOTAL_BYTES", len(header) * 100), \
                mock.patch.object(A, "resolve", lambda host, port: "192.0.2.1"):
            r = A.run(root, ["https://registry.npmjs.org/"], os.path.join(self.tree(), "out"), build=lambda *a: None)
        self.assertEqual(len(sent), 1)                    # the first refusal spends the whole budget
        self.assertGreaterEqual(r["counts"]["downloaded"], len(header) * 100)
        self.assertIn("download failed", r["refused"][0]["reason"])

    def test_framing_and_read_ahead_are_charged_on_success(self):
        # one payload byte behind a 60,000-byte chunk extension: the artifact is 1 byte, the download is not
        body = b"A"
        wire = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1;" + b"e" * 60000 + b"\r\n" + body +
                b"\r\n0\r\n\r\n")
        _, connect = self.real_connection(wire)
        art = {"package": "x", "version": "1.0.0", "url": "https://registry.npmjs.org/x.tgz",
               "sha512": hashlib.sha512(body).hexdigest()}
        with connect, mock.patch.object(A, "resolve", lambda host, port: "192.0.2.1"):
            size, used = A.fetch(art, A.parse_origins(["https://registry.npmjs.org/"]),
                                 os.path.join(self.tree(), "x.tgz"), 10 ** 6)
        self.assertEqual(size, 1)
        self.assertGreaterEqual(used, 60000)

    def test_no_byte_is_read_past_the_limit(self):
        # a correctly hashed 1-byte artifact followed by a flood of trailer lines: the limit stops the read itself
        wire = (b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nA\r\n0\r\n" +
                (b"X-Trailer: " + b"t" * 1000 + b"\r\n") * 200 + b"\r\n")
        _, connect = self.real_connection(wire)
        art = {"package": "x", "version": "1.0.0", "url": "https://registry.npmjs.org/x.tgz",
               "sha512": hashlib.sha512(b"A").hexdigest()}
        with connect, mock.patch.object(A, "resolve", lambda host, port: "192.0.2.1"), \
                self.assertRaisesRegex(A.AcquireError, "budget is spent") as ctx:
            A.fetch(art, A.parse_origins(["https://registry.npmjs.org/"]), os.path.join(self.tree(), "x.tgz"), 5000)
        self.assertLessEqual(ctx.exception.received, 5000)

    def test_a_failure_before_the_body_spends_nothing(self):
        failing = [{"package": "x", "url": "https://registry.npmjs.org/x.tgz", "sha512": "0" * 128}]

        def broken(url, limit, usage):
            raise A.AcquireError("download failed: reset") from None
            yield b""
        with self.assertRaises(A.AcquireError) as ctx:
            A.fetch(failing[0], A.parse_origins(["https://registry.npmjs.org/"]), os.path.join(self.tree(), "x"),
                    100, broken)
        self.assertEqual(ctx.exception.received, 0)       # nothing read, nothing charged

    def test_the_lockfile_is_read_without_following_a_link_or_its_bound(self):
        outside = self.tree({"package-lock.json": self.lock({})})
        root = self.tree()
        os.symlink(os.path.join(outside, "package-lock.json"), os.path.join(root, "package-lock.json"))
        with self.assertRaisesRegex(A.AcquireError, "without following a link"):
            A.plan_npm(root)
        big = self.tree({"package-lock.json": dict(self.lock({}), padding="x" * 512)})
        with mock.patch.object(A, "MAX_LOCK_BYTES", 128), self.assertRaisesRegex(A.AcquireError, "larger than"):
            A.plan_npm(big)

    def test_malformed_and_double_encoded_urls_are_refused(self):
        root = self.tree({"package-lock.json": self.lock({
            "node_modules/v6": {"version": "1.0.0", "resolved": "https://[broken/x.tgz", "integrity": sri(b"a")},
            "node_modules/ok": {"version": "1.0.0", "resolved": "https://registry.npmjs.org/ok.tgz",
                                "integrity": sri(b"b")}})})
        plan = A.plan_npm(root)
        self.assertEqual([a["package"] for a in plan["artifacts"]], ["ok"])
        self.assertIn("malformed", plan["refused"][0]["reason"])
        origins = A.parse_origins(["https://registry.npmjs.org/npm/"])
        for url in ("https://registry.npmjs.org:bad/npm/x.tgz", "https://registry.npmjs.org/npm/%252e%252e%252fx.tgz"):
            self.assertFalse(A.approved(url, origins), url)
        with self.assertRaises(A.AcquireError):
            A.parse_origins(["https://registry.npmjs.org:bad/"])

    def test_one_url_pinned_to_two_hashes_is_refused(self):
        url = "https://registry.npmjs.org/same.tgz"
        root = self.tree({"package-lock.json": self.lock({
            "node_modules/a": {"version": "1.0.0", "resolved": url, "integrity": sri(b"one")},
            "node_modules/b/node_modules/a": {"version": "1.0.0", "resolved": url, "integrity": sri(b"two")}})})
        plan = A.plan_npm(root)
        self.assertEqual(plan["artifacts"], [])
        self.assertEqual([r["reason"] for r in plan["refused"]], ["the lockfile pins this URL to more than one hash"] * 2)


class DetonateFetch(Base):
    """detonate --fetch: the fetch feeds this run's cache, is reported, and leaves nothing behind (no network)."""

    def cli(self):
        loader = importlib.machinery.SourceFileLoader("jh_cli", _util.CLI)
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader("jh_cli", loader))
        loader.exec_module(module)
        return module

    def detonate(self, *argv, refused=()):
        cli, seen = self.cli(), {}

        def fake_fetch(path, origins, out, image=None, engine=None):
            seen["origins"], seen["workdir"] = origins, os.path.dirname(out)
            os.makedirs(os.path.join(out, "npm"))
            return {"state": "partial" if refused else "complete", "lockfile": "package-lock.json",
                    "lockfile_sha256": "0" * 64, "origins": ["https://registry.npmjs.org:443/"],
                    "counts": {"pinned": 1 + len(refused), "fetched": 1, "refused": len(refused), "bytes": 22},
                    "skipped_platform": [], "fetched": [], "refused": list(refused),
                    "cache": os.path.join(out, "npm")}

        def fake_run(path, **kw):
            seen["npm_cache"], seen["cache_there"] = kw["npm_cache"], os.path.isdir(kw["npm_cache"] or "")
            return {"counts": {"ALERT": 0}, "coverage": {"state": "complete", "gaps": []}}

        args = cli.build_parser().parse_args(["detonate", self.tree({"x": "1"}), *argv])
        with mock.patch.object(A, "run", fake_fetch), mock.patch.object(jh_detonate, "run", fake_run), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out, mock.patch("sys.stderr", new_callable=io.StringIO):
            code = cli.cmd_detonate(args)
        return code, (json.loads(out.getvalue()) if out.getvalue() else None), seen

    def test_the_fetch_feeds_the_run_and_is_cleaned_up(self):
        code, doc, seen = self.detonate("--fetch", "https://registry.npmjs.org/", "--json")
        self.assertEqual(code, 0)
        self.assertEqual(seen["origins"], ["https://registry.npmjs.org/"])
        self.assertTrue(seen["cache_there"])                      # the run saw the fetched cache
        self.assertTrue(seen["npm_cache"].startswith(seen["workdir"] + os.sep))
        self.assertFalse(os.path.exists(seen["workdir"]))         # and nothing is left behind
        self.assertEqual((doc["fetch"]["state"], doc["fetch"]["counts"]["fetched"]), ("complete", 1))
        self.assertNotIn("cache", doc["fetch"])
        self.assertEqual(doc["coverage"], {"state": "complete", "gaps": []})

    def test_refused_packages_make_coverage_partial(self):
        refused = [{"package": "gitdep", "reason": "a git dependency"}]
        code, doc, _ = self.detonate("--fetch", "https://registry.npmjs.org/", "--json", refused=refused)
        self.assertEqual(code, 0)
        self.assertEqual(doc["fetch"]["refused"], refused)
        self.assertEqual(doc["coverage"]["state"], "partial")
        self.assertIn("pinned packages not fetched: 1", doc["coverage"]["gaps"][0])

    def test_fetch_and_a_supplied_cache_do_not_mix(self):
        code, doc, seen = self.detonate("--fetch", "https://registry.npmjs.org/", "--npm-cache", self.tree())
        self.assertEqual((code, doc, seen), (2, None, {}))


@unittest.skipUnless(os.environ.get("JH_ACQUIRE_LIVE") == "1" and shutil.which("podman") and
                     subprocess.run(["podman", "image", "exists", jh_detonate.DEFAULT_IMAGE]).returncode == 0,
                     "set JH_ACQUIRE_LIVE=1 with podman and the detonate image to fetch from the public npm registry")
class Live(Base):
    def test_fetch_then_detonate_offline(self):
        # a tiny public package with no dependencies and no install scripts; its real integrity is fetched first
        meta = json.loads(subprocess.run(["python3", "-c", (
            "import json,urllib.request;print(json.dumps(json.load(urllib.request.urlopen("
            "'https://registry.npmjs.org/is-number/7.0.0',timeout=30))['dist']))")],
            capture_output=True, text=True, check=True).stdout)
        root = self.tree({"package.json": {"name": "app", "version": "1.0.0", "dependencies": {"is-number": "7.0.0"}},
                          "package-lock.json": self.lock({"node_modules/is-number": {
                              "version": "7.0.0", "resolved": meta["tarball"], "integrity": meta["integrity"]}})})
        p = _util.run_cli("detonate", root, "--fetch", "https://registry.npmjs.org/", "--surface", "install",
                          "--timeout", "90", "--json")
        self.assertEqual(p.returncode, 0, p.stderr)
        d = json.loads(p.stdout)
        self.assertEqual((d["fetch"]["state"], d["fetch"]["counts"]["fetched"]), ("complete", 1))
        self.assertEqual([(s["name"], s["exit"]) for s in d["steps"]], [("npm ci (offline, with dependencies)", "0")])


if __name__ == "__main__":
    unittest.main()
