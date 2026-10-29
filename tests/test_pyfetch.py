"""Python --fetch: parser, hostile indexes and real bounded HTTP parsing against an offline fixture server.

Only TLS connection establishment and DNS are substituted in fixture tests. Production origin checks, HTTP parser,
_CountingRaw, hash verification and publishing run as shipped. No pip or downloaded code runs on the host.
"""
import hashlib
import http.server
import importlib.machinery
import importlib.util
import io
import json
import os
import shutil
import socket
import tempfile
import threading
import unittest
from contextlib import contextmanager
from unittest import mock

import _util
import jh_acquire as A
import jh_sandbox
import jh_pyfetch as P

ORIGIN = "https://index.example.invalid/"
FILE_ORIGIN = "https://files.example.invalid/"
WHEEL = "demo_pkg-1.0-py3-none-any.whl"
SDIST = "demo_pkg-1.0.tar.gz"
PAYLOAD = b"invented wheel bytes; never opened or executed"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def requirement(data=PAYLOAD, name="Demo_Pkg", version="1.0"):
    return "%s==%s --hash=sha256:%s\n" % (name, version, sha(data))


def file_entry(filename=WHEEL, data=PAYLOAD, url=None, **kw):
    return dict({"filename": filename, "url": url or "/files/" + filename, "hashes": {"sha256": sha(data)}}, **kw)


def index(files, **kw):
    return json.dumps(dict({"meta": {"api-version": "1.0"}, "name": "demo-pkg", "files": files}, **kw)).encode()


class Base(unittest.TestCase):
    def tree(self, files=None):
        root = tempfile.mkdtemp(prefix="jh-pyfetch-")
        self.addCleanup(shutil.rmtree, root, True)
        for name, value in (files or {}).items():
            path = os.path.join(root, name)
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "wb") as fh:
                fh.write(value.encode() if isinstance(value, str) else value)
        return root

    @contextmanager
    def server(self, routes):
        requests = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                requests.append((self.headers.get("Host"), self.path, self.headers.get("Accept")))
                value = routes.get(self.path, (404, b"not found"))
                status, body = value[:2]
                self.send_response(status)
                extra = value[2] if len(value) > 2 else {}
                if "Content-Length" not in extra:
                    self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                for key, val in extra.items():
                    if val is not None:
                        self.send_header(key, val)
                self.end_headers()
                try:
                    self.wfile.write(body)
                except (BrokenPipeError, ConnectionResetError):
                    pass

            def log_message(self, *args):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=lambda: server.serve_forever(poll_interval=0.01), daemon=True)
        thread.start()

        def connect(conn):
            conn.sock = socket.create_connection(server.server_address, timeout=2)

        try:
            with mock.patch.object(A, "resolve", return_value="127.0.0.1"), \
                    mock.patch.object(A._PinnedHTTPS, "connect", connect):
                yield requests
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)

    def acquire(self, text=None, origins=None, **kw):
        root = self.tree({"requirements.txt": requirement() if text is None else text})
        out = os.path.join(self.tree(), "acq")
        return A.run(root, origins or [ORIGIN], out, **kw)


class Planning(Base):
    def test_comments_continuations_hash_sets_and_normalization(self):
        text = "# lock\n--require-hashes\nDemo_Pkg == 1.0 \\\n --hash=sha256:%s \\\n --hash sha256:%s # generated\n" % (sha(PAYLOAD).upper(), sha(b"other"))
        p = P.plan_requirements(self.tree({"requirements.txt": text}))
        self.assertEqual(p["refused"], [])
        self.assertEqual([(a["package"], a["version"], a["line"]) for a in p["artifacts"]], [("demo-pkg", "1.0", 3)])
        self.assertEqual(set(p["artifacts"][0]["hashes"]), {sha(PAYLOAD), sha(b"other")})
        self.assertEqual(p["lockfile_sha256"], sha(text.encode()))

    def test_unsupported_inputs_are_gaps_and_not_downloads(self):
        bad = ["demo-pkg", "demo-pkg>=1", "demo-pkg==1.0", "demo-pkg==1.*", "demo-pkg===1.0",
               "https://evil.example.invalid/x.whl", "./local.whl", "demo-pkg @ https://evil.example.invalid/x",
               "-e ./local", "-r other.txt", "--requirement=other.txt", "-c constraints.txt",
               "--index-url https://evil.example.invalid/", "--trusted-host localhost", "--no-binary=:all:",
               "demo-pkg[extra]==1.0", "demo-pkg==1.0; python_version < '3.0'", "demo-pkg==${VERSION}",
               "demo-pkg==1.* --hash=sha256:" + sha(PAYLOAD),
               "demo-pkg==banana --hash=sha256:" + sha(PAYLOAD),
               "demo-pkg==1.0 --hash=md5:" + "a" * 32, "demo-pkg==1.0 --hash=sha256:" + "a" * 63,
               requirement().strip() + " --config-settings=evil=1", requirement().strip() + " \\bad"]
        for text in bad:
            with self.subTest(text=text):
                with mock.patch.object(P, "json_stream", side_effect=AssertionError("must not fetch")):
                    r = self.acquire(text + "\n")
                self.assertEqual((r["state"], r["counts"]["fetched"], len(r["refused"])), ("partial", 0, 1))
                self.assertTrue(r["refused"][0]["reason"])

    def test_links_oversize_invalid_encoding_and_conflicting_duplicates(self):
        root = self.tree()
        other = self.tree({"requirements.txt": requirement()})
        os.symlink(os.path.join(other, "requirements.txt"), os.path.join(root, "requirements.txt"))
        self.assertIn("without following", P.plan_requirements(root)["refused"][0]["reason"])
        with mock.patch.object(A, "MAX_LOCK_BYTES", 20):
            p = P.plan_requirements(other)
        self.assertIn("larger", p["refused"][0]["reason"])
        self.assertTrue(P.plan_requirements(self.tree({"requirements.txt": b"\xff"}))["refused"])
        for second in (requirement(b"different"), requirement(version="2.0")):
            p = P.plan_requirements(self.tree({"requirements.txt": requirement() + second}))
            self.assertEqual(p["artifacts"], [])
            self.assertIn("conflicting", p["refused"][0]["reason"])
        p = P.plan_requirements(self.tree({"requirements.txt": requirement() * 2}))
        self.assertEqual((len(p["artifacts"]), p["refused"]), (1, []))

    def test_distribution_identity_and_safe_names(self):
        pin = {"package": "demo-pkg", "version": "1.0"}
        self.assertEqual(P._kind("demo_pkg-1.0.0-1-py3-none-any.whl", pin), "wheel")
        self.assertEqual(P._kind("demo-pkg-1.0.zip", pin), "sdist")
        self.assertEqual(P._kind("demo_pkg-1.0+local-py3-none-any.whl", pin), "wheel")
        for filename in ("../" + WHEEL, "/tmp/" + WHEEL, "..\\" + WHEEL, "%2f" + WHEEL,
                         "other-1.0-py3-none-any.whl", "demo_pkg-2.0-py3-none-any.whl",
                         "demo_pkg-1.0-.whl", "demo_pkg-1.0-x-py3-none-any.whl", WHEEL + "\n", "." + WHEEL, "demo_pkg-1.0-py3-none-../../owned.whl"):
            self.assertEqual(P._kind(filename, pin), "", filename)
        for a, b in (("v01.0RC01", "1.0rc1"), ("1.0-1", "1.0.post1"), ("1.0dev", "1.0.dev0"),
                     ("1!1.0+LOCAL_01", "1!1.0+local.1")):
            self.assertEqual(P._version_key(a), P._version_key(b))


class Acquisition(Base):
    def test_pep691_wheels_win_and_no_host_package_manager_runs(self):
        native = "demo_pkg-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
        entries = [file_entry(SDIST, b"source"), file_entry(native, b"native"), file_entry(), file_entry()]
        routes = {"/simple/demo-pkg/": (200, index(entries)), "/files/" + WHEEL: (200, PAYLOAD),
                  "/files/" + native: (200, b"native")}
        text = requirement().strip() + " --hash=sha256:%s --hash=sha256:%s\n" % (sha(b"source"), sha(b"native"))
        with self.server(routes) as calls, \
                mock.patch.object(jh_sandbox, "find_engine", side_effect=AssertionError("no engine needed")), \
                mock.patch("subprocess.run", side_effect=AssertionError("no host subprocess")):
            r = self.acquire(text)
        self.assertEqual((r["state"], r["counts"]["fetched"], r["counts"]["pinned"]), ("complete", 2, 2))
        self.assertEqual(calls[0][1:], ("/simple/demo-pkg/", P.JSON_ACCEPT))
        self.assertEqual(sorted(os.listdir(r["wheelhouse"])), sorted([native, WHEEL]))
        self.assertEqual(r["source_builds"], [])
        self.assertIsNone(r["cache"])
        self.assertGreater(r["counts"]["downloaded"], r["counts"]["bytes"])
        with open(os.path.join(os.path.dirname(r["wheelhouse"]), "receipt.json")) as fh:
            receipt = json.load(fh)
        self.assertEqual(receipt["lockfiles"], [{"path": "requirements.txt", "sha256": sha(text.encode())}])
        self.assertFalse(any(a["build_runs_code"] for a in receipt["fetched"]))
        self.assertNotIn("wheelhouse", A.summary(r))

    def test_a_pinned_sdist_is_explicit_and_is_never_opened(self):
        routes = {"/simple/demo-pkg/": (200, index([file_entry(SDIST)])), "/files/" + SDIST: (200, PAYLOAD)}
        with self.server(routes):
            r = self.acquire()
        self.assertEqual(r["state"], "complete")
        self.assertEqual(r["source_builds"], ["demo-pkg"])
        self.assertEqual((r["fetched"][0]["kind"], r["fetched"][0]["build_runs_code"]), ("sdist", True))
        self.assertEqual(A.summary(r)["source_builds"], ["demo-pkg"])

    def test_hashes_are_checked_against_the_pin_and_against_downloaded_bytes(self):
        for entry, why in ((file_entry(data=b"not pinned"), "no wheel or sdist"), (file_entry(), "do not match")):
            entries = [entry] if why == "no wheel or sdist" else [entry, file_entry(SDIST)]
            with self.subTest(why=why), self.server({"/simple/demo-pkg/": (200, index(entries)),
                                                    "/files/" + WHEEL: (200, b"tampered")}) as calls:
                r = self.acquire()
            self.assertEqual(r["state"], "partial")
            self.assertIn(why, r["refused"][0]["reason"])
            self.assertEqual(os.listdir(r["wheelhouse"]), [])
            self.assertEqual(len(calls), 1 if why == "no wheel or sdist" else 2)
            self.assertGreater(r["counts"]["downloaded"], 0)

    def test_off_origin_files_require_explicit_approval(self):
        routes = {"/simple/demo-pkg/": (200, index([file_entry(url=FILE_ORIGIN + "files/" + WHEEL)])),
                  "/files/" + WHEEL: (200, PAYLOAD)}
        with self.server(routes) as calls:
            r = self.acquire()
        self.assertEqual(len(calls), 1)
        self.assertIn("approved origin", r["refused"][0]["reason"])
        with self.server(routes) as calls:
            r = self.acquire(origins=[ORIGIN, FILE_ORIGIN])
        self.assertEqual(r["state"], "complete")
        self.assertEqual(calls[1][0], "files.example.invalid")

    def test_duplicate_mirrors_prefer_an_approved_url_without_counting_twice(self):
        entries = [file_entry(url="https://aaa.example.invalid/" + WHEEL), file_entry()]
        routes = {"/simple/demo-pkg/": (200, index(entries)), "/files/" + WHEEL: (200, PAYLOAD)}
        with self.server(routes) as calls:
            r = self.acquire()
        self.assertEqual((r["state"], r["counts"]["pinned"], r["counts"]["fetched"]), ("complete", 1, 1))
        self.assertEqual(len(calls), 2)

    def test_an_unapproved_index_is_never_requested(self):
        stream = mock.Mock(side_effect=AssertionError("must not fetch"))
        with self.assertRaisesRegex(A.AcquireError, "approved origin"):
            P._index(FILE_ORIGIN + "simple/demo-pkg/", A.parse_origins([ORIGIN]), 1000, stream)
        stream.assert_not_called()

    def test_redirects_path_escapes_and_private_addresses_are_refused(self):
        for url in ("http://index.example.invalid/files/" + WHEEL, "https://u:p@index.example.invalid/" + WHEEL,
                    ORIGIN + "simple/%2e%2e/" + WHEEL, ORIGIN + "files/" + WHEEL + "?q=1"):
            with self.subTest(url=url), self.server({"/simple/demo-pkg/": (200, index([file_entry(url=url)]))}) as calls:
                r = self.acquire()
            self.assertEqual((r["state"], len(calls)), ("partial", 1))
        with self.server({"/simple/demo-pkg/": (302, b"", {"Location": FILE_ORIGIN})}) as calls:
            r = self.acquire()
        self.assertEqual(len(calls), 1)
        self.assertIn("redirects are refused", r["refused"][0]["reason"])
        for ip in ("127.0.0.1", "169.254.169.254", "::1"):
            with mock.patch.object(A.socket, "getaddrinfo", return_value=[(0, 0, 0, "", (ip, 443))]), \
                    mock.patch.object(A, "_PinnedHTTPS", side_effect=AssertionError("must not connect")):
                r = self.acquire()
            self.assertIn("no public address", r["refused"][0]["reason"])

    def test_malformed_indexes_and_hostile_filenames_are_gaps(self):
        documents = [b"not JSON", b"[]", b'{"files":[],"files":[]}',
                     index([], meta={"api-version": "2.0"}), index([], meta=None),
                     b'{"files":' + b"[" * 1200 + b"]" * 1200 + b"}",
                     index([file_entry(filename="../" + WHEEL), file_entry(url="https://[broken/x")]),
                     index([file_entry(filename="other-1.0-py3-none-any.whl"),
                            file_entry(filename="demo_pkg-2.0-py3-none-any.whl")]),
                     index([None, {"filename": WHEEL, "url": 3, "hashes": []}])]
        for doc in documents:
            with self.subTest(doc=doc[:100]), self.server({"/simple/demo-pkg/": (200, doc)}) as calls:
                r = self.acquire()
            self.assertEqual((r["state"], r["counts"]["fetched"], len(calls)), ("partial", 0, 1))
            self.assertEqual(os.listdir(r["wheelhouse"]), [])

    def test_index_and_artifact_limits_include_wire_bytes_and_failed_downloads(self):
        routes = {"/simple/demo-pkg/": (200, index([file_entry()])), "/files/" + WHEEL: (200, PAYLOAD)}
        with self.server(routes) as calls, mock.patch.object(P, "MAX_INDEX_BYTES", 128):
            r = self.acquire()
        self.assertEqual((r["state"], len(calls)), ("partial", 1))
        self.assertLessEqual(r["counts"]["downloaded"], 128)
        with self.server(routes), mock.patch.object(A, "MAX_ARTIFACT_BYTES", 16):
            r = self.acquire()
        self.assertEqual((r["state"], r["counts"]["fetched"]), ("partial", 0))
        self.assertEqual(os.listdir(r["wheelhouse"]), [])
        # An overlarge first index spends the entire global allowance. The second pin must cause no request.
        routes["/simple/demo-pkg/"] = (200, b" " * 4000, {"Content-Length": None})
        with self.server(routes) as calls, mock.patch.object(A, "MAX_TOTAL_BYTES", 256):
            r = self.acquire(requirement() + requirement(name="next"))
        self.assertEqual(len(calls), 1)
        self.assertEqual(r["counts"]["downloaded"], 256)
        self.assertEqual(len(r["refused"]), 2)
        self.assertIn("budget is spent", r["refused"][1]["reason"])

    def test_subpath_simple_root_relative_urls_and_wheels_from_a_second_index(self):
        routes = {"/mirror/simple/demo-pkg/": (200, index([file_entry(SDIST)])),
                  "/simple/demo-pkg/": (200, index([file_entry(url="../../files/" + WHEEL)])),
                  "/files/" + WHEEL: (200, PAYLOAD)}
        with self.server(routes) as calls:
            r = self.acquire(origins=[ORIGIN + "mirror/simple/", FILE_ORIGIN])
        self.assertEqual(r["state"], "complete")
        self.assertEqual([x[1] for x in calls], ["/mirror/simple/demo-pkg/", "/simple/demo-pkg/", "/files/" + WHEEL])
        self.assertEqual(r["source_builds"], [])

    def test_file_hash_conflicts_and_artifact_count_bound(self):
        text = requirement().strip() + " --hash=sha256:" + sha(b"other") + "\n"
        routes = {"/simple/demo-pkg/": (200, index([file_entry(), file_entry(data=b"other")]))}
        with self.server(routes) as calls:
            r = self.acquire(text)
        self.assertEqual(len(calls), 1)
        self.assertTrue(all("conflicting hashes" in a["reason"] for a in r["refused"]))
        # Two distinct basenames must hit the count bound independently of the conflict guard above.
        native = "demo_pkg-1.0-cp311-cp311-manylinux_2_17_x86_64.whl"
        routes["/simple/demo-pkg/"] = (200, index([file_entry(), file_entry(native, b"other")]))
        routes["/files/" + WHEEL] = (200, PAYLOAD)
        routes["/files/" + native] = (200, b"other")
        with self.server(routes) as calls, mock.patch.object(A, "MAX_ARTIFACTS", 1):
            r = self.acquire(text)
        self.assertEqual((r["state"], len(calls), r["counts"]["fetched"]), ("partial", 1, 0))

    def test_npm_and_python_share_the_budget(self):
        data = b"tarball"
        import base64
        root = self.tree({"requirements.txt": requirement(), "package-lock.json": json.dumps({
            "lockfileVersion": 3, "packages": {"node_modules/demo": {"version": "1.0", "resolved": ORIGIN + "a.tgz",
            "integrity": "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()}}})})
        routes = {"/a.tgz": (200, data), "/simple/demo-pkg/": (200, index([file_entry()])),
                  "/files/" + WHEEL: (200, PAYLOAD)}
        with self.server(routes), mock.patch.object(jh_sandbox, "find_engine", return_value="docker"):
            r = A.run(root, [ORIGIN], os.path.join(self.tree(), "out"), build=lambda *a: None)
        self.assertEqual((r["state"], r["counts"]["fetched"], len(r["lockfiles"])), ("complete", 2, 2))
        self.assertTrue(os.path.isdir(r["cache"]) and os.path.isdir(r["wheelhouse"]))
        with self.server(routes) as calls, mock.patch.object(jh_sandbox, "find_engine", return_value="docker"), \
                mock.patch.object(A, "MAX_TOTAL_BYTES", 16):
            r = A.run(root, [ORIGIN], os.path.join(self.tree(), "out"), build=lambda *a: None)
        self.assertEqual((r["state"], r["counts"]["downloaded"], len(calls)), ("partial", 16, 1))


class DetonateHandoff(Base):
    def cli(self):
        loader = importlib.machinery.SourceFileLoader("jh_cli_pyfetch", _util.CLI)
        module = importlib.util.module_from_spec(importlib.util.spec_from_loader("jh_cli_pyfetch", loader))
        loader.exec_module(module)
        return module

    def test_actual_acquisition_hands_both_paths_to_the_sandbox_and_cleans_up(self):
        cli, seen = self.cli(), {}
        root = self.tree({"requirements.txt": requirement() + "-r other.txt\n"})
        args = cli.build_parser().parse_args(["sandbox", root, "--fetch", ORIGIN, "--json"])

        def run(path, **kw):
            seen.update(kw)
            self.assertIsNone(kw["npm_cache"])
            self.assertTrue(os.path.isfile(os.path.join(kw["wheelhouse"], WHEEL)))
            return {"counts": {"ALERT": 0}, "coverage": {"state": "complete", "gaps": []}}

        routes = {"/simple/demo-pkg/": (200, index([file_entry()])), "/files/" + WHEEL: (200, PAYLOAD)}
        with self.server(routes), mock.patch.object(jh_sandbox, "run", run), \
                mock.patch("sys.stdout", new_callable=io.StringIO) as out:
            code = cli.cmd_sandbox(args)
        d = json.loads(out.getvalue())
        self.assertEqual((code, d["fetch"]["state"], d["coverage"]["state"]), (0, "partial", "partial"))
        self.assertIn("pinned packages not fetched: 1", d["coverage"]["gaps"][0])
        self.assertFalse(os.path.exists(os.path.dirname(seen["wheelhouse"])))
        self.assertNotIn("wheelhouse", d["fetch"])

    def test_supplied_wheelhouse_and_fetch_do_not_mix(self):
        cli = self.cli()
        args = cli.build_parser().parse_args(["sandbox", self.tree(), "--fetch", ORIGIN, "--wheelhouse", self.tree()])
        with mock.patch.object(A, "run", side_effect=AssertionError("must not fetch")), \
                mock.patch("sys.stderr", new_callable=io.StringIO):
            self.assertEqual(cli.cmd_sandbox(args), 2)


@unittest.skipUnless(os.environ.get("JH_ACQUIRE_LIVE") == "1", "set JH_ACQUIRE_LIVE=1 for a public PyPI fetch")
class Live(Base):
    def test_public_pypi_wheel(self):
        # Fixed tiny public wheel; known digest from https://pypi.org/pypi/six/1.17.0/json.
        # At test time the pin is independent of the simple API response and downloaded bytes.
        text = "six==1.17.0 --hash=sha256:4721f391ed90541fddacab5acf947aa0d3dc7d27b2e1e8eda2be8970586c3274\n"
        r = self.acquire(text, origins=["https://pypi.org/", "https://files.pythonhosted.org/"])
        self.assertEqual((r["state"], r["counts"]["fetched"]), ("complete", 1), r["refused"])
        self.assertEqual(r["fetched"][0]["kind"], "wheel")


if __name__ == "__main__":
    unittest.main()
