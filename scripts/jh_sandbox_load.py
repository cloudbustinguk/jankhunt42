"""Loads one installed Python distribution for the sandbox's import surface: its top-level modules, imported the way an
application imports them, so code that runs only when a package is loaded runs where the tracer can see it.

Runs inside the sandbox as `python3 -I /jh/load.py NAME`, after pip installed the requirements into /work/pydeps.
The modules come from the distribution's own record (top_level.txt, else the top of RECORD). With `--pth` instead
of a name, it only adds the folder as a site directory, so the .pth files installed there run, as they do at every
Python start from a real site-packages; that is its own step, so what they do is never charged to a package import.
stdlib only.
"""
import importlib
import os
import re
import site
import sys
import time

PYDEPS = "/work/pydeps"
MAX_MODULES = 10
SETTLE_SECONDS = 2        # after loading, time for what it deferred (a timer, a thread) to run where it is seen
_NOT_MODULES = {"bin", "include", "share", "lib", "scripts"}


def _norm(name: str) -> str:
    return re.sub(r"[-_.]+", "_", name).lower()


def modules(name: str, base: str = PYDEPS) -> list:
    """The top-level modules distribution `name` installed under base, at most MAX_MODULES."""
    want = _norm(name)
    try:
        entries = sorted(os.listdir(base))
    except OSError:
        return []
    for entry in entries:
        if not entry.endswith(".dist-info") or _norm(entry[:-len(".dist-info")].rsplit("-", 1)[0]) != want:
            continue
        info = os.path.join(base, entry)
        found = []
        top = os.path.join(info, "top_level.txt")
        record = os.path.join(info, "RECORD")
        if os.path.isfile(top):
            with open(top, encoding="utf-8", errors="replace") as fh:
                found = [line.strip() for line in fh]
        elif os.path.isfile(record):
            with open(record, encoding="utf-8", errors="replace") as fh:
                for line in fh:
                    parts = line.split(",", 1)[0].split("/")
                    # a package folder, or a module file at the top (pkg.py, or an extension pkg.cpython-312-...so)
                    head = parts[0] if len(parts) > 1 else (parts[0].split(".", 1)[0]
                                                            if parts[0].endswith((".py", ".so", ".pyd")) else "")
                    if head and head not in found:
                        found.append(head)
        return [m for m in found if m.isidentifier() and m not in _NOT_MODULES
                and not m.endswith(("_dist_info", "_data"))][:MAX_MODULES]
    return []


def main(argv: list) -> int:
    if len(argv) != 2:
        return 2
    if argv[1] == "--pth":
        site.addsitedir(PYDEPS)
        time.sleep(SETTLE_SECONDS)
        return 0
    names = modules(argv[1])
    if not names:
        print("jankhunt42: no importable module found for %s" % argv[1], file=sys.stderr)
        return 3
    sys.path.insert(0, PYDEPS)          # after this script's own imports, so nothing installed can stand in for them
    failed = 0
    for name in names:
        try:
            importlib.import_module(name)
            print("jankhunt42: imported %s" % name)
        except BaseException as exc:    # a module may raise anything while it loads, SystemExit included
            failed += 1
            print("jankhunt42: import %s failed: %s" % (name, type(exc).__name__), file=sys.stderr)
    time.sleep(SETTLE_SECONDS)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
