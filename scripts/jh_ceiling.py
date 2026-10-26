"""Operator input that can only narrow a discovered host/port plan.

This is not a runtime sandbox or proof of operator identity. The operator
must control the external file and its parent directories.
"""
from __future__ import annotations

import json
import os
import stat
from typing import AbstractSet, Any, Dict, Set, Tuple

import jh_fence

SCHEMA = "jankhunt.network-ceiling.v1"
MAX_BYTES = 65536
MAX_ENDPOINTS = 512


def _under(path: str, root: str) -> bool:
    try:
        return os.path.commonpath((path, root)) == root
    except ValueError:
        return False


def _unique(pairs: Any) -> Dict[str, Any]:
    result: Dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("network ceiling contains duplicate JSON keys")
        result[key] = value
    return result


def _endpoint(row: Any) -> Tuple[str, int]:
    if not isinstance(row, dict) or set(row) != {"host", "port"}:
        raise ValueError("network ceiling entries require only host and port")
    host, port = row["host"], row["port"]
    if not isinstance(host, str) or jh_fence.clean_host(host) != host:
        raise ValueError("network ceiling requires exact canonical hosts; no URLs, ports or wildcards")
    if type(port) is not int or not 1 <= port <= 65535:
        raise ValueError("network ceiling ports must be integers from 1 through 65535")
    return host, port


def load(path: str, root: str) -> Set[Tuple[str, int]]:
    """Read a bounded regular file outside both root spellings; no stdin."""
    absolute, resolved = os.path.abspath(path), os.path.realpath(path)
    roots = {os.path.abspath(root), os.path.realpath(root)}
    # A scanned subdirectory cannot promote its containing repository's file
    # into operator input. Inspect only Git metadata existence, not Git config.
    for start in tuple(roots):
        ancestor = start
        while True:
            if os.path.lexists(os.path.join(ancestor, ".git")):
                roots.add(ancestor)
            parent = os.path.dirname(ancestor)
            if parent == ancestor:
                break
            ancestor = parent
    if any(_under(candidate, base) for candidate in (absolute, resolved) for base in roots):
        raise ValueError("network ceiling must be supplied from outside the scanned repository")
    if absolute != resolved:
        raise ValueError("network ceiling requires a canonical external path without symlinks")
    flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(absolute, flags)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink > 1:
                raise ValueError("network ceiling requires a regular file without hard links")
            if info.st_size > MAX_BYTES:
                raise ValueError("network ceiling exceeds the size limit")
            raw = stream.read(MAX_BYTES + 1)
            after = os.fstat(stream.fileno())
            fingerprint = lambda s: (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_nlink)
            if fingerprint(info) != fingerprint(after):
                raise ValueError("network ceiling changed while it was read")
    except OSError as exc:
        raise ValueError("cannot read operator network ceiling") from exc
    if len(raw) > MAX_BYTES:
        raise ValueError("network ceiling exceeds the size limit")
    try:
        doc = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise ValueError("network ceiling is not unambiguous UTF-8 JSON") from exc
    if not isinstance(doc, dict) or set(doc) != {"schema", "allow"} or doc["schema"] != SCHEMA:
        raise ValueError("unsupported network ceiling schema or fields")
    rows = doc["allow"]
    if not isinstance(rows, list) or len(rows) > MAX_ENDPOINTS:
        raise ValueError("network ceiling allow must be a bounded list")
    return {_endpoint(row) for row in rows}


def constrain(plan: Dict[str, Any], ceiling: AbstractSet[Tuple[str, int]]) -> Dict[str, Any]:
    """Intersection only: approved destinations absent from discovery stay absent."""
    for host, port in ceiling:
        _endpoint({"host": host, "port": port})
    kept, excluded = [], list(plan["excluded"])
    for row in plan["allow"]:
        host, port = row["host"], row["port"]
        if not isinstance(host, str) or jh_fence.clean_host(host, wildcard=True) != host or \
                type(port) is not int or not 1 <= port <= 65535:
            raise ValueError("discovered network plan has an invalid destination")
        if (host, port) in ceiling:
            kept.append(row)
        else:
            excluded.append({"what": "%s:%d" % (host, port),
                             "why": "not approved by the operator network ceiling"})
    return dict(plan, allow=kept, excluded=excluded)
