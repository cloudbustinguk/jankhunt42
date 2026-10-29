"""NuGet acquisition and .NET discovery. Project files are data here; MSBuild and archives run only in the guest.

Fetch supports default packages.lock.json files, and literal, unconditional RestoreLockedMode=true in a project
or its nearest Directory.Build.props/targets. Custom imports/conditional lock settings are refused as unresolved.
https://learn.microsoft.com/en-us/nuget/consume-packages/package-references-in-project-files#locking-dependencies
https://learn.microsoft.com/en-us/nuget/api/package-base-address-resource
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import re
import stat
import xml.etree.ElementTree as ET
from typing import Any, Dict, List

import jh_ceiling
from jh_graph import sanitize_text

MAX_PROJECTS = 100
MAX_ENTRIES = 20000
MAX_XML_BYTES = 1024 * 1024
_SKIP = {'.git', 'bin', 'obj', 'node_modules', '.venv', 'venv', '__pycache__'}
_PROPS = ('Directory.Build.props', 'Directory.Packages.props', 'Directory.Build.targets')
_ID = re.compile(r'[A-Za-z0-9_.-]{1,100}\Z')
_VERSION = re.compile(r'([0-9]+(?:\.[0-9]+){1,3})(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?'
                      r'(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\Z')


class PlanError(ValueError):
    pass


def discover(root: str) -> Dict[str, Any]:
    """Bounded descriptor-relative discovery. No repository link is traversed, even when entries change."""
    result: Dict[str, Any] = {'projects': [], 'solutions': [], 'locks': [], 'files': set(), 'issues': []}
    count = 0
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK

    def walk(fd: int, prefix: str, depth: int) -> None:
        nonlocal count
        if depth > 64:
            raise PlanError('.NET discovery nests deeper than 64 folders')
        for name in sorted(os.listdir(fd)):
            count += 1
            if count > MAX_ENTRIES:
                raise PlanError('.NET discovery exceeds %d entries' % MAX_ENTRIES)
            rel = prefix + name
            st = os.stat(name, dir_fd=fd, follow_symlinks=False)
            if stat.S_ISDIR(st.st_mode):
                if name not in _SKIP:
                    sub = os.open(name, flags, dir_fd=fd)
                    try:
                        walk(sub, rel + '/', depth + 1)
                    finally:
                        os.close(sub)
                continue
            result['files'].add(rel)
            low = name.lower()
            field = 'projects' if low.endswith('.csproj') else 'solutions' if low.endswith('.sln') else \
                    'locks' if name == 'packages.lock.json' else None
            if field:
                result[field].append(rel)
                if not stat.S_ISREG(st.st_mode):
                    result['issues'].append('%s is not a regular file' % sanitize_text(rel))
        if len(result['projects']) > MAX_PROJECTS:
            raise PlanError('more than %d .NET projects' % MAX_PROJECTS)

    try:
        fd = os.open(root, flags)
        try:
            walk(fd, '', 0)
        finally:
            os.close(fd)
    except (OSError, PlanError) as exc:
        result['issues'].append('could not discover .NET inputs: %s' % sanitize_text(str(exc)))
    return result


def is_dotnet(root: str) -> bool:
    tree = discover(root)
    return bool(tree['projects'] or tree['solutions'])


def _read(root: str, rel: str, limit: int) -> bytes:
    """Open every component without following links; reject devices/FIFOs before reading bounded bytes."""
    parts = rel.split('/')
    if os.path.isabs(rel) or any(p in ('', '.', '..') for p in parts):
        raise PlanError('invalid repository-relative input path')
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_NONBLOCK
    fd = None
    try:
        fd = os.open(root, flags)
        for p in parts[:-1]:
            sub = os.open(p, flags, dir_fd=fd)
            os.close(fd)
            fd = sub
        leaf = os.open(parts[-1], os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=fd)
        with os.fdopen(leaf, 'rb') as fh:
            if not stat.S_ISREG(os.fstat(fh.fileno()).st_mode):
                raise PlanError('%s is not a regular file' % sanitize_text(rel))
            data = fh.read(limit + 1)
        if len(data) > limit:
            raise PlanError('%s exceeds its input size limit' % sanitize_text(rel))
        return data
    except OSError:
        raise PlanError('%s cannot be read without following a link' % sanitize_text(rel)) from None
    finally:
        if fd is not None:
            os.close(fd)


def _nearest(rel: str, name: str, files: set) -> str:
    parent = rel.rsplit('/', 1)[0] if '/' in rel else ''
    while True:
        path = parent + '/' + name if parent else name
        if path in files:
            return path
        if not parent:
            return ''
        parent = parent.rsplit('/', 1)[0] if '/' in parent else ''


def _locked(root: str, project: str, files: set) -> bool:
    paths = [_nearest(project, n, files) for n in _PROPS[:2]] + [project] + [_nearest(project, _PROPS[2], files)]
    value = None
    for path in dict.fromkeys(p for p in paths if p):
        raw = _read(root, path, MAX_XML_BYTES)
        # Reject declarations before XML parsing, including UTF-16 input: no entities are expanded on the host.
        try:
            text = raw.decode('utf-8-sig')
        except UnicodeError:
            raise PlanError('project/props XML must be UTF-8') from None
        if '<!DOCTYPE' in text.upper() or '<!ENTITY' in text.upper():
            raise PlanError('XML entity/doctype declarations are not supported')
        try:
            doc = ET.fromstring(text)
        except (ET.ParseError, RecursionError, ValueError):
            raise PlanError('project/props XML could not be parsed') from None
        groups = {id(e) for e in doc if e.tag.rsplit("}", 1)[-1].lower() == "propertygroup"}
        for element in doc.iter():
            tag = element.tag.rsplit('}', 1)[-1].lower()
            if tag in ('import', 'importgroup', 'choose'):
                raise PlanError('custom MSBuild imports/choices: locked mode cannot be verified statically')
            local = element.attrib.get('TreatAsLocalProperty', '').lower().split(';')
            if 'restorelockedmode' in (p.strip() for p in local):
                raise PlanError('RestoreLockedMode is local and can override the locked-mode command')
            if tag == 'propertygroup':
                if id(element) not in groups and any(p.tag.rsplit('}', 1)[-1].lower() == 'restorelockedmode' for p in element):
                    raise PlanError('dynamic lock settings inside a target cannot be verified statically')
                for prop in element:
                    key = prop.tag.rsplit('}', 1)[-1].lower()
                    if key not in ('restorelockedmode', 'nugetlockfilepath', 'restorepackageswithlockfile'):
                        continue
                    if 'Condition' in element.attrib or 'Condition' in prop.attrib:
                        raise PlanError('conditional lock settings cannot be verified statically')
                    v = (prop.text or '').strip().lower()
                    if key == 'restorelockedmode':
                        if v not in ('true', 'false'):
                            raise PlanError('RestoreLockedMode must be a literal true or false')
                        value = v == 'true'
                    elif key == 'nugetlockfilepath' and v not in ('', 'packages.lock.json'):
                        raise PlanError('custom NuGetLockFilePath is not supported')
                    elif key == 'restorepackageswithlockfile' and v != 'true':
                        raise PlanError('RestorePackagesWithLockFile must not disable the lock')
    return value is True


def version(value: Any) -> str:
    if not isinstance(value, str) or len(value) > 128:
        return ''
    m = _VERSION.fullmatch(value)
    if not m:
        return ''
    parts = [(p.lstrip('0') or '0') for p in m[1].split('.')]
    parts += ['0'] * (3 - len(parts))
    if len(parts) == 4 and parts[-1] == '0':
        parts.pop()
    return '.'.join(parts) + ('-' + m[2].lower() if m[2] else '')


def plan(root: str, tree: Any = None) -> Dict[str, Any]:
    import jh_acquire as A
    tree = tree or discover(root)
    result: Dict[str, Any] = {'lockfile': 'packages.lock.json', 'lockfile_sha256': None, 'lockfiles': [],
                              'artifacts': [], 'refused': [], 'skipped_platform': 0}
    def refuse(package: str, reason: str) -> None:
        result['refused'].append({'package': sanitize_text(package), 'reason': sanitize_text(reason)})
    if tree['issues']:
        for issue in tree['issues']:
            refuse('NuGet', issue)
        return result
    if not tree['projects']:
        refuse('NuGet', 'no project with a verifiable locked-mode setting (a solution or lock alone is insufficient)')
        return result
    artifacts: Dict[tuple, Dict[str, Any]] = {}
    hashes: Dict[tuple, set] = {}
    read_bytes = 0
    for project in tree['projects']:
        lock = (project.rsplit('/', 1)[0] + '/' if '/' in project else '') + 'packages.lock.json'
        try:
            if not _locked(root, project, tree['files']):
                raise PlanError('project is not in locked mode (RestoreLockedMode must be true)')
            raw = _read(root, lock, max(0, A.MAX_LOCK_BYTES - read_bytes))
            read_bytes += len(raw)
            doc = json.loads(raw.decode('utf-8-sig'), object_pairs_hook=jh_ceiling._unique)
            if not isinstance(doc, dict) or type(doc.get('version')) is not int or doc['version'] not in (1, 2) or \
                    not isinstance(doc.get('dependencies'), dict):
                raise PlanError('packages.lock.json must be NuGet lock format version 1 or 2')
        except (PlanError, UnicodeError, ValueError, RecursionError) as exc:
            refuse(project, str(exc))
            continue
        receipt = {'path': sanitize_text(lock), 'sha256': hashlib.sha256(raw).hexdigest()}
        if receipt not in result['lockfiles']:
            result['lockfiles'].append(receipt)
        for framework, deps in doc['dependencies'].items():
            if not isinstance(deps, dict):
                refuse(project, 'a target framework has no package object')
                continue
            for name, entry in deps.items():
                if isinstance(entry, dict) and entry.get('type') == 'Project':
                    continue
                v = version(entry.get('resolved')) if isinstance(entry, dict) else ''
                try:
                    digest = base64.b64decode(entry.get('contentHash', ''), validate=True) if isinstance(entry, dict) else b''
                except (TypeError, ValueError):
                    digest = b''
                if not _ID.fullmatch(name) or not re.search('[A-Za-z0-9]', name) or not v or len(digest) != 64 or \
                        entry.get('type') not in ('Direct', 'Transitive', 'CentralTransitive'):
                    refuse(name, 'package needs a safe id, resolved version and base64 sha512 contentHash')
                    continue
                key = name.lower(), v
                hashes.setdefault(key, set()).add(digest.hex())
                artifacts.setdefault(key, {'ecosystem': 'nuget', 'package': name.lower(), 'version': v,
                                           'filename': '%s.%s.nupkg' % key, 'sha512': digest.hex()})
    for key, artifact in sorted(artifacts.items()):
        if len(hashes[key]) != 1:
            refuse(artifact['package'], 'conflicting content hashes for the same id/version')
        else:
            result['artifacts'].append(artifact)
    if len(result['artifacts']) > A.MAX_ARTIFACTS:
        refuse('NuGet', 'too many pinned NuGet packages')
        result['artifacts'] = []
    if result['lockfiles']:
        first = result['lockfiles'][0]
        result['lockfile'], result['lockfile_sha256'] = first['path'], first['sha256']
    return result


def acquire(plan: Dict[str, Any], origins: Any, feed: str, budget: int, stream: Any) -> Dict[str, Any]:
    import jh_acquire as A
    os.makedirs(feed)
    result: Dict[str, Any] = {'fetched': [], 'refused': list(plan['refused']), 'bytes': 0, 'downloaded': 0,
                              'pinned': len(plan['artifacts'])}
    for artifact in plan['artifacts']:
        errors = []
        dest = os.path.join(feed, artifact['package'], artifact['version'], artifact['filename'])
        for origin in origins:
            room = budget - result['downloaded']
            if room <= 0:
                errors.append('not fetched: the download budget is spent')
                break
            scheme, host, port, path = origin
            authority = '[%s]' % host if ':' in host else host
            base = '%s://%s:%d%s' % (scheme, authority, port, path)
            url = base + 'v3-flatcontainer/%s/%s/%s' % (artifact['package'], artifact['version'], artifact['filename'])
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            try:
                size, used = A.fetch(dict(artifact, url=url), origins, dest, min(A.MAX_ARTIFACT_BYTES, room), stream)
            except A.AcquireError as exc:
                result['downloaded'] += getattr(exc, 'received', 0)
                errors.append(str(exc))
                continue
            result['downloaded'] += used
            result['bytes'] += size
            result['fetched'].append({k: sanitize_text(artifact[k]) for k in ('package', 'version', 'filename')} |
                                     {'ecosystem': 'nuget', 'sha512': artifact['sha512'], 'bytes': size})
            os.chmod(dest, 0o644)
            break
        if errors and not os.path.isfile(dest):
            result['refused'].append({'package': sanitize_text(artifact['package']),
                                       'reason': sanitize_text(errors[-1])})
    return result
