"""NuGet --fetch and .NET restore/build: offline fixture HTTP, hostile inputs and mocked engines.
Live acquisition/sandbox checks are explicitly gated. No downloaded archive or MSBuild executes on the host.
"""
import base64
import contextlib
import hashlib
import importlib.machinery
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import unittest
import zipfile
from unittest import mock

import _util
import jh_acquire as A
import jh_nuget as N
import jh_sandbox as S
from test_pyfetch import Base

ORIGIN = 'https://nuget.example.invalid/'
DATA = b'invented nupkg bytes; never opened on the host'
PROJECT = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework>' \
          '<RestoreLockedMode>true</RestoreLockedMode></PropertyGroup></Project>'


def pin(data=DATA, version='1.2.3', kind='Direct'):
    return {'type': kind, 'requested': '[%s, )' % version, 'resolved': version,
            'contentHash': base64.b64encode(hashlib.sha512(data).digest()).decode()}


def lock(entries=None, version=1):
    return json.dumps({'version': version, 'dependencies': {'net10.0': entries or {'Demo.Lib': pin()}}})


class Planning(Base):
    def test_v1_v2_frameworks_projects_and_normalized_versions(self):
        for v in (1, 2):
            doc = json.loads(lock(version=v))
            doc['dependencies']['net10.0/linux-x64'] = {'DEMO.LIB': pin(), 'Other.Project': {'type': 'Project'}}
            root = self.tree({'src/app.csproj': PROJECT, 'src/packages.lock.json': json.dumps(doc)})
            p = N.plan(root)
            self.assertEqual(p['refused'], [])
            self.assertEqual([(a['package'], a['version'], a['filename']) for a in p['artifacts']],
                             [('demo.lib', '1.2.3', 'demo.lib.1.2.3.nupkg')])
            self.assertEqual(p['lockfiles'][0]['sha256'], hashlib.sha256(json.dumps(doc).encode()).hexdigest())
        for text, expected in [('01.02.003.0+build', '1.2.3'), ('1.2', '1.2.0'), ('1.2.3.4-RC.1', '1.2.3.4-rc.1')]:
            self.assertEqual(N.version(text), expected)
        for text in ['../1', '1.2/3', '1.*', 'https://evil.invalid', '1.2%2f3', '-p:Exec=x']:
            self.assertEqual(N.version(text), '')

    def test_lock_settings_restore_would_not_honour_never_fetch(self):
        local = '<Project TreatAsLocalProperty="Foo;RestoreLockedMode"><PropertyGroup>' \
                '<RestoreLockedMode>false</RestoreLockedMode></PropertyGroup></Project>'
        force = '<Project TreatAsLocalProperty="RestoreForceEvaluate"><PropertyGroup>' \
                '<RestoreForceEvaluate>true</RestoreForceEvaluate></PropertyGroup></Project>'
        cases = [{'app.csproj': PROJECT},                                     # no lock beside the project
                 {'app.csproj': local, 'packages.lock.json': lock()},
                 {'app.csproj': force, 'packages.lock.json': lock()},
                 {'app.csproj': PROJECT.replace('</PropertyGroup>', '<NuGetLockFilePath>other.json</NuGetLockFilePath>'
                                                '</PropertyGroup>'), 'packages.lock.json': lock()},
                 {'app.csproj': PROJECT.replace('</PropertyGroup>', '<NuGetLockFilePath>$(Dir)x.json</NuGetLockFilePath>'
                                                '</PropertyGroup>'), 'packages.lock.json': lock()},
                 {'app.csproj': PROJECT.replace('</PropertyGroup>', '<RestorePackagesWithLockFile>false'
                                                '</RestorePackagesWithLockFile></PropertyGroup>'),
                  'packages.lock.json': lock()},
                 {'Directory.Build.props': '<Project><PropertyGroup><NuGetLockFilePath>a.json</NuGetLockFilePath>'
                                           '</PropertyGroup></Project>',
                  'src/app.csproj': '<Project/>', 'src/packages.lock.json': lock()},
                 {'only.sln': 'solution', 'packages.lock.json': lock()}]
        for files in cases:
            with self.subTest(files=files):
                root = self.tree(files)
                with mock.patch.object(A, '_PinnedHTTPS', side_effect=AssertionError('must not fetch')):
                    r = A.run(root, [ORIGIN], os.path.join(self.tree(), 'out'))
                self.assertEqual((r['state'], r['counts']['fetched']), ('partial', 0))
                self.assertTrue(r['refused'])
                # the plan itself authorizes nothing (a fetch error would also leave the run partial)
                self.assertEqual(N.plan(root)['artifacts'], [])

    def test_documented_lock_setups_fetch_because_restore_forces_locked_mode(self):
        # Microsoft's documented forms: the lock opt-in alone, and locked mode only in CI. The sandbox's
        # --locked-mode is a global property, so neither a missing, false, conditional, imported nor
        # target-level RestoreLockedMode can loosen the restore.
        optin = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><TargetFramework>net10.0</TargetFramework>' \
                '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile>%s</PropertyGroup>%s</Project>'
        for extra, tail in [('', ''),
                            ('<RestoreLockedMode Condition="\'$(ContinuousIntegrationBuild)\' == \'true\'">true'
                             '</RestoreLockedMode>', ''),
                            ('<RestoreLockedMode>false</RestoreLockedMode>', ''),
                            ('', '<Import Project="custom.props"/>'),
                            ('', '<Target Name="x"><PropertyGroup><RestoreLockedMode>false</RestoreLockedMode>'
                                 '</PropertyGroup></Target>')]:
            with self.subTest(extra=extra, tail=tail):
                root = self.tree({'app.csproj': optin % (extra, tail), 'packages.lock.json': lock()})
                p = N.plan(root)
                self.assertEqual((p['refused'], len(p['artifacts'])), ([], 1))
        root = self.tree({'Directory.Build.props': '<Project/>', 'src/app.csproj': '<Project/>',
                          'src/packages.lock.json': lock()})
        self.assertEqual(len(N.plan(root)['artifacts']), 1)

    def test_hostile_json_xml_names_hashes_and_conflicts_are_refused(self):
        bad = [dict(pin(), resolved='../../escape'), dict(pin(), contentHash='not base64'),
               dict(pin(), contentHash=base64.b64encode(b'short').decode()), {'type': 'Direct'}]
        for entry in bad:
            root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock({'Demo.Lib': entry})})
            self.assertEqual(N.plan(root)['artifacts'], [])
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock({'../outside': pin()})})
        self.assertEqual(N.plan(root)['artifacts'], [])
        for text in ['[]', '{"version":1,"version":2}', '{"version":3,"dependencies":{}}',
                     '{"version":1,"dependencies":' + '[' * 1200 + ']' * 1200 + '}']:
            self.assertTrue(N.plan(self.tree({'app.csproj': PROJECT, 'packages.lock.json': text}))['refused'])
        for xml in ['<!DOCTYPE Project [<!ENTITY x "yes">]><Project>&x;</Project>', '<Project>', '\xff']:
            self.assertTrue(N.plan(self.tree({'app.csproj': xml, 'packages.lock.json': lock()}))['refused'])
        root = self.tree({'a/a.csproj': PROJECT, 'a/packages.lock.json': lock(), 'b/b.csproj': PROJECT,
                          'b/packages.lock.json': lock({'demo.lib': pin(b'other')})})
        p = N.plan(root)
        self.assertEqual(p['artifacts'], [])
        self.assertIn('conflicting', p['refused'][0]['reason'])

    def test_links_fifos_bounds_and_parent_links_are_not_read(self):
        root = self.tree({'app.csproj': PROJECT})
        outside = self.tree({'packages.lock.json': lock()})
        os.symlink(os.path.join(outside, 'packages.lock.json'), os.path.join(root, 'packages.lock.json'))
        self.assertTrue(N.plan(root)['refused'])
        with self.assertRaises(N.PlanError):
            N._read(root, 'packages.lock.json', 10000)
        os.unlink(os.path.join(root, 'packages.lock.json'))
        os.mkfifo(os.path.join(root, 'packages.lock.json'))
        self.assertTrue(N.plan(root)['refused'])
        os.symlink(outside, os.path.join(root, 'link'))
        with self.assertRaises(N.PlanError):
            N._read(root, 'link/packages.lock.json', 10000)
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock()})
        with mock.patch.object(A, 'MAX_LOCK_BYTES', 20):
            self.assertTrue(N.plan(root)['refused'])
        with mock.patch.object(N, 'MAX_ENTRIES', 1):
            self.assertTrue(N.discover(root)['issues'])


class Acquisition(Base):
    PATH = '/v3-flatcontainer/demo.lib/1.2.3/demo.lib.1.2.3.nupkg'

    def acquire(self, **kw):
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock()})
        return A.run(root, [ORIGIN], os.path.join(self.tree(), 'out'), **kw)

    def test_verified_folder_feed_without_any_host_archive_or_package_manager(self):
        with self.server({self.PATH: (200, DATA)}) as calls, \
                mock.patch('subprocess.run', side_effect=AssertionError('no host commands')):
            r = self.acquire()
        self.assertEqual((r['state'], r['counts']['fetched'], len(calls)), ('complete', 1, 1))
        self.assertEqual(Path(r['nuget_cache'], 'demo.lib', 'demo.lib.1.2.3.nupkg').read_bytes(), DATA)
        self.assertGreater(r['counts']['downloaded'], r['counts']['bytes'])
        self.assertIsNone(r['cache'])
        self.assertNotIn('nuget_cache', A.summary(r))
        self.assertEqual(r['fetched'][0]['sha512'], hashlib.sha512(DATA).hexdigest())

    @staticmethod
    def zipped(entries, appended=()):
        """An archive, then the same archive with entries appended the way NuGet's repository signing appends
        .signature.p7s: a new last local entry and a rewritten central directory."""
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            for name, data in entries:
                z.writestr(name, data)
        unsigned = buf.getvalue()
        with zipfile.ZipFile(buf, 'a') as z:
            for name, data in appended:
                z.writestr(name, data)
        return unsigned, buf.getvalue()

    def test_repository_signed_package_matches_lock_without_its_signature(self):
        # nuget.org signs every package; packages.lock.json pins the hash of the archive before signing
        unsigned, signed = self.zipped([('demo.nuspec', '<package/>'), ('lib/net10.0/Demo.dll', 'code')],
                                       [('.signature.p7s', 'pkcs7')])
        self.assertNotEqual(signed, unsigned)
        self.assertEqual(N.signed_content_hash(signed), hashlib.sha512(unsigned).hexdigest())
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock({'Demo.Lib': pin(unsigned)})})
        with self.server({self.PATH: (200, signed)}):
            r = A.run(root, [ORIGIN], os.path.join(self.tree(), 'out'))
        self.assertEqual((r['state'], r['counts']['fetched']), ('complete', 1))
        self.assertEqual(Path(r['nuget_cache'], 'demo.lib', 'demo.lib.1.2.3.nupkg').read_bytes(), signed)
        # tampered content, a non-signature last entry, a signature placed before content, a second signature
        tampered = signed.replace(b'code', b'evil')
        _, extra = self.zipped([('demo.nuspec', '<package/>'), ('lib/net10.0/Demo.dll', 'code')],
                               [('lib/net10.0/Evil.dll', 'evil')])
        _, early = self.zipped([('.signature.p7s', 'pkcs7'), ('demo.nuspec', '<package/>')],
                               [('lib/net10.0/Demo.dll', 'code')])
        _, twice = self.zipped([('demo.nuspec', '<package/>'), ('lib/net10.0/Demo.dll', 'code'),
                                ('.SIGNATURE.P7S', 'x')], [('.signature.p7s', 'pkcs7')])
        for body in (tampered, extra, early, twice, signed + b'trailing', signed[:-30], b'PK\x05\x06' + b'\0' * 18):
            with self.subTest(body=body[-40:]):
                self.assertNotEqual(N.signed_content_hash(body), hashlib.sha512(unsigned).hexdigest())
                with self.server({self.PATH: (200, body)}):
                    r = A.run(root, [ORIGIN], os.path.join(self.tree(), 'out'))
                self.assertEqual(r['counts']['fetched'], 0)
        self.assertEqual(N.signed_content_hash(early), '')
        # the same archive with its directory reordered so the signature is listed last but stored first
        import struct
        i = early.rfind(b'PK\x05\x06')
        cd_off = struct.unpack('<I', early[i + 16:i + 20])[0]
        records, p = [], cd_off
        while p < i:
            n, e, c = struct.unpack('<HHH', early[p + 28:p + 34])
            records.append(early[p:p + 46 + n + e + c]); p += 46 + n + e + c
        listed_last = early[:cd_off] + b''.join(records[1:] + records[:1]) + early[i:]
        self.assertEqual(N.signed_content_hash(listed_last), '')
        # the signature stored last but listed anywhere in the directory: NuGet removes it by index, so the hash is
        # NuGet's own (GetPackageContentHash in the .NET 10.0.403 SDK, on this exact archive)
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, 'w') as z:
            for name, body in (('x.nuspec', b'<package/>'), ('lib/a.dll', b'fake')):
                z.writestr(zipfile.ZipInfo(name), body)
        with zipfile.ZipFile(buf, 'a') as z:
            z.writestr(zipfile.ZipInfo('.signature.p7s'), b'synthetic-signature')
        normal = buf.getvalue()
        i = normal.rfind(b'PK\x05\x06')
        cd_off = struct.unpack('<I', normal[i + 16:i + 20])[0]
        records, p = [], cd_off
        while p < i:
            n, e, c = struct.unpack('<HHH', normal[p + 28:p + 34])
            records.append(normal[p:p + 46 + n + e + c]); p += 46 + n + e + c
        reversed_cd = normal[:cd_off] + b''.join(reversed(records)) + normal[i:]
        self.assertEqual(N.signed_content_hash(normal), '265608cb40fd4ef699afa4ccc74db62ff95f15409c5b795de25ed8aac4807b5b'
                                                        '295c417f2953ba9a83be64c573d64adb026c0596aa0088f1e183bbcaf9fe8972')
        self.assertEqual(N.signed_content_hash(reversed_cd), '200a06d2d50927b4c7dce9840480862537f5a00e2edf65998ffd74109b02b1f4'
                                                             '662a9d84e1548d2e7b62c497631a0c2f3267443705ccc11f532a62f2d482e1d7')
        # the signature allowance is NuGet's alone: an npm tarball must match its integrity byte for byte
        part = os.path.join(self.tree(), 'x.part')
        Path(part).write_bytes(signed)
        artifact = {'sha512': hashlib.sha512(unsigned).hexdigest()}
        self.assertTrue(A._nuget_signed(dict(artifact, ecosystem='nuget'), part))
        self.assertFalse(A._nuget_signed(dict(artifact, ecosystem='npm'), part))
        self.assertFalse(A._nuget_signed(artifact, part))

    def test_id_folder_feed_separates_ambiguous_basenames(self):
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock({'A.1': pin(DATA, '2.3.4'),
                          'A': pin(b'other', '1.2.3.4')})})
        routes = {'/v3-flatcontainer/a.1/2.3.4/a.1.2.3.4.nupkg': (200, DATA),
                  '/v3-flatcontainer/a/1.2.3.4/a.1.2.3.4.nupkg': (200, b'other')}
        with self.server(routes):
            r = A.run(root, [ORIGIN], os.path.join(self.tree(), 'out'))
        self.assertEqual((r['state'], r['counts']['fetched']), ('complete', 2))
        self.assertEqual(sorted(str(p.relative_to(r['nuget_cache'])) for p in Path(r['nuget_cache']).rglob('*.nupkg')),
                         ['a.1/a.1.2.3.4.nupkg', 'a/a.1.2.3.4.nupkg'])

    def test_tamper_redirect_size_limits_private_dns_and_cleanup(self):
        for response, why in [((200, b'tampered'), 'do not match'),
                               ((302, b'', {'Location': 'https://evil.invalid/a'}), 'redirects are refused')]:
            with self.server({self.PATH: response}) as calls:
                r = self.acquire()
            self.assertEqual((r['state'], len(calls)), ('partial', 1))
            self.assertIn(why, r['refused'][0]['reason'])
            self.assertFalse(any(p.is_file() for p in Path(r['nuget_cache']).rglob('*')))
            self.assertGreater(r['counts']['downloaded'], 0)
        with self.server({self.PATH: (200, DATA)}), mock.patch.object(A, 'MAX_ARTIFACT_BYTES', 16):
            r = self.acquire()
        self.assertEqual((r['state'], r['counts']['downloaded']), ('partial', 16))
        with mock.patch.object(A.socket, 'getaddrinfo', return_value=[(0,0,0,'',('127.0.0.1',443))]), \
                mock.patch.object(A, '_PinnedHTTPS', side_effect=AssertionError('must not connect')):
            r = self.acquire()
        self.assertIn('no public address', r['refused'][0]['reason'])

    def test_approved_prefix_and_shared_python_npm_nuget_budget(self):
        origins = A.parse_origins([ORIGIN + 'mirror/'])
        p = N.plan(self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock()}))
        seen = []
        def stream(url, limit, usage):
            seen.append(url)
            usage['received'] = len(DATA)
            yield DATA
        result = N.acquire(p, origins, os.path.join(self.tree(), 'feed'), len(DATA), stream)
        self.assertEqual(result['downloaded'], len(DATA))
        self.assertEqual(seen, [ORIGIN[:-1] + ':443/mirror' + self.PATH])
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock(), 'requirements.txt':
                          'demo==1.0 --hash=sha256:' + hashlib.sha256(b'wheel').hexdigest()})
        def index_stream(url, limit, usage):
            usage['received'] = limit
            raise A.AcquireError('index failed')
            yield b''
        with mock.patch.object(A, 'MAX_TOTAL_BYTES', 128), \
                mock.patch.object(A, '_PinnedHTTPS', side_effect=AssertionError('NuGet must spend no more')):
            r = A.run(root, [ORIGIN], os.path.join(self.tree(), 'out'), index_stream=index_stream)
        self.assertEqual(r['counts']['downloaded'], 128)
        self.assertEqual(r['counts']['fetched'], 0)
        self.assertTrue(any('budget is spent' in x['reason'] for x in r['refused']))


class Sandbox(Base):
    def test_restore_and_build_are_quoted_install_steps_and_feed_is_read_only(self):
        name = '-bad; touch owned.csproj'
        root = self.tree({name: PROJECT})
        steps, gaps = S.plan_steps(root, ('install',), ('nuget',))
        self.assertEqual([s['surface'] for s in steps], ['install', 'install'])
        self.assertEqual(shlex.split(steps[0]['script'])[-1], './' + name)
        self.assertIn('--locked-mode --source /cache/nuget', steps[0]['script'])
        self.assertIn('-p:RestoreForceEvaluate=false', steps[0]['script'])   # NU1512: it overrides locked mode
        # only the verified feed: a sandbox-owned config, and no project fallback folders or extra sources
        for flag in ('--configfile /jh/nuget.config', '-p:RestoreFallbackFolders=/tmp/jh-nofallback',
                     '-p:RestoreAdditionalProjectSources= ', '-p:RestoreAdditionalProjectFallbackFolders='):
            self.assertIn(flag, steps[0]['script'])
        self.assertIn('<fallbackPackageFolders><clear/></fallbackPackageFolders>', S.NUGET_CONFIG)
        self.assertIn('--no-restore', steps[1]['script'])
        argv = S.container_argv('podman', 'img', '/tmp/run', '/src', ('nuget',))
        self.assertIn('/tmp/run/cache/nuget:/cache/nuget:ro,Z', argv)
        for setting in ['DOTNET_CLI_TELEMETRY_OPTOUT=1', 'DOTNET_NOLOGO=1', 'NUGET_XMLDOC_MODE=skip']:
            self.assertIn(setting, argv)
        self.assertIn('--network=none', argv)
        self.assertIn('/home/canary/.dotnet:rw,size=64m,mode=1777', argv)
        self.assertIn('/tmp/run/home:/home/canary:ro,Z', argv)
        self.assertTrue(S.plan_steps(root, ('install',))[1])
        self.assertEqual(S.plan_steps(root, ('install',), ('nuget',), dotnet_ready=False)[0], [])

    def test_image_selected_only_for_dotnet_and_when_present(self):
        root = self.tree({'app.csproj': PROJECT})
        present = {S.DEFAULT_IMAGE}
        def process(argv, **kw):
            return subprocess.CompletedProcess(argv, 0 if argv[-1] in present else 1, 'id', '')
        with mock.patch.object(S, 'find_engine', return_value='podman'), mock.patch.object(S.subprocess, 'run', process):
            self.assertEqual(S.resolve_image(None, S.DEFAULT_IMAGE, root), S.DEFAULT_IMAGE)
            present.add(S.DOTNET_IMAGE)
            self.assertEqual(S.resolve_image(None, S.DEFAULT_IMAGE, root), S.DOTNET_IMAGE)
            self.assertEqual(S.resolve_image(None, S.DEFAULT_IMAGE, self.tree()), S.DEFAULT_IMAGE)
            self.assertEqual(S.resolve_image(None, 'custom', root), 'custom')

    def test_missing_sdk_or_engine_reports_a_coverage_gap(self):
        root = self.tree({'app.csproj': PROJECT})
        with mock.patch.object(S, 'find_engine', return_value=None):
            r = S.run(root)
        self.assertEqual((r['coverage']['state'], r['steps']), ('partial', []))
        self.assertTrue(any('SDK image' in g for g in r['coverage']['gaps']))
        self.assertEqual(r['counts'], {'ALERT': 0, 'DENY': 0})

    def test_cli_hands_feed_on_and_removes_fetch_workdir(self):
        loader = importlib.machinery.SourceFileLoader('nuget_cli', _util.CLI)
        cli = importlib.util.module_from_spec(importlib.util.spec_from_loader('nuget_cli', loader))
        loader.exec_module(cli)
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock()})
        seen = {}
        def run(path, **kw):
            seen['feed'] = kw['nuget_cache']
            self.assertTrue(Path(kw['nuget_cache'], 'demo.lib', 'demo.lib.1.2.3.nupkg').is_file())
            return {'coverage': {'state':'complete','gaps':[]}, 'counts':{'ALERT':0}}
        args = cli.build_parser().parse_args(['sandbox', root, '--fetch', ORIGIN, '--json'])
        with self.server({Acquisition.PATH:(200, DATA)}), mock.patch.object(S, 'resolve_image', return_value=S.DOTNET_IMAGE), \
                mock.patch.object(S, 'run', run), contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(cli.cmd_sandbox(args), 0)
        self.assertEqual(json.loads(out.getvalue())['fetch']['state'], 'complete')
        self.assertFalse(os.path.exists(os.path.dirname(seen['feed'])))
        args = cli.build_parser().parse_args(['sandbox', root, '--fetch', ORIGIN, '--nuget-cache', self.tree()])
        with mock.patch.object(A, 'run', side_effect=AssertionError('must not fetch')), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(cli.cmd_sandbox(args), 2)


@unittest.skipUnless(os.environ.get('JH_ACQUIRE_LIVE') == '1', 'set JH_ACQUIRE_LIVE=1 for public NuGet acquisition')
class LiveAcquire(Base):
    def test_public_flat_container(self):
        origin = 'https://api.nuget.org/'
        path = 'v3-flatcontainer/newtonsoft.json/13.0.3/newtonsoft.json.13.0.3.nupkg'
        # The contentHash real packages.lock.json files pin for this package: the archive before nuget.org's
        # repository signature. (The catalog's packageHash is of the signed file, which no lock file holds.)
        digest = 'HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ=='
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock({'Newtonsoft.Json': dict(pin(),
                         resolved='13.0.3', contentHash=digest)})})
        r = A.run(root, [origin], os.path.join(self.tree(), 'out'))
        self.assertEqual((r['state'], r['counts']['fetched']), ('complete', 1), r['refused'])

    @unittest.skipUnless(os.environ.get('JH_SANDBOX_LIVE') == '1' and shutil.which('podman'),
                         'also set JH_SANDBOX_LIVE=1 with podman and the dotnet runner image')
    def test_fetched_feed_restores_and_builds_offline(self):
        # End to end on the fetched feed itself: the layout restore must find, offline, in locked mode.
        digest = 'HrC5BXdl00IP9zeV+0Z848QWPAoCr9P3bDEZguI+gkLcBKAOxix/tLEAAHC+UvDNPv4a2d18lOReHMOagPa+zQ=='
        project = '<Project Sdk="Microsoft.NET.Sdk"><PropertyGroup><OutputType>Exe</OutputType>' \
                  '<TargetFramework>net10.0</TargetFramework>' \
                  '<RestorePackagesWithLockFile>true</RestorePackagesWithLockFile></PropertyGroup><ItemGroup>' \
                  '<PackageReference Include="Newtonsoft.Json" Version="13.0.3"/></ItemGroup></Project>'
        root = self.tree({'app.csproj': project, 'Program.cs': 'System.Console.WriteLine(Newtonsoft.Json.JsonConvert.True);',
                          'packages.lock.json': lock({'Newtonsoft.Json': dict(pin(version='13.0.3'), contentHash=digest)})})
        r = A.run(root, ['https://api.nuget.org/'], os.path.join(self.tree(), 'out'))
        self.assertEqual(r['state'], 'complete', r['refused'])
        s = S.run(root, surfaces=('install',), nuget_cache=r['nuget_cache'], timeout=300)
        self.assertEqual([x['exit'] for x in s['steps']], ['0', '0'], s['coverage'])


@unittest.skipUnless(os.environ.get('JH_SANDBOX_LIVE') == '1' and shutil.which('podman'),
                     'set JH_SANDBOX_LIVE=1 with podman and the dotnet runner image')
class LiveSandbox(Base):
    def test_package_build_target_reads_canary(self):
        # The only archive created on the host is this invented fixture. Downloaded archives are never opened.
        import zipfile
        feed = self.tree()
        package = Path(feed, 'jh.canary.target.1.0.0.nupkg')
        target = '<Project><Target Name="CanaryProbe" BeforeTargets="Build"><Exec Command="cat /home/canary/.aws/credentials &gt; /dev/null" /></Target></Project>'
        with zipfile.ZipFile(package, 'w') as z:
            z.writestr('jh.canary.target.nuspec', '<package><metadata><id>jh.canary.target</id><version>1.0.0</version>'
                       '<authors>fixture</authors><description>inert canary test</description></metadata></package>')
            z.writestr('build/jh.canary.target.targets', target)
        root = self.tree({'app.csproj': PROJECT.replace('</Project>', '<ItemGroup><PackageReference Include="jh.canary.target" Version="1.0.0"/></ItemGroup></Project>'),
                          'packages.lock.json': lock({'jh.canary.target': pin(package.read_bytes(), '1.0.0')})})
        r = S.run(root, surfaces=('install',), nuget_cache=feed, timeout=120)
        self.assertEqual(r['image'], S.DOTNET_IMAGE)
        self.assertEqual([s['exit'] for s in r['steps']], ['0','0'], r)
        self.assertTrue(any(e['kind']=='canary-read' and 'dotnet build' in e['step'] for e in r['events']), r['events'])
        for c in r['canaries']:
            self.assertNotIn('values', c)

    def test_repository_fallback_folder_cannot_replace_the_verified_package(self):
        # Codex's reproduction: an expanded package folder in the repository, named by its nuget.config, is used
        # without a content-hash check. Here it carries a build target that reads a canary; the feed holds the
        # benign package the lock pins. Only the feed may be used.
        import zipfile
        feed = self.tree()
        os.makedirs(os.path.join(feed, 'jh.canary.target'))
        package = Path(feed, 'jh.canary.target', 'jh.canary.target.1.0.0.nupkg')
        nuspec = ('<package><metadata><id>jh.canary.target</id><version>1.0.0</version><authors>fixture</authors>'
                  '<description>benign</description></metadata></package>')
        with zipfile.ZipFile(package, 'w') as z:
            z.writestr('jh.canary.target.nuspec', nuspec)
        digest = base64.b64encode(hashlib.sha512(package.read_bytes()).digest()).decode()
        poisoned = 'fb/jh.canary.target/1.0.0/'
        target = ('<Project><Target Name="CanaryProbe" BeforeTargets="Build"><Exec Command="cat '
                  '/home/canary/.aws/credentials &gt; /dev/null" /></Target></Project>')
        root = self.tree({
            'app.csproj': PROJECT.replace('</Project>', '<ItemGroup><PackageReference Include="jh.canary.target" '
                                          'Version="1.0.0"/></ItemGroup></Project>'),
            'packages.lock.json': lock({'jh.canary.target': pin(package.read_bytes(), '1.0.0')}),
            'nuget.config': '<configuration><fallbackPackageFolders><add key="fb" value="fb"/>'
                            '</fallbackPackageFolders></configuration>',
            poisoned + 'jh.canary.target.1.0.0.nupkg': package.read_bytes(),
            poisoned + 'jh.canary.target.1.0.0.nupkg.sha512': digest,
            poisoned + 'jh.canary.target.nuspec': nuspec,
            poisoned + '.nupkg.metadata': json.dumps({'version': 2, 'contentHash': digest, 'source': None}),
            poisoned + 'build/jh.canary.target.targets': target})
        r = S.run(root, surfaces=('install',), nuget_cache=feed, timeout=120)
        self.assertEqual([s['exit'] for s in r['steps']], ['0', '0'], r['coverage'])
        self.assertFalse([e for e in r['events'] if e['kind'] == 'canary-read'], r['events'])


if __name__ == '__main__':
    unittest.main()
