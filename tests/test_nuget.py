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

    def test_missing_lock_unlocked_conditional_and_custom_imports_never_fetch(self):
        cases = [{'app.csproj': PROJECT},
                 {'app.csproj': PROJECT.replace('true', 'false'), 'packages.lock.json': lock()},
                 {'app.csproj': PROJECT.replace('<RestoreLockedMode>', '<RestoreLockedMode Condition="true">'),
                  'packages.lock.json': lock()},
                 {'app.csproj': PROJECT.replace('</Project>', '<Import Project="custom.props"/></Project>'),
                  'packages.lock.json': lock()},
                 {'app.csproj': '<Project><Target Name="x"><PropertyGroup><RestoreLockedMode>true</RestoreLockedMode>'
                                '</PropertyGroup></Target></Project>', 'packages.lock.json': lock()},
                 {'only.sln': 'solution', 'packages.lock.json': lock()}]
        for files in cases:
            with self.subTest(files=files):
                root = self.tree(files)
                with mock.patch.object(A, '_PinnedHTTPS', side_effect=AssertionError('must not fetch')):
                    r = A.run(root, [ORIGIN], os.path.join(self.tree(), 'out'))
                self.assertEqual((r['state'], r['counts']['fetched']), ('partial', 0))
                self.assertTrue(r['refused'])

    def test_directory_props_are_inherited_and_project_false_wins(self):
        props = '<Project><PropertyGroup><RestoreLockedMode>true</RestoreLockedMode></PropertyGroup></Project>'
        root = self.tree({'Directory.Build.props': props, 'src/app.csproj': '<Project/>', 'src/packages.lock.json': lock()})
        self.assertEqual(len(N.plan(root)['artifacts']), 1)
        Path(root, 'src/app.csproj').write_text(PROJECT.replace('true', 'false'))
        self.assertEqual(N.plan(root)['artifacts'], [])

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
        self.assertEqual(Path(r['nuget_cache'], 'demo.lib', '1.2.3', 'demo.lib.1.2.3.nupkg').read_bytes(), DATA)
        self.assertGreater(r['counts']['downloaded'], r['counts']['bytes'])
        self.assertIsNone(r['cache'])
        self.assertNotIn('nuget_cache', A.summary(r))
        self.assertEqual(r['fetched'][0]['sha512'], hashlib.sha512(DATA).hexdigest())

    def test_hierarchical_feed_separates_ambiguous_basenames(self):
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock({'A.1': pin(DATA, '2.3.4'),
                          'A': pin(b'other', '1.2.3.4')})})
        routes = {'/v3-flatcontainer/a.1/2.3.4/a.1.2.3.4.nupkg': (200, DATA),
                  '/v3-flatcontainer/a/1.2.3.4/a.1.2.3.4.nupkg': (200, b'other')}
        with self.server(routes):
            r = A.run(root, [ORIGIN], os.path.join(self.tree(), 'out'))
        self.assertEqual((r['state'], r['counts']['fetched']), ('complete', 2))
        self.assertEqual(len(list(Path(r['nuget_cache']).rglob('*.nupkg'))), 2)

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
            self.assertTrue(Path(kw['nuget_cache'], 'demo.lib', '1.2.3', 'demo.lib.1.2.3.nupkg').is_file())
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
        # Fixed SHA512 published by NuGet's catalog (no registry metadata is trusted at test time):
        # https://api.nuget.org/v3/catalog0/data/2023.03.08.07.46.17/newtonsoft.json.13.0.3.json
        digest = 'mbJSvHfRxfX3tR/U6n1WU+mWHXswYc+SB/hkOpx8yZZe68hNZGfymJu0cjsaJEkVzCMqePiU6LdIyogqfIn7kg=='
        root = self.tree({'app.csproj': PROJECT, 'packages.lock.json': lock({'Newtonsoft.Json': dict(pin(),
                         resolved='13.0.3', contentHash=digest)})})
        r = A.run(root, [origin], os.path.join(self.tree(), 'out'))
        self.assertEqual((r['state'], r['counts']['fetched']), ('complete', 1), r['refused'])


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


if __name__ == '__main__':
    unittest.main()
