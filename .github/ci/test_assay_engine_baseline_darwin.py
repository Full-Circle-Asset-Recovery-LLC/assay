"""Offline fixtures for the exact Darwin baseline installer; no native execution.

The repository's historical attestation stays untouched. Synthetic artifact bytes
and their matching in-memory metadata exercise the same validation/install path.
"""
from __future__ import annotations

import contextlib
import copy
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import stat
import struct
import subprocess
import sys
import tempfile
import unittest
from unittest import mock
import urllib.error

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
MANIFEST_BYTES = (HERE / 'assay-engine-v0.5.15-darwin-aarch64.json').read_bytes()
SPEC = importlib.util.spec_from_file_location(
    'darwin_baseline_installer', HERE / 'install-assay-engine-baseline-darwin.py'
)
INSTALLER = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(INSTALLER)
REAL_DOWNLOAD = INSTALLER.download


class DarwinBaselineTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.destination = Path(directory.name, 'baseline')
        self.installed = self.destination / 'assay-engine-v0.5.15'
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.reset_fixture()
        patches = [
            mock.patch.object(INSTALLER.platform, 'system', return_value='Darwin'),
            mock.patch.object(INSTALLER.platform, 'machine', return_value='arm64'),
            mock.patch.object(sys, 'argv', [str(HERE / 'installer.py'), str(self.destination)]),
            mock.patch.object(INSTALLER.Path, 'read_text', side_effect=lambda *a, **k: json.dumps(self.manifest)),
            mock.patch.object(INSTALLER, 'github_json', side_effect=self.lookup),
            mock.patch.object(INSTALLER, 'download', side_effect=lambda *a: self.payload),
            mock.patch.object(INSTALLER.subprocess, 'run', return_value=subprocess.CompletedProcess([], 0, 'assay-engine 0.5.15\n')),
            contextlib.redirect_stdout(self.stdout),
            contextlib.redirect_stderr(self.stderr),
        ]
        stack = contextlib.ExitStack()
        self.addCleanup(stack.close)
        entered = [stack.enter_context(p) for p in patches]
        self.json_api, self.download, self.native = entered[4:7]

    def reset_fixture(self):
        self.manifest = json.loads(MANIFEST_BYTES)
        self.payload = struct.pack('<IIII', 0xFEEDFACF, 0x0100000C, 0, 2) + b'fixture'
        artifact = self.manifest['artifact']
        artifact['size_bytes'] = len(self.payload)
        artifact['sha256'] = hashlib.sha256(self.payload).hexdigest()
        distribution = self.manifest['distribution']
        self.api = 'https://api.github.com/repos/' + distribution['repository']
        self.old_tag = distribution['tag_object_sha']
        self.old_commit = self.manifest['source']['commit']
        self.new_tag, self.new_commit, self.tree = '2' * 40, '3' * 40, '1' * 40
        self.urls = {
            'release': f"{self.api}/releases/{distribution['release_id']}",
            'ref': f"{self.api}/git/ref/tags/{distribution['release_tag']}",
            'original_tag': f'{self.api}/git/tags/{self.old_tag}',
            'original_commit': f'{self.api}/git/commits/{self.old_commit}',
            'current_tag': f'{self.api}/git/tags/{self.new_tag}',
            'current_commit': f'{self.api}/git/commits/{self.new_commit}',
        }
        self.responses = {
            self.urls['release']: {
                'id': distribution['release_id'], 'tag_name': distribution['release_tag'],
                'draft': False, 'prerelease': False,
                'assets': [{
                    'id': distribution['asset_id'], 'name': artifact['asset_name'],
                    'size': artifact['size_bytes'], 'digest': 'sha256:' + artifact['sha256'],
                    'browser_download_url': 'https://example.com/pinned-baseline',
                }],
            },
            self.urls['ref']: {
                'ref': 'refs/tags/' + distribution['release_tag'],
                'object': {'type': 'tag', 'sha': self.new_tag},
            },
            self.urls['original_tag']: {
                'sha': self.old_tag, 'tag': distribution['release_tag'],
                'object': {'type': 'commit', 'sha': self.old_commit},
                'verification': {'verified': True, 'reason': 'valid'},
            },
            self.urls['original_commit']: {'sha': self.old_commit, 'tree': {'sha': self.tree}},
            self.urls['current_tag']: {
                'sha': self.new_tag, 'tag': distribution['release_tag'],
                'object': {'type': 'commit', 'sha': self.new_commit},
                'verification': {'verified': False, 'reason': 'unknown_key'},
            },
            self.urls['current_commit']: {'sha': self.new_commit, 'tree': {'sha': self.tree}},
        }
        for name in ['stdout', 'stderr']:
            if hasattr(self, name):
                getattr(self, name).seek(0)
                getattr(self, name).truncate()
        for name in ['json_api', 'download', 'native']:
            if hasattr(self, name):
                getattr(self, name).reset_mock()
                getattr(self, name).side_effect = None
        if hasattr(self, 'json_api'):
            self.json_api.side_effect = self.lookup
            self.download.side_effect = lambda *a: self.payload
            self.native.return_value = subprocess.CompletedProcess([], 0, 'assay-engine 0.5.15\n')

    def lookup(self, url):
        if url not in self.responses:
            raise urllib.error.URLError('unregistered fixture object')
        value = self.responses[url]
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)

    def assert_no_install(self):
        self.assertFalse(self.installed.exists())
        self.assertEqual(self.stdout.getvalue(), '')
        if self.destination.exists():
            self.assertEqual(list(self.destination.iterdir()), [])

    def assert_metadata_rejected(self):
        with self.assertRaises((SystemExit, urllib.error.URLError)):
            INSTALLER.main()
        self.download.assert_not_called()
        self.native.assert_not_called()
        self.assert_no_install()
        self.assertEqual(self.stderr.getvalue(), '')

    def test_same_tree_ref_drift_preserves_original_baseline_and_stdout(self):
        INSTALLER.main()
        self.assertEqual(self.installed.read_bytes(), self.payload)
        self.assertEqual(self.stdout.getvalue(), str(self.installed) + '\n')
        event = json.loads(self.stderr.getvalue())
        self.assertEqual(event['event'], 'SAME_TREE_REF_DRIFT')
        self.assertEqual(event['original_tag_object'], self.old_tag)
        self.assertEqual(event['original_commit'], self.old_commit)
        self.assertEqual(event['current_tag_object'], self.new_tag)
        self.assertEqual(event['current_commit'], self.new_commit)
        self.assertEqual(event['tree'], self.tree)
        self.assertEqual(event['original_verification'], {'verified': True, 'reason': 'valid'})
        self.assertEqual(event['current_verification'], {'verified': False, 'reason': 'unknown_key'})
        self.assertEqual(stat.S_IMODE(self.installed.stat().st_mode), 0o500)
        self.assertEqual(stat.S_IMODE(self.destination.stat().st_mode), 0o700)
        self.native.assert_called_once()
        self.json_api.assert_any_call(self.urls['original_tag'])
        self.json_api.assert_any_call(self.urls['original_commit'])

    def test_original_ref_still_validates_original_commit_without_drift_event(self):
        self.responses[self.urls['ref']]['object']['sha'] = self.old_tag
        INSTALLER.main()
        self.assertEqual(self.stdout.getvalue(), str(self.installed) + '\n')
        self.assertEqual(self.stderr.getvalue(), '')
        self.json_api.assert_any_call(self.urls['original_tag'])
        self.json_api.assert_any_call(self.urls['original_commit'])

    def test_checked_in_attestation_is_byte_identical(self):
        self.assertEqual(hashlib.sha256(MANIFEST_BYTES).hexdigest(),
                         'cfa5f88ea4221fcfb05c6ff2ba9356fa2d17e850fe6999c546cf3f3fa6cc5538')

    def test_missing_malformed_or_wrong_git_identity_is_rejected(self):
        cases = []
        for key in ['original_tag', 'current_tag']:
            for field, values in [
                (('sha',), [None, '', 'z' * 40, '4' * 40]),
                (('tag',), [None, '', 'other-tag']),
                (('object',), [None, [], 'invalid']),
                (('object', 'type'), [None, '', 'tag', 'blob']),
                (('object', 'sha'), [None, '', 'z' * 40, 'a' * 39]),
            ]:
                cases.extend((key, field, value) for value in values)
        for key in ['original_commit', 'current_commit']:
            for field, values in [
                (('sha',), [None, '', 'z' * 40, '4' * 40]),
                (('tree',), [None, [], 'invalid']),
                (('tree', 'sha'), [None, '', 'z' * 40, 'a' * 39, 'A' * 40]),
            ]:
                cases.extend((key, field, value) for value in values)
        for field, values in [
            (('ref',), [None, '', 'refs/tags/other-tag']),
            (('object',), [None, [], 'invalid']),
            (('object', 'type'), [None, '', 'commit', 'blob']),
            (('object', 'sha'), [None, '', 'z' * 40, 'a' * 39]),
        ]:
            cases.extend(('ref', field, value) for value in values)
        for key, field, value in cases:
            with self.subTest(record=key, field=field, value=value):
                self.reset_fixture()
                parent = self.responses[self.urls[key]]
                for component in field[:-1]:
                    parent = parent[component]
                parent[field[-1]] = value
                self.assert_metadata_rejected()
        for key in ['original_tag', 'current_tag', 'original_commit', 'current_commit', 'ref']:
            with self.subTest(record=key, missing=True):
                self.reset_fixture()
                self.responses[self.urls[key]] = None
                self.assert_metadata_rejected()

    def test_original_pinned_commit_and_both_tree_bindings_are_required(self):
        for key, path in [('original_tag', ('object', 'sha')),
                          ('original_commit', ('tree', 'sha')),
                          ('current_commit', ('tree', 'sha'))]:
            with self.subTest(record=key):
                self.reset_fixture()
                parent = self.responses[self.urls[key]][path[0]]
                parent[path[1]] = '4' * 40
                self.assert_metadata_rejected()

    def test_omitted_identity_and_tree_fields_are_not_defaults(self):
        for key, fields in [
            ('original_tag', [('sha',), ('tag',), ('object',), ('object', 'type'), ('object', 'sha')]),
            ('current_tag', [('sha',), ('tag',), ('object',), ('object', 'type'), ('object', 'sha')]),
            ('original_commit', [('sha',), ('tree',), ('tree', 'sha')]),
            ('current_commit', [('sha',), ('tree',), ('tree', 'sha')]),
            ('ref', [('ref',), ('object',), ('object', 'type'), ('object', 'sha')]),
        ]:
            for field in fields:
                with self.subTest(record=key, field=field):
                    self.reset_fixture()
                    parent = self.responses[self.urls[key]]
                    for component in field[:-1]:
                        parent = parent[component]
                    del parent[field[-1]]
                    self.assert_metadata_rejected()

    def test_same_tree_does_not_bypass_an_invalid_original_when_ref_is_unchanged(self):
        self.responses[self.urls['ref']]['object']['sha'] = self.old_tag
        self.responses[self.urls['original_commit']]['tree'] = None
        self.assert_metadata_rejected()

    def test_unchanged_tag_identity_cannot_report_a_different_commit(self):
        self.responses[self.urls['ref']]['object']['sha'] = self.old_tag
        lookups = 0
        def inconsistent_lookup(url):
            nonlocal lookups
            result = self.lookup(url)
            if url == self.urls['original_tag']:
                lookups += 1
                if lookups == 2:
                    result['object']['sha'] = self.new_commit
            return result
        self.json_api.side_effect = inconsistent_lookup
        self.assert_metadata_rejected()

    def test_api_errors_never_fall_back_to_unverified_objects(self):
        for key in self.urls:
            with self.subTest(endpoint=key):
                self.reset_fixture()
                self.responses[self.urls[key]] = urllib.error.URLError('fixture API failure')
                self.assert_metadata_rejected()

    def test_release_and_asset_gates_remain_closed(self):
        changes = [
            (('id',), 0), (('tag_name',), 'other-tag'),
            (('draft',), True), (('draft',), None), (('draft',), 0),
            (('prerelease',), True), (('prerelease',), None), (('prerelease',), 0),
            (('assets',), None), (('assets',), ''), (('assets',), [None]),
            (('assets',), []),
            (('assets', 0, 'id'), 0), (('assets', 0, 'name'), 'other-artifact'),
            (('assets', 0, 'size'), 0), (('assets', 0, 'digest'), 'sha256:' + '0' * 64),
        ]
        for path, value in changes:
            with self.subTest(path=path, value=value):
                self.reset_fixture()
                parent = self.responses[self.urls['release']]
                for component in path[:-1]:
                    parent = parent[component]
                parent[path[-1]] = value
                self.assert_metadata_rejected()
        self.reset_fixture()
        assets = self.responses[self.urls['release']]['assets']
        assets.append(copy.deepcopy(assets[0]))
        self.assert_metadata_rejected()

    def test_bad_payload_length_digest_and_macho_never_reach_execution(self):
        for kind in ['length', 'digest', 'short', 'magic', 'cpu', 'filetype']:
            with self.subTest(kind=kind):
                self.reset_fixture()
                if kind == 'length':
                    self.payload += b'x'
                elif kind == 'digest':
                    self.payload = self.payload[:-1] + b'x'
                else:
                    values = {'magic': (0, 0x0100000C, 0, 2),
                              'cpu': (0xFEEDFACF, 0x01000007, 0, 2),
                              'filetype': (0xFEEDFACF, 0x0100000C, 0, 1)}
                    self.payload = b'short' if kind == 'short' else struct.pack('<IIII', *values[kind])
                    self.manifest['artifact']['size_bytes'] = len(self.payload)
                    self.manifest['artifact']['sha256'] = hashlib.sha256(self.payload).hexdigest()
                    asset = self.responses[self.urls['release']]['assets'][0]
                    asset['size'] = len(self.payload)
                    asset['digest'] = 'sha256:' + self.manifest['artifact']['sha256']
                with self.assertRaises(SystemExit):
                    INSTALLER.main()
                self.native.assert_not_called()
                self.assert_no_install()
                self.assertEqual(self.stderr.getvalue(), '')

    def test_download_error_never_installs_executes_or_emits_a_drift_receipt(self):
        self.download.side_effect = urllib.error.URLError('fixture download error')
        with self.assertRaises(urllib.error.URLError):
            INSTALLER.main()
        self.native.assert_not_called()
        self.assert_no_install()
        self.assertEqual(self.stderr.getvalue(), '')

    def test_download_reads_at_most_attested_size_plus_one(self):
        for payload in [b'x' * 8, b'x' * 9]:
            with self.subTest(size=len(payload)):
                response = mock.MagicMock()
                response.__enter__.return_value = response
                response.read.side_effect = lambda maximum: payload[:maximum]
                with mock.patch.object(INSTALLER.urllib.request, 'urlopen', return_value=response):
                    if len(payload) == 8:
                        self.assertEqual(REAL_DOWNLOAD('https://example.com/pinned-baseline', 8), payload)
                    else:
                        with self.assertRaisesRegex(SystemExit, 'exceeded its attested size'):
                            REAL_DOWNLOAD('https://example.com/pinned-baseline', 8)
                response.read.assert_called_once_with(9)

    def test_native_version_failure_never_promotes_or_emits_a_path(self):
        for kind in ['version', 'extra_stdout', 'process_error', 'timeout']:
            with self.subTest(kind=kind):
                self.reset_fixture()
                if kind == 'version':
                    self.native.return_value.stdout = 'assay-engine 9.9.9\n'
                elif kind == 'extra_stdout':
                    self.native.return_value.stdout += 'unexpected output\n'
                elif kind == 'process_error':
                    self.native.side_effect = subprocess.CalledProcessError(1, 'fixture')
                else:
                    self.native.side_effect = subprocess.TimeoutExpired('fixture', 10)
                with self.assertRaises((SystemExit, subprocess.SubprocessError)):
                    INSTALLER.main()
                self.native.assert_called_once()
                self.assert_no_install()
                self.assertEqual(self.stderr.getvalue(), '')

    def test_failed_native_check_preserves_previous_installed_bytes(self):
        self.destination.mkdir(mode=0o700)
        self.installed.write_bytes(b'previous accepted fixture')
        self.installed.chmod(0o500)
        self.native.return_value.stdout = 'assay-engine 9.9.9\n'
        with self.assertRaises(SystemExit):
            INSTALLER.main()
        self.assertEqual(self.installed.read_bytes(), b'previous accepted fixture')
        self.assertEqual(sorted(p.name for p in self.destination.iterdir()), ['assay-engine-v0.5.15'])
        self.assertEqual(self.stdout.getvalue(), '')
        self.assertEqual(self.stderr.getvalue(), '')

    def test_native_check_uses_validated_private_staging_and_retained_flags(self):
        def execute(arguments, **options):
            path = Path(arguments[0])
            self.assertNotEqual(path, self.installed)
            self.assertEqual(path.parent, self.destination)
            self.assertEqual(path.read_bytes(), self.payload)
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o500)
            self.assertFalse(self.installed.exists())
            self.assertEqual(arguments[1:], ['--version'])
            self.assertEqual(options, {'check': True, 'capture_output': True, 'text': True, 'timeout': 10})
            return subprocess.CompletedProcess(arguments, 0, 'assay-engine 0.5.15\n')
        self.native.side_effect = execute
        INSTALLER.main()
        self.assertEqual(self.installed.read_bytes(), self.payload)


if __name__ == '__main__':
    unittest.main()
