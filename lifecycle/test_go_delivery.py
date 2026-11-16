"""Focused preparation contracts. Synthetic identities are never release evidence."""
import copy
import importlib.util
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import go_delivery as d
import handoff as h

o = d.owners
FIXTURE_LICENSE = b'Synthetic license marker: not a real distributable'


def source_fixture():
    paths = ['LICENSE', 'cmake/mvp-dependencies.json', 'cmake/mvp-release-identities.json']
    for unit in o.OWNERS.values():
        paths += [unit['source_root'] + '/go.mod']
        if unit['component_id'] != 'sov-stdio-adapter':
            paths += [unit['source_root'] + '/go.sum']
    return o.sealed({'protocol': 'symphony.distribution.go-owner-source.v1', 'source_commit': '1' * 40,
                     'source_tree': '2' * 40, 'source_evidence': [{'path': p, 'sha256': d.sha(FIXTURE_LICENSE if p == 'LICENSE' else p.encode())} for p in sorted(paths)]}, 'binding_digest')


class DeliveryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='s05-contract-', dir=str(Path(tempfile.gettempdir()).resolve()))
        self.root = Path(self.tmp.name).resolve()
        self.binding = source_fixture()
        self.catalog = o.catalog(self.binding)
        self.digest = self.catalog['catalog_digest']

    def tearDown(self):
        self.tmp.cleanup()

    def carrier(self, component='qxctl', number=0, binary=b'#!/bin/sh\nexit 0\n', suffix=''):
        root = self.root / (component + suffix)
        root.mkdir(mode=0o700)
        unit = o.unit(self.catalog, component)
        sources = {x['path']: x['sha256'] for x in self.binding['source_evidence']}
        qx = component == 'qxctl'
        identity = {'protocol': 'symphony.artifact-build-identity.v1', 'component_id': component,
                    'version': unit['native_version'], 'binary_name': unit['binary_name'],
                    'source_commit': self.binding['source_commit'], 'source_tree': self.binding['source_tree'],
                    'source_date_epoch': '1', 'dependency_map_sha256': sources['cmake/mvp-dependencies.json'],
                    'release_identity_catalog_sha256': sources['cmake/mvp-release-identities.json'],
                    'go_mod_sha256': sources[unit['source_root'] + '/go.mod'],
                    'go_sum_sha256': sources.get(unit['source_root'] + '/go.sum'),
                    'build_recipe': 'symphony.qxctl.reproducible-build.v1' if qx else 'symphony.go.candidate-build.v1',
                    'go_version': 'go1.26.5', 'goos': 'darwin', 'goarch': 'amd64',
                    'executable_sha256': d.sha(binary), 'isolated_builds': 2 if qx else 1,
                    'reproducibility': 'verified_on_recorded_profile' if qx else 'not_assessed',
                    'publication_authorized': False}
        for name, data, mode in [(unit['binary_name'], binary, 0o755), ('artifact-identity.json', d.canonical(identity), 0o644),
                                  ('LICENSE-AGPL-3.0', FIXTURE_LICENSE, 0o644)]:
            (root / name).write_bytes(data)
            (root / name).chmod(mode)
        manifest = d.make_manifest(self.catalog, self.digest, component, root, o.FIXTURE_PROFILE, number,
                                   fixture=True, binding=self.binding)
        (root / 'carrier-manifest.json').write_bytes(d.canonical(manifest) + b'\n')
        (root / 'carrier-manifest.json').chmod(0o644)
        return root, manifest, unit

    def retain(self, carrier, manifest, output='retained', **kwargs):
        return d.materialize(self.catalog, self.digest, carrier, manifest['manifest_digest'], self.root / output,
                             fixture=True, binding=self.binding, **kwargs)

    def inspect(self, output, result):
        return d.inspect_custody(self.catalog, self.digest, self.root / output, result['custody_digest'], fixture=True, binding=self.binding)

    def test_exact_seven_owners_and_rehashed_substitution_refused(self):
        self.assertEqual(set(o.OWNERS), {'secure-identity-access-governance', 'stav-append-authority', 'accordare-stav-producer',
                                        'qxctl', 'sov-ssh-adapter', 'sov-stdio-adapter', 'sov-transport-profile-admin'})
        self.assertEqual(len(o.SERVICE_IDS), 3)
        value = copy.deepcopy(self.catalog)
        value['units'][0]['owner_contract'] = 'arbitrary.shell-owner.v1'
        value = o.sealed({k: v for k, v in value.items() if k != 'catalog_digest'}, 'catalog_digest')
        with self.assertRaisesRegex(ValueError, 'substituted'):
            o.validate_catalog(value, value['catalog_digest'], self.binding)
        with self.assertRaisesRegex(ValueError, 'unknown Go owner'):
            o.unit(self.catalog, 'unknown')

    def test_carrier_deletion_leaves_independent_retained_raw_bytes(self):
        for component in sorted(set(o.OWNERS) - o.SERVICE_IDS):
            with self.subTest(component=component):
                carrier, manifest, unit = self.carrier(component)
                cache = self.root / (component + '-conda-cache')
                os.link(carrier / unit['binary_name'], cache)
                with patch.object(d.subprocess, 'run') as run:
                    result = self.retain(carrier, manifest, output=component + '-retained')
                    run.assert_not_called()
                retained = Path(result['retained_executable'])
                self.assertNotEqual(retained.stat().st_ino, cache.stat().st_ino)
                self.assertEqual(retained.stat().st_nlink, 1)
                shutil.rmtree(carrier)
                cache.unlink()
                self.assertEqual(self.inspect(component + '-retained', result), result)
                sentinel = self.root / (component + '-user-data')
                sentinel.write_text('preserve')
                with self.assertRaisesRegex(ValueError, 'RAW_USE_OWNER_REQUIRED'):
                    d.refuse_cleanup(result)
                self.assertEqual(sentinel.read_text(), 'preserve')
                self.assertTrue(retained.exists())
                self.assertIsNone(result['runtime_installation'])
                self.assertFalse(result['administrator_provisioned'])

    def test_tamper_and_unexpected_host_state_fail_before_output(self):
        carrier, manifest, unit = self.carrier()
        (carrier / unit['binary_name']).write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'build bytes'):
            self.retain(carrier, manifest)
        self.assertFalse((self.root / 'retained').exists())
        (carrier / '.symphony-package-retirement').mkdir()
        with self.assertRaisesRegex(ValueError, 'host-local state'):
            self.retain(carrier, manifest)

    def test_private_marker_and_dependency_identity_are_rejected(self):
        with self.assertRaisesRegex(ValueError, 'private marker'):
            self.carrier(binary=b'#!/bin/sh\n# /Users/example-publisher/private\n')
        carrier, manifest, _ = self.carrier('sov-ssh-adapter')
        path = carrier / 'artifact-identity.json'
        identity = d.strict_json(path.read_bytes())
        identity['go_mod_sha256'] = 'f' * 64
        path.write_bytes(d.canonical(identity))
        with self.assertRaisesRegex(ValueError, 'dependency/source evidence'):
            d.make_manifest(self.catalog, self.digest, manifest['component_id'], carrier, o.FIXTURE_PROFILE, 0,
                            fixture=True, binding=self.binding)

    def test_same_native_version_builds_get_distinct_custody(self):
        first, ma, unit = self.carrier(number=1, suffix='-first')
        second, mb, _ = self.carrier(number=2, binary=b'#!/bin/sh\nexit 1\n', suffix='-second')
        a, b = self.retain(first, ma, 'one'), self.retain(second, mb, 'two')
        self.assertEqual(a['native_version'], b['native_version'])
        self.assertNotEqual(a['executable_sha256'], b['executable_sha256'])
        self.assertNotEqual(a['retained_executable'], b['retained_executable'])
        self.inspect('one', a)
        self.inspect('two', b)
        with self.assertRaises(FileExistsError):
            self.retain(second, mb, 'one')
        self.inspect('one', a)

    def test_symlink_carrier_and_retained_hardlink_are_refused(self):
        carrier, manifest, unit = self.carrier()
        alias = self.root / 'alias'
        alias.symlink_to(carrier, target_is_directory=True)
        with self.assertRaises(OSError):
            self.retain(alias, manifest)
        result = self.retain(carrier, manifest)
        os.link(result['retained_executable'], self.root / 'unowned-alias')
        with self.assertRaisesRegex(ValueError, 'links are unsafe'):
            self.inspect('retained', result)

    def fake_owner(self, component, *, tamper=False):
        def install(argv, **kwargs):
            self.assertEqual(argv[0].split('/')[-1], o.OWNERS[component]['binary_name'])
            prefix = Path(argv[argv.index('--prefix') + 1])
            expected = o.install_argv(component, argv[0], prefix)
            self.assertEqual(argv, expected)
            self.assertEqual(kwargs['env']['HOME'], str(prefix.parent / 'private-install-home'))
            binary = Path(argv[0]).read_bytes()
            receipt = o.receipt_expected(component, len(binary), d.sha(binary), 'darwin', 'amd64')
            target = prefix / receipt['files'][0]['path']
            target.parent.mkdir(parents=True)
            target.write_bytes(binary)
            target.chmod(0o755)
            path = prefix / 'share/symphony/receipts' / component / receipt['version'] / 'install-receipt.json'
            path.parent.mkdir(parents=True)
            if tamper:
                receipt['component_id'] = 'other'
            path.write_bytes(d.canonical(receipt))
            path.chmod(0o644)
            (prefix / '.symphony-package-retirement').mkdir()
            return subprocess.CompletedProcess(argv, 0)
        return install

    def test_native_argv_and_independent_receipt_gate_synthetic_only(self):
        for component in sorted(o.SERVICE_IDS):
            carrier, manifest, _ = self.carrier(component)
            with patch.object(d.subprocess, 'run', side_effect=self.fake_owner(component)) as call, \
                 patch.object(d.platform, 'system', return_value='Darwin'), patch.object(d.platform, 'machine', return_value='x86_64'):
                result = self.retain(carrier, manifest, component + '-native', install_native=True)
                self.assertEqual(call.call_count, 1)
            self.assertTrue(result['native_receipt_created'])
            self.inspect(component + '-native', result)
            self.assertFalse((Path(result['retained_executable']).parent / '.symphony-package-retirement').exists())
            exported = d.export_native(self.catalog, self.digest, self.root / (component + '-native'), result['custody_digest'],
                self.root / (component + '-export'), fixture=True, binding=self.binding)
            self.assertFalse(exported['host_local_guard_exported'])
            payload = self.root / (component + '-export/payload')
            self.assertEqual({str(p.relative_to(payload)) for p in payload.rglob('*') if p.is_file()},
                             {row['path'] for row in exported['files']})
            self.assertEqual(len(exported['files']), 2)

    def test_bad_native_result_retains_unknown_outcome_and_never_retries(self):
        component = 'stav-append-authority'
        carrier, manifest, _ = self.carrier(component)
        with patch.object(d.subprocess, 'run', side_effect=self.fake_owner(component, tamper=True)) as call, \
             patch.object(d.platform, 'system', return_value='Darwin'), patch.object(d.platform, 'machine', return_value='x86_64'):
            with self.assertRaisesRegex(ValueError, 'receipt identity/content'):
                self.retain(carrier, manifest, install_native=True)
            self.assertEqual(call.call_count, 1)
        self.assertTrue((self.root / 'retained/outcome-unknown.json').exists())
        self.assertTrue((self.root / 'retained/owner-call.json').exists())
        self.assertFalse((self.root / 'retained/custody.json').exists())
        # The retry reaches the existing-output guard on every test host; this
        # synthetic Darwin carrier is never executed by a real native owner.
        with patch.object(d.subprocess, 'run') as retry, \
             patch.object(d.platform, 'system', return_value='Darwin'), patch.object(d.platform, 'machine', return_value='x86_64'):
            with self.assertRaises(FileExistsError):
                self.retain(carrier, manifest, install_native=True)
            retry.assert_not_called()

    def test_wrong_host_native_carrier_refused_before_output_or_execution(self):
        carrier, manifest, _ = self.carrier('stav-append-authority')
        for system, machine in [('Linux', 'x86_64'), ('Darwin', 'arm64')]:
            with self.subTest(system=system, machine=machine), \
                 patch.object(d.subprocess, 'run') as call, \
                 patch.object(d.platform, 'system', return_value=system), \
                 patch.object(d.platform, 'machine', return_value=machine):
                with self.assertRaisesRegex(ValueError, 'different host'):
                    self.retain(carrier, manifest, install_native=True)
                call.assert_not_called()
                self.assertFalse((self.root / 'retained').exists())

    def test_raw_commands_have_no_native_install_fallback(self):
        for component in sorted(set(o.OWNERS) - o.SERVICE_IDS):
            carrier, manifest, _ = self.carrier(component)
            with self.assertRaisesRegex(ValueError, 'three user-owned installers'):
                self.retain(carrier, manifest, component + '-invalid', install_native=True)
            self.assertFalse((self.root / (component + '-invalid')).exists())

    def test_native_handoff_requires_exact_independently_retained_binding(self):
        component = 'stav-append-authority'
        carrier, manifest, unit = self.carrier(component)
        result = self.retain(carrier, manifest)
        binary = Path(result['retained_executable'])
        receipt = o.receipt_expected(component, binary.stat().st_size, d.sha(binary.read_bytes()), 'darwin', 'amd64')
        request = {'unit_id': unit['unit_id'], 'component_id': component, 'state_scope': 'user'}
        with patch.object(h.go_delivery.owners, 'reviewed_binding', return_value=self.binding):
            owner = h.validate_owner(self.catalog, self.digest, request, receipt)
        source = {'commit': self.binding['source_commit'], 'tree': self.binding['source_tree']}
        profile = {'configured_roots': [str(self.root / 'runtime')]}
        binding = component + '=' + str(binary)
        with patch.object(h.go_delivery.owners, 'reviewed_binding', return_value=self.binding):
            argv, evidence = h.native_owner_arguments([binding], owner, request, receipt, profile, source,
                catalog=self.catalog, manifest_digest=manifest['manifest_digest'], fixture=True)
        self.assertEqual(argv, ['--native-owner', binding])
        self.assertFalse(evidence['private_staging_home_for_maintenance'])
        with self.assertRaisesRegex(ValueError, 'Independently selected'):
            h.native_owner_arguments([binding], owner, request, receipt, profile, source)
        for bindings in ([], [binding, binding], ['unknown=' + str(binary)]):
            with self.assertRaises(ValueError):
                h.native_owner_arguments(bindings, owner, request, receipt, profile, source)
        with self.assertRaisesRegex(ValueError, 'outside installation roots'):
            h.native_owner_arguments([binding], owner, request, receipt, {'configured_roots': [str(binary.parent)]}, source)
        binary.write_bytes(b'different owner')
        with self.assertRaisesRegex(ValueError, 'SHA-256 differs'):
            h.native_owner_arguments([binding], owner, request, receipt, profile, source)
        with self.assertRaisesRegex(ValueError, 'unrelated owner route'):
            h.native_owner_arguments([binding], {}, request, receipt, profile, source)

    def test_recipe_stage_copies_only_inert_payload_and_detects_tamper(self):
        recipes = Path(__file__).resolve().parents[1] / 'recipes'
        def module(name):
            spec = importlib.util.spec_from_file_location(name, recipes / (name + '.py'))
            obj = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(obj)
            return obj
        generator, stage = module('go_generate'), module('stage_payload')
        for component in sorted(o.OWNERS):
            carrier, manifest, unit = self.carrier(component)
            recipe = self.root / (component + '-recipe')
            record = generator.render(self.catalog, self.digest, carrier, manifest['manifest_digest'], recipe,
                                      fixture=True, binding=self.binding)
            self.assertEqual(record['runtime_dependencies'], [])
            self.assertEqual(record['lifecycle_hooks'], [])
            text = (recipe / 'meta.yaml').read_text()
            self.assertNotIn('post-link', text)
            self.assertNotIn('pre-unlink', text)
            self.assertNotIn('  run:', text)
            prefix = self.root / (component + '-conda')
            prefix.mkdir()
            sentinel = prefix / 'unrelated'
            sentinel.write_text('preserve')
            stage.stage(recipe / 'payload', prefix, record['manifest_file_sha256'], record['carrier_destination'])
            self.assertEqual(sentinel.read_text(), 'preserve')
            shipped = prefix / record['carrier_destination']
            d.verify_carrier(self.catalog, self.digest, shipped, manifest['manifest_digest'], fixture=True, binding=self.binding)
            self.assertNotEqual((shipped / unit['binary_name']).stat().st_ino, (recipe / 'payload' / unit['binary_name']).stat().st_ino)
            (recipe / 'payload' / unit['binary_name']).write_bytes(b'tampered')
            with self.assertRaisesRegex(ValueError, 'Payload changed'):
                stage.stage(recipe / 'payload', prefix, record['manifest_file_sha256'], record['carrier_destination'] + '-other')
            self.assertEqual(sentinel.read_text(), 'preserve')


if __name__ == '__main__':
    unittest.main()
