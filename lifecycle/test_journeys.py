"""Synthetic package-stage checks: no installed runtime or process acceptance."""
import copy
import io
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

import contracts as c
import handoff as h
import journeys as j
import qualified_sources as q
import test_go_delivery as delivery_fixture
import test_handoff as base

COMPONENT = 'secure-identity-access-governance'
TARGET = b'#!/bin/sh\nexit 81\n'
PRIOR = b'#!/bin/sh\nexit 82\n'


def historical_controller():
    path = Path(__file__).parent / 'qualified-sources' / (q.CURRENT_COMMIT + '.json')
    raw = path.read_bytes()
    q.require(q.owners.sha(raw) == '81f4f36a003fae15cada6ebc9d8f2e482cda2e29f4d97cbd245c7a64993207a9',
              'Historical controller snapshot differs')
    return q.owners.strict_json(raw)


def rebind(values):
    profile, observation, boot = values[:3]
    base.seal_profile(profile)
    base.seal_observation(observation)
    boot['plan'].update(desired_state_digest=profile['desired_state']['desired_state_digest'],
                        observation_digest=observation['observation_digest'])
    boot['journal'].update(profile_digest=profile['profile_digest'],
                           desired_state_digest=profile['desired_state']['desired_state_digest'],
                           current_observation_digest=observation['observation_digest'],
                           current_stable_inventory_digest=h.stable_inventory(observation))
    base.reseal_boot(boot)


def fixture(operation, *, target_bytes=TARGET, prior_bytes=PRIOR):
    values = list(base.fixture())
    profile, observation, boot, _, _, request = values
    receipt = h.go_delivery.owners.receipt_expected(COMPONENT, len(target_bytes), h.sha(target_bytes), 'darwin', 'amd64')
    prior = h.go_delivery.owners.receipt_expected(COMPONENT, len(prior_bytes), h.sha(prior_bytes), 'darwin', 'amd64')
    values[4] = receipt
    component = profile['desired_state']['components'][0]
    component.update(component_id=COMPONENT, component_kind='service', module_id=COMPONENT,
                     vector_id=None, engine_id=None, selected_package=j.receipt_identity(receipt))
    request.update(protocol=j.PROTOCOL, format_version=2, operation=operation, component_id=COMPONENT,
                   unit_id='PKG-GO-' + COMPONENT, prior_receipt_digest=None, prior_install_root=None)
    installed_receipt, installed_root = receipt, component['install_root']
    if operation in j.TRANSITIONS:
        installed_receipt, installed_root = prior, '/private/tmp/d05-fixture-prior-runtime'
        request.update(prior_receipt_digest=prior['receipt_digest'], prior_install_root=installed_root)
        profile['configured_roots'].append(installed_root)
    if operation == 'remove':
        component.update(presence='absent', selected_package=None)
    observation['configured_roots'] = profile['configured_roots'][:]
    if operation != 'install':
        observation['components'] = [{
            **{k: component[k] for k in ('component_id', 'component_kind', 'module_id', 'vector_id', 'engine_id')},
            'packages': [{**j.receipt_identity(installed_receipt), 'install_root': installed_root,
                          'integrity': 'valid', 'entry_points_validated': True}],
            'selected_package_digest': None, 'activation': 'inactive', 'docking': 'undocked', 'receptor_id': None,
            'capabilities': installed_receipt['provides_capabilities'], 'platform_compatibility': 'compatible'}]
    a = boot['plan']['actions'][0]
    a.update(component_id=COMPONENT, kind='uninstall' if operation == 'remove' else 'install',
             action_id='package-target', expected_artifact_digests=[receipt['receipt_digest']])
    boot['plan']['actions'][1].update(component_id=COMPONENT)
    boot['plan']['ready_action_ids'] = [x['action_id'] for x in boot['plan']['actions']]
    rebind(values)
    if operation == 'remove':
        a['expected_before_digest'] = observation['components'][0]['observation_digest']
        base.reseal_boot(boot)
    return values, prior if operation in j.TRANSITIONS else None


class JourneyTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        base.HandoffTests.setUpClass()
        cls.registry = base.HandoffTests.registry

    def prepare(self, operation):
        values, prior = fixture(operation)
        return values, prior, h.make_scope(*values, self.registry, prior_receipt=prior)

    def test_all_five_intents_bind_one_existing_effect_and_preserve_full_inputs(self):
        for operation in sorted(j.OPERATIONS):
            with self.subTest(operation=operation):
                values, prior = fixture(operation)
                before = copy.deepcopy(values)
                scope = h.make_scope(*values, self.registry, prior_receipt=prior)
                self.assertEqual(values, before)
                self.assertEqual(scope['profile_digest'], values[0]['profile_digest'])
                self.assertEqual(scope['desired_state_digest'], values[0]['desired_state']['desired_state_digest'])
                self.assertEqual(scope['components'], [COMPONENT])
                self.assertEqual(len(scope['effects']), 1)
                self.assertEqual(scope['effects'][0]['kind'], 'uninstall' if operation == 'remove' else 'install')
                self.assertEqual(scope['ownership_effects'][0]['disposition'], 'release' if operation == 'remove' else 'retained')
                self.assertEqual(len(values[2]['plan']['actions']), 4)
                self.assertEqual(values[0]['desired_state']['components'][1], before[0]['desired_state']['components'][1])

    def test_removal_requires_absence_and_exact_single_installed_receipt(self):
        mutations = [
            lambda v: v[0]['desired_state']['components'][0].update(presence='present', selected_package=j.receipt_identity(v[4])),
            lambda v: v[1]['components'][0]['packages'][0].update(receipt_digest=base.D),
            lambda v: v[1]['components'][0]['packages'][0].update(install_root='/opt/other'),
            lambda v: v[1]['components'][0]['packages'][0].update(integrity='unknown'),
            lambda v: v[1]['components'][0]['packages'].append(copy.deepcopy(v[1]['components'][0]['packages'][0])),
        ]
        for mutate in mutations:
            values, prior = fixture('remove'); mutate(values); rebind(values)
            with self.subTest(mutation=mutate), self.assertRaises(ValueError):
                h.make_scope(*values, self.registry, prior_receipt=prior)

    def test_live_selected_docked_and_unknown_consumers_refuse(self):
        for operation in ('remove', 'upgrade', 'swap', 'rollback'):
            for field, value in (('activation', 'active'), ('activation', 'unknown'), ('selected_package_digest', base.D),
                                 ('docking', 'unknown'), ('platform_compatibility', 'unknown')):
                values, prior = fixture(operation)
                values[1]['components'][0][field] = value; rebind(values)
                with self.subTest(operation=operation, field=field), self.assertRaises(ValueError):
                    h.make_scope(*values, self.registry, prior_receipt=prior)

    def test_transition_requires_prior_identity_and_distinct_immutable_root(self):
        for operation in sorted(j.TRANSITIONS):
            values, prior = fixture(operation)
            with self.assertRaisesRegex(ValueError, 'Retained prior'):
                h.make_scope(*values, self.registry)
            for root in (values[0]['desired_state']['components'][0]['install_root'],
                         values[0]['desired_state']['components'][0]['install_root'] + '/nested'):
                values, prior = fixture(operation)
                values[5]['prior_install_root'] = root
                values[1]['components'][0]['packages'][0]['install_root'] = root
                rebind(values)
                with self.assertRaisesRegex(ValueError, 'immutable root'):
                    h.make_scope(*values, self.registry, prior_receipt=prior)
            values, prior = fixture(operation)
            prior['receipt_digest'] = base.D
            with self.assertRaises(ValueError):
                h.make_scope(*values, self.registry, prior_receipt=prior)

    def test_unknown_raw_system_and_critical_request_fields_refuse(self):
        for key, value in (('operation', 'activate'), ('component_id', 'qxctl'), ('component_id', 'unknown'),
                           ('state_scope', 'system'), ('force', True), ('format_version', True)):
            values, prior = fixture('remove'); values[5][key] = value
            with self.subTest(field=key, value=value), self.assertRaises(ValueError):
                h.make_scope(*values, self.registry, prior_receipt=prior)

    def test_prerequisites_artifact_changes_and_blocked_removal_never_expand_scope(self):
        for key, value in (('prerequisite_action_ids', ['select-skvi']), ('expected_artifact_digests', [base.D]),
                           ('expected_before_digest', base.D), ('target_receptor_id', 'some-receptor')):
            values, prior = fixture('remove'); values[2]['plan']['actions'][0][key] = value; base.reseal_boot(values[2])
            with self.subTest(field=key), self.assertRaises(ValueError):
                h.make_scope(*values, self.registry, prior_receipt=prior)
        values, prior = fixture('remove'); a = values[2]['plan']['actions'][0]
        a.update(disposition='blocked', blockers=[{'class': 'dependency_wait', 'component_id': COMPONENT,
                 'action_id': a['action_id'], 'retryable': True, 'detail': 'cannot invent removal readiness'}])
        values[2]['plan']['ready_action_ids'].remove(a['action_id'])
        values[2]['plan']['blocked_action_ids'].append(a['action_id']); base.reseal_boot(values[2])
        with self.assertRaises(ValueError): h.make_scope(*values, self.registry, prior_receipt=prior)

    def test_activation_and_same_candidate_transition_are_not_prepared(self):
        for operation in sorted(j.OPERATIONS):
            values, prior = fixture(operation)
            values[0]['desired_state']['components'][0]['activation'] = 'active'; rebind(values)
            with self.subTest(operation=operation), self.assertRaises(ValueError):
                h.make_scope(*values, self.registry, prior_receipt=prior)
        values, prior = fixture('rollback', prior_bytes=TARGET)
        with self.assertRaisesRegex(ValueError, 'distinct exact candidate'):
            h.make_scope(*values, self.registry, prior_receipt=prior)

    def test_full_profile_cas_and_scope_remain_required_for_removal(self):
        values, prior = fixture('remove')
        for index, key, value in ((5, 'expected_apply_journal_digest', base.D), (5, 'expected_applied_state_digest', base.D),
                                  (0, 'profile_digest', base.D)):
            changed = copy.deepcopy(values); changed[index][key] = value
            with self.subTest(field=key), self.assertRaises(ValueError):
                h.make_scope(*changed, self.registry, prior_receipt=prior)

    def test_only_code_owned_retained_source_pair_is_accepted(self):
        current = historical_controller()
        prior = q.retained_binding(current)
        catalog = q.owners.catalog(prior)
        source = {'commit': current['source_commit'], 'tree': current['source_tree']}
        with patch.object(q.owners, 'reviewed_binding', return_value=current):
            self.assertEqual(q.resolve(catalog, catalog['catalog_digest'], source), prior)
        for mutation in ('unknown_source', 'owner_contract', 'new_controller', 'runtime_bytes'):
            changed = copy.deepcopy(catalog)
            controller = copy.deepcopy(source)
            current_copy = copy.deepcopy(current)
            if mutation == 'unknown_source':
                changed['source_commit'] = 'e' * 40
            elif mutation == 'owner_contract':
                changed['units'][0]['owner_contract'] = 'caller.defined.owner'
                changed = q.owners.sealed(c.without(changed, 'catalog_digest'), 'catalog_digest')
            elif mutation == 'new_controller':
                controller['commit'] = 'f' * 40
            else:
                row = next(r for r in current_copy['source_evidence'] if r['path'].endswith('/internal/packageretirement/guard_unix.go'))
                row['sha256'] = 'f' * 64
            with self.subTest(mutation=mutation), patch.object(q.owners, 'reviewed_binding', return_value=current_copy), self.assertRaises(ValueError):
                q.resolve(changed, changed['catalog_digest'], controller)

    def test_new_candidate_cannot_inherit_historical_controller_qualification(self):
        current = q.owners.reviewed_binding()
        self.assertNotEqual(current['source_commit'], q.CURRENT_COMMIT)
        with self.assertRaisesRegex(ValueError, 'has not been qualified'):
            q.retained_binding(current)
        prior = q.retained_binding(historical_controller())
        catalog = q.owners.catalog(prior)
        with self.assertRaisesRegex(ValueError, 'has not been qualified'):
            q.resolve(catalog, catalog['catalog_digest'])
        beta1_catalog = q.owners.catalog(historical_controller())
        with self.assertRaisesRegex(ValueError, 'Unqualified retained owner source'):
            q.resolve(beta1_catalog, beta1_catalog['catalog_digest'])
        active = q.owners.catalog(current)
        self.assertEqual(q.resolve(active, active['catalog_digest']), current)

    def test_known_source_record_changes_and_cross_component_observations_refuse(self):
        current = historical_controller()
        with patch.object(q.Path, 'read_bytes', return_value=b'changed'), self.assertRaisesRegex(ValueError, 'evidence changed'):
            q.retained_binding(current)
        values, prior = fixture('remove')
        values[1]['components'][0]['module_id'] = 'different-owner'; rebind(values)
        with self.assertRaisesRegex(ValueError, 'component identity'):
            h.make_scope(*values, self.registry, prior_receipt=prior)


class JourneyCLITests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        JourneyTests.setUpClass()
        cls.registry = JourneyTests.registry

    def setUp(self):
        self.real_binding = h.go_delivery.owners.reviewed_binding()
        self.files = delivery_fixture.DeliveryTests()
        self.files.setUp()
        self.root = self.files.root
        self.binding_patch = patch.object(h.go_delivery.owners, 'reviewed_binding', return_value=self.files.binding)
        self.binding_patch.start()

    def tearDown(self):
        self.binding_patch.stop()
        self.files.tearDown()

    def cli(self, operation):
        values, prior = fixture(operation)
        profile, observation, boot, status, receipt, request = values
        carrier, manifest, unit = self.files.carrier(COMPONENT, binary=TARGET, suffix='-target')
        retained = self.files.retain(carrier, manifest, output='target-retained')
        prior_carrier = prior_manifest = prior_retained = None
        if prior is not None:
            prior_carrier, prior_manifest, _ = self.files.carrier(COMPONENT, binary=PRIOR, suffix='-prior')
            prior_retained = self.files.retain(prior_carrier, prior_manifest, output='prior-retained')
        repository = self.root / 'repository'; repository.mkdir()
        stage = self.root / 'stage'; stage.mkdir()
        qxctl, coordinator = self.root / 'qxctl', self.root / 'coordinator'
        for executable in (qxctl, coordinator):
            executable.write_bytes(b'#!/bin/sh\nexit 86\n'); executable.chmod(0o700)
        binary_sha = h.sha(qxctl.read_bytes())
        for field in ('qxctl_identity', 'coordinator_identity'):
            observation['platform'][field]['executable_digest'] = 'sha256:' + binary_sha
        rebind(values)
        if operation == 'remove':
            boot['plan']['actions'][0]['expected_before_digest'] = observation['components'][0]['observation_digest']
            base.reseal_boot(boot)
        source = {'commit': self.files.binding['source_commit'], 'tree': self.files.binding['source_tree'],
                  'files': [], 'synthetic_fixture': True}
        build = {'protocol': 'symphony.distribution.controller-build-binding.v1', 'format_version': 1,
                 'source_commit': source['commit'], 'source_tree': source['tree'],
                 'qxctl_sha256': binary_sha, 'coordinator_sha256': binary_sha}
        payload = stage / receipt['files'][0]['path']; payload.parent.mkdir(parents=True)
        payload.write_bytes(TARGET); payload.chmod(0o755)
        receipt_path = stage / 'share/symphony/receipts' / COMPONENT / receipt['version'] / 'install-receipt.json'
        receipt_path.parent.mkdir(parents=True)
        docs = {'profile': profile, 'observation': observation, 'boot': boot, 'apply-status': status,
                'receipt': receipt, 'request': request, 'build-binding': build, 'catalog': self.files.catalog}
        paths = {'qxctl': qxctl, 'coordinator': coordinator}
        for name, value in docs.items():
            path = receipt_path if name == 'receipt' else self.root / (name + '.json')
            path.write_bytes(h.native_bytes(value)); path.chmod(0o600); paths[name] = path
        output = self.root / 'proposal'
        argv = ['handoff.py', '--repository', str(repository), '--source-root', str(stage), '--output', str(output),
                '--source-commit', source['commit'], '--source-tree', source['tree'], '--catalog-digest', self.files.digest,
                '--native-owner', COMPONENT + '=' + retained['retained_executable'],
                '--native-owner-manifest-digest', manifest['manifest_digest'], '--native-owner-fixture',
                '--native-owner-custody', str(self.root / 'target-retained'), '--native-owner-custody-digest', retained['custody_digest']]
        for name, path in paths.items():
            argv += ['--' + name, str(path), '--' + name + '-sha256', h.sha(path.read_bytes())]
        if prior is not None:
            path = self.root / 'prior-receipt.json'; path.write_bytes(h.native_bytes(prior)); path.chmod(0o600)
            argv += ['--prior-receipt', str(path), '--prior-receipt-sha256', h.sha(path.read_bytes()),
                     '--prior-native-owner', COMPONENT + '=' + prior_retained['retained_executable'],
                     '--prior-native-owner-manifest-digest', prior_manifest['manifest_digest'],
                     '--prior-native-owner-custody', str(self.root / 'prior-retained'),
                     '--prior-native-owner-custody-digest', prior_retained['custody_digest']]
        return argv, source, output, values

    def invoke(self, argv, source):
        with patch('sys.argv', argv), patch.object(h, 'bound_source', return_value=(self.registry, source)), \
                patch.object(h.subprocess, 'check_output', side_effect=AssertionError('No runtime owner invocation')), \
                patch.object(h.subprocess, 'run', side_effect=AssertionError('No runtime owner invocation')), \
                patch('sys.stdout', io.StringIO()), patch('sys.stderr', io.StringIO()):
            h.main()

    def test_removal_cli_is_one_exact_release_with_retained_old_candidate(self):
        argv, source, output, values = self.cli('remove'); self.invoke(argv, source)
        proposal = json.loads((output / 'handoff.json').read_text())
        scope = json.loads((output / 'execution-scope.json').read_text())
        self.assertEqual(proposal['protocol'], 'symphony.distribution.scoped-package-handoff.v2')
        self.assertEqual(proposal['journey']['stage'], 'native_removal_proposal')
        self.assertEqual(scope['ownership_effects'][0]['disposition'], 'release')
        self.assertFalse(proposal['owner_invoked'])
        self.assertFalse(proposal['live_removal_qualified'])
        self.assertFalse(proposal['journey']['journey_completed'])
        self.assertEqual(json.loads((output / 'profile.json').read_text()), values[0])
        self.assertEqual(proposal['excluded_action_ids'], ['select-skvi', 'uninstall-unrelated', 'activate-unrelated'])

    def test_rollback_cli_preserves_both_candidates_without_select_or_activation(self):
        argv, source, output, values = self.cli('rollback'); self.invoke(argv, source)
        proposal = json.loads((output / 'handoff.json').read_text())
        self.assertEqual(proposal['journey']['stage'], 'target_install_proposal')
        self.assertIsNotNone(proposal['journey']['retained_prior_candidate'])
        self.assertFalse(proposal['runtime_selection_changed'])
        self.assertFalse(proposal['runtime_activation_changed'])
        self.assertFalse(proposal['journey']['old_candidate_reclaimed'])
        self.assertFalse(proposal['journey']['history_proven'])
        self.assertTrue((output / 'prior-receipt.json').exists())
        self.assertEqual(proposal['journey']['prior_receipt_digest'], values[5]['prior_receipt_digest'])

    def test_missing_rollback_candidate_retention_fails_before_output(self):
        argv, source, output, _ = self.cli('rollback')
        index = argv.index('--prior-native-owner-manifest-digest'); del argv[index:index + 2]
        with self.assertRaises(SystemExit): self.invoke(argv, source)
        self.assertFalse(output.exists())

    def test_prior_carrier_drift_fails_before_output(self):
        argv, source, output, _ = self.cli('upgrade')
        executable = Path(argv[argv.index('--prior-native-owner') + 1].split('=', 1)[1])
        executable.write_bytes(b'changed')
        with self.assertRaises(SystemExit): self.invoke(argv, source)
        self.assertFalse(output.exists())

    def test_sole_installed_controller_is_not_retained_custody(self):
        argv, source, output, values = self.cli('remove')
        executable = Path(argv[argv.index('--native-owner') + 1].split('=', 1)[1])
        profile = copy.deepcopy(values[0]); profile['configured_roots'].append(str(executable.parent))
        owner = h.validate_owner(self.files.catalog, self.files.digest, values[5], values[4])
        with self.assertRaisesRegex(ValueError, 'outside installation roots'):
            h.native_owner_arguments([COMPONENT + '=' + str(executable)], owner, values[5], values[4], profile, source,
                catalog=self.files.catalog, manifest_digest=argv[argv.index('--native-owner-manifest-digest') + 1], fixture=True)
        self.assertFalse(output.exists())

    def test_qualified_old_controller_is_verified_against_its_own_source_catalog(self):
        # Synthetic executable remains inert; this exercises compatibility policy,
        # not the authenticity or execution of a real historical owner binary.
        historical = historical_controller()
        prior = q.retained_binding(historical)
        self.files.binding = prior
        self.files.catalog = q.owners.catalog(prior)
        self.files.digest = self.files.catalog['catalog_digest']
        with patch.object(delivery_fixture, 'FIXTURE_LICENSE', (Path(__file__).parent.parent / 'LICENSE').read_bytes()):
            carrier, manifest, unit = self.files.carrier(COMPONENT, binary=TARGET)
        retained = self.files.retain(carrier, manifest, output='retained-prior')
        values, _ = fixture('remove')
        source = {'commit': historical['source_commit'], 'tree': historical['source_tree']}
        with patch.object(q.owners, 'reviewed_binding', return_value=historical):
            owner = h.validate_owner(self.files.catalog, self.files.digest, values[5], values[4])
            argv, evidence = h.native_owner_arguments([COMPONENT + '=' + retained['retained_executable']],
                owner, values[5], values[4], values[0], source, catalog=self.files.catalog,
                manifest_digest=manifest['manifest_digest'], fixture=True,
                custody_root=self.root / 'retained-prior', custody_digest=retained['custody_digest'])
        self.assertEqual(argv[0], '--native-owner')
        self.assertEqual(evidence['source_commit'], q.PRIOR_COMMIT)
        self.assertEqual(evidence['catalog_digest'], self.files.digest)

    def test_partial_prior_catalog_refuses_without_output(self):
        argv, source, output, _ = self.cli('rollback')
        argv += ['--prior-catalog-digest', self.files.digest]
        with self.assertRaises(SystemExit): self.invoke(argv, source)
        self.assertFalse(output.exists())

    def test_bare_carrier_cannot_pose_as_v2_retained_controller(self):
        argv, source, output, _ = self.cli('remove')
        index = argv.index('--native-owner-custody'); del argv[index:index + 2]
        index = argv.index('--native-owner-custody-digest'); del argv[index:index + 2]
        with self.assertRaises(SystemExit): self.invoke(argv, source)
        self.assertFalse(output.exists())

    def test_conda_environment_or_known_cache_custody_refuses(self):
        argv, source, output, _ = self.cli('remove')
        (self.root / 'conda-meta').mkdir()
        with self.assertRaises(SystemExit): self.invoke(argv, source)
        self.assertFalse(output.exists())
        (self.root / 'conda-meta').rmdir()
        argv += ['--conda-owned-root', str(self.root / 'target-retained')]
        with self.assertRaises(SystemExit): self.invoke(argv, source)
        self.assertFalse(output.exists())

    def test_custody_root_digest_and_selected_controller_are_exact(self):
        argv, source, output, _ = self.cli('rollback')
        changed = argv[:]
        changed[changed.index('--native-owner-custody-digest') + 1] = base.D
        with self.assertRaises(SystemExit): self.invoke(changed, source)
        self.assertFalse(output.exists())
        changed = argv[:]
        changed[changed.index('--native-owner-custody') + 1] = str(self.root / 'prior-retained')
        changed[changed.index('--native-owner-custody-digest') + 1] = argv[argv.index('--prior-native-owner-custody-digest') + 1]
        with self.assertRaises(SystemExit): self.invoke(changed, source)
        self.assertFalse(output.exists())

    def test_resealed_custody_cannot_add_authority_fields(self):
        argv, source, output, _ = self.cli('remove')
        path = self.root / 'target-retained/custody.json'
        record = h.strict_json(path.read_bytes())
        record['force_removal_authorized'] = True
        record = q.owners.sealed(c.without(record, 'custody_digest'), 'custody_digest')
        path.write_bytes(q.owners.canonical(record))
        argv[argv.index('--native-owner-custody-digest') + 1] = record['custody_digest']
        with self.assertRaises(SystemExit): self.invoke(argv, source)
        self.assertFalse(output.exists())


if __name__ == '__main__':
    unittest.main()
