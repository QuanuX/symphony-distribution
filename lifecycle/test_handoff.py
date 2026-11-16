"""Synthetic contract checks only: no qxctl, coordinator or lifecycle owner runs."""
import copy
import json
import io
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

import contracts as c
import handoff as h
from schema import Registry, SchemaError


D = 'sha256:' + 'd' * 64
WHEN = '2026-11-15T00:00:00Z'
SOURCE = Path(os.environ['SYMPHONY_SCOPE_TEST_SOURCE']).resolve() if os.environ.get('SYMPHONY_SCOPE_TEST_SOURCE') else None


def seal_profile(profile):
    desired = profile['desired_state']
    desired['desired_state_digest'] = c.digest(c.without(c.normalize_desired(desired), 'desired_state_digest'))
    normalized = copy.deepcopy(profile)
    normalized['configured_roots'].sort()
    normalized['desired_state'] = c.normalize_desired(desired)
    profile['profile_digest'] = c.digest(c.without(normalized, 'profile_digest'))


def seal_observation(observation):
    for component in observation['components']:
        normalized = copy.deepcopy(component)
        normalized['packages'].sort(key=c.canonical)
        normalized['capabilities'].sort()
        component['observation_digest'] = c.digest(c.without(normalized, 'observation_digest'))
    observation['observation_digest'] = c.digest(c.without(c.normalize_observation(observation), 'observation_digest'))


def compatibility(journal_version=1):
    return {'mode': 'full', 'process_protocol': 'symphony.knowledge.engine-process.v1',
            'journal_read_version': journal_version, 'journal_write_version': journal_version,
            'missing_capabilities': [], 'two_way_procedural_compatibility': True, 'reason': 'synthetic fixture'}


def action(component, kind, identity):
    return {'action_id': identity, 'component_id': component, 'kind': kind, 'direction': 'forward',
            'prerequisite_action_ids': [], 'inverse_action_id': None, 'expected_before_digest': None,
            'target_state_digest': D, 'target_receptor_id': None, 'expected_artifact_digests': [D],
            'expected_evidence': ['receipt'], 'disposition': 'ready', 'blockers': []}


def fixture():
    component = {'component_id': 'skvi-engine', 'component_kind': 'vector_engine', 'module_id': 'skvi-engine',
                 'vector_id': 'SKVI', 'engine_id': 'skvi-engine', 'presence': 'present',
                 'selected_package': None, 'required': False, 'install_scope': 'prefix',
                 'install_root': '/private/tmp/d05-fixture-runtime', 'activation': 'inactive',
                 'docking': {'disposition': 'undocked', 'receptor_id': None}, 'dependencies': [],
                 'compatibility': {'required_capabilities': [], 'platform_requirements': []}, 'extensions': []}
    receipt = {'protocol': c.RECEIPT, 'format_version': 2,
               **{key: component[key] for key in ('component_id', 'component_kind', 'module_id', 'vector_id', 'engine_id')},
               'package_id': 'skvi-engine', 'version': '0.2.0-dev', 'install_scope': 'prefix', 'prefix_mode': 'installation_prefix',
               'files': [{'path': 'share/skvi-fixture.dat', 'kind': 'regular', 'size': 12,
                          'digest': 'sha256:' + h.sha(b'fixture-data')}],
               'entry_points': [], 'provides_capabilities': [], 'requires_capabilities': [],
               'compatible_receptors': [], 'platform_requirements': []}
    receipt['receipt_digest'] = c.digest(receipt)
    component['selected_package'] = {key: receipt[key] for key in ('package_id', 'version', 'receipt_digest')}
    component['selected_package']['receipt_protocol'] = receipt['protocol']
    unrelated = copy.deepcopy(component)
    unrelated.update(component_id='unrelated', module_id='unrelated', vector_id=None, engine_id=None, component_kind='module')
    desired = {'protocol': c.DESIRED, 'format_version': 1, 'profile_id': 'fixture-profile',
               'tops_id': '11111111-1111-4111-8111-111111111111', 'generation': 1,
               'previous_desired_state_digest': None, 'components': [component, unrelated],
               'extensions': [], 'canonical': False}
    profile = {'protocol': c.PROFILE, 'format_version': 1, 'profile_id': desired['profile_id'], 'tops_id': desired['tops_id'],
               'generation': 1, 'previous_profile_digest': None, 'configured_roots': [component['install_root']],
               'boot_mode': 'apply-compatible', 'desired_state': desired, 'canonical': False}
    seal_profile(profile)
    observation = {'protocol': c.OBSERVATION, 'format_version': 1, 'profile_id': desired['profile_id'], 'tops_id': desired['tops_id'],
                   'configured_roots': profile['configured_roots'][:], 'platform': {
                       'os': 'macos', 'kernel_abi': 'darwin', 'architecture': 'amd64',
                       'qxctl_identity': {'component_id': 'qxctl', 'version': '0.1.0-dev', 'executable_digest': D},
                       'coordinator_identity': {'component_id': 'knowledge-session-coordinator', 'version': '0.1.0-dev', 'executable_digest': D},
                       'provider_availability': [], 'compatibility_digest': D},
                   'binding_registry_digest': None, 'components': [], 'unknown_packages': [],
                   'observed_at': WHEN, 'canonical': False}
    seal_observation(observation)
    actions = [action('skvi-engine', 'install', 'install-skvi'), action('skvi-engine', 'select', 'select-skvi'),
               action('unrelated', 'uninstall', 'uninstall-unrelated'), action('unrelated', 'activate', 'activate-unrelated')]
    actions[0]['expected_artifact_digests'] = [receipt['receipt_digest']]
    plan = {'protocol': 'symphony.knowledge.lifecycle-plan.v1', 'format_version': 1,
            'transaction_id': 'fixture-transaction', 'revision': 1, 'previous_plan_digest': None,
            'desired_state_digest': desired['desired_state_digest'], 'observation_digest': observation['observation_digest'],
            'observation_key': D, 'prior_applied_state_digest': None,
            'compatibility': {'mode': 'full', 'coordinator_version': '0.1.0-dev', 'desired_state_version': 1,
                              'observation_version': 1, 'plan_version': 1, 'applied_state_version': 1,
                              'receipt_versions': [2], 'required_capabilities': ['receipt-v2'],
                              'missing_capabilities': [], 'two_way_procedural_compatibility': True, 'reason': 'fixture'},
            'scheduler': {'algorithm': 'dependency_ready_set_v1', 'dynamic_replanning': True, 'directionality': 'forward_and_inverse',
                          'tie_break': 'lexicographic_action_id', 'safety_phase_order': ['lock', 'observe', 'authorize', 'compare_and_swap', 'act', 'verify', 'audit'],
                          'cycle_policy': 'block_cyclic_component_continue_unrelated', 'max_actions': 4096,
                          'max_replans_per_transaction': 256, 'max_attempts_per_action': 8},
            'actions': actions, 'ready_action_ids': [item['action_id'] for item in actions], 'deferred_action_ids': [],
            'blocked_action_ids': [], 'advisories': [], 'fatal_blockers': [], 'apply_authorized': False, 'canonical': False}
    journal = {'protocol': 'symphony.knowledge.lifecycle-boot-journal.v1', 'format_version': 1,
               'journal_id': 'fixture-journal', 'transaction_id': 'fixture-transaction', 'operation_id': 'fixture-boot',
               'generation': 1, 'previous_journal_digest': None, 'profile_id': profile['profile_id'],
               'profile_digest': profile['profile_digest'], 'tops_id': profile['tops_id'], 'mode': 'apply-compatible', 'state': 'open',
               'desired_state_digest': desired['desired_state_digest'], 'observation_key': D,
               'current_observation_digest': observation['observation_digest'], 'current_stable_inventory_digest': h.stable_inventory(observation),
               'prior_applied_state_digest': None, 'current_plan_digest': '', 'current_plan_revision': 1,
               'replan_count': 0, 'action_attempts': [], 'blockers': [],
               'checkpoints': [{'sequence': 1, 'kind': 'begin', 'plan_revision': 1, 'operation_id': 'fixture-boot', 'observed_at': WHEN,
                                'observation_digest': observation['observation_digest'], 'ready_set_digest': D,
                                'previous_checkpoint_digest': None, 'checkpoint_digest': D}],
               'compatibility': {'journal_read_versions': [1], 'journal_write_version': 1,
                                 **{name + suffix: value for name in ('desired', 'observation', 'plan', 'applied')
                                    for suffix, value in (('_read_versions', [1]), ('_write_version', 1))},
                                 'receipt_read_versions': [2], 'required_capabilities': [], 'optional_capabilities': [],
                                 'opaque_extensions_preserved': True},
               'extensions': [], 'recovery': {'state': 'clean', 'disposition': 'not_applicable', 'recovered_from_digest': None, 'detail': 'fixture'},
               'started_at': WHEN, 'updated_at': WHEN, 'closed_at': None, 'canonical': False, 'apply_authorized': False}
    boot = {'protocol': 'symphony.knowledge.lifecycle-boot-result.v1', 'operation': 'lifecycle_boot',
            'compatibility': compatibility(), 'journal_present': True, 'journal': journal, 'journal_digest': '', 'plan': plan,
            'changed': True, 'recovered': False, 'repair_actions': [], 'read_only': False, 'apply_authorized': False, 'canonical': False}
    reseal_boot(boot)
    status = {'protocol': 'symphony.knowledge.lifecycle-apply-result.v1', 'operation': 'lifecycle_apply_status',
              'compatibility': compatibility(2), 'journal_present': False, 'journal': None, 'journal_digest': None,
              'plan': None, 'action': None, 'applied_state': None, 'changed': False, 'recovered': False,
              'repair_actions': [], 'read_only': True, 'apply_authorized': False, 'canonical': False}
    request = {'protocol': 'symphony.distribution.scoped-install-request.v1', 'format_version': 1,
               'unit_id': 'PKG-NATIVE-skvi-engine', 'component_id': 'skvi-engine', 'scope_id': 'fixture-scope',
               'operation_id': 'fixture-install', 'expected_apply_journal_digest': 'absent',
               'expected_applied_state_digest': 'absent', 'state_root': '/private/tmp/d05-fixture-state', 'state_scope': 'user'}
    return profile, observation, boot, status, receipt, request


def reseal_boot(boot):
    plan, journal = boot['plan'], boot['journal']
    plan['plan_digest'] = h.native_digest(c.without(plan, 'plan_digest'))
    journal['current_plan_digest'] = plan['plan_digest']
    journal['journal_digest'] = h.native_digest(c.without(journal, 'journal_digest'))
    boot['journal_digest'] = journal['journal_digest']


class HandoffTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if SOURCE is None:
            raise RuntimeError('Set SYMPHONY_SCOPE_TEST_SOURCE to the exact reviewed immutable core checkout; schema coverage cannot be skipped')
        binding = h.strict_json((Path(__file__).parent / 'SOURCE-BINDING.json').read_bytes())['source']
        cls.registry, actual = h.bound_source(SOURCE, binding['commit'], binding['tree'])
        if actual != binding:
            raise RuntimeError('Reviewed immutable handoff source binding differs')

    def prepare(self, values=None):
        return h.make_scope(*(values or fixture()), self.registry)

    def test_install_scope_keeps_full_profile_and_excludes_other_effects(self):
        values = fixture()
        before = copy.deepcopy(values)
        scope = self.prepare(values)
        self.assertEqual(values, before)
        self.assertEqual(scope['components'], ['skvi-engine'])
        self.assertEqual([item['kind'] for item in scope['effects']], ['install'])
        self.assertEqual(scope['ownership_effects'], [{'install_root': values[0]['configured_roots'][0],
                         'component_id': 'skvi-engine', 'receipt_digest': values[4]['receipt_digest'], 'disposition': 'retained'}])
        self.assertEqual(scope['initial_plan_digest'], h.semantic_plan_digest(values[2]['plan'], h.stable_inventory(values[1])))
        self.assertEqual(len(values[2]['plan']['actions']), 4)

    def test_exact_absent_staged_package_wait_is_supported(self):
        values = fixture()
        plan = values[2]['plan']; a = plan['actions'][0]
        a.update(disposition='blocked', blockers=[{'class': 'dependency_wait', 'component_id': a['component_id'],
                       'action_id': a['action_id'], 'retryable': True, 'detail': 'fixture missing staged package'}])
        plan['ready_action_ids'].remove(a['action_id']); plan['blocked_action_ids'].append(a['action_id'])
        reseal_boot(values[2]); self.prepare(values)
        a['blockers'][0]['class'] = 'observation_retryable'; reseal_boot(values[2])
        with self.assertRaises(ValueError): self.prepare(values)

    def test_unknown_fields_and_versions_refuse(self):
        for index, key, value in [(0, 'unexpected', True), (1, 'format_version', 9), (5, 'format_version', True), (5, 'argv', ['rm'])]:
            values = fixture(); values[index][key] = value
            with self.subTest(index=index, key=key), self.assertRaises(ValueError): self.prepare(values)

    def test_digest_and_full_profile_substitution_refuse(self):
        for mutate in (lambda v: v[0]['desired_state']['components'][1].update(activation='active'),
                       lambda v: v[2]['journal'].update(profile_digest=D),
                       lambda v: v[2]['plan']['actions'][0].update(target_state_digest='sha256:'+'a'*64),
                       lambda v: v[1].update(observed_at='2026-11-15T00:00:01Z')):
            values = fixture(); mutate(values)
            with self.assertRaises(ValueError): self.prepare(values)

    def test_inventory_and_initial_cas_substitution_refuse(self):
        for key in ('current_stable_inventory_digest', 'current_observation_digest'):
            values = fixture(); values[2]['journal'][key] = D; reseal_boot(values[2])
            with self.assertRaises(ValueError): self.prepare(values)
        for key in ('expected_apply_journal_digest', 'expected_applied_state_digest'):
            values = fixture(); values[5][key] = D
            with self.assertRaises(ValueError): self.prepare(values)

    def test_prerequisite_or_noninstall_scope_does_not_expand(self):
        for change in ({'prerequisite_action_ids': ['activate-unrelated']}, {'kind': 'uninstall'}, {'disposition': 'waiting'},
                       {'expected_artifact_digests': [D]}, {'target_receptor_id': 'live-receptor'}):
            values = fixture(); values[2]['plan']['actions'][0].update(change); reseal_boot(values[2])
            with self.subTest(change=change), self.assertRaises(ValueError): self.prepare(values)

    def test_replanned_boot_is_not_misrepresented_as_fresh_apply_plan(self):
        values = fixture()
        values[2]['plan']['revision'] = 2
        values[2]['plan']['previous_plan_digest'] = D
        values[2]['journal']['current_plan_revision'] = 2
        reseal_boot(values[2])
        with self.assertRaisesRegex(ValueError, 'separately bound fresh native plan'): self.prepare(values)

    def test_existing_component_refuses_live_replacement(self):
        values = fixture(); p, o, boot, _, receipt, _ = values
        component = p['desired_state']['components'][0]
        o['components'] = [{**{key: component[key] for key in ('component_id', 'component_kind', 'module_id', 'vector_id', 'engine_id')},
                           'packages': [{**component['selected_package'], 'install_root': component['install_root'],
                                         'integrity': 'valid', 'entry_points_validated': True}],
                           'selected_package_digest': receipt['receipt_digest'], 'activation': 'inactive', 'docking': 'undocked',
                           'receptor_id': None, 'capabilities': [], 'platform_compatibility': 'compatible'}]
        seal_observation(o)
        with self.assertRaisesRegex(ValueError, 'not upgrade or live replacement'): self.prepare(values)

    def test_native_utf8_digest_and_literal_escape_are_distinct(self):
        value = {'z': '&<>\u2028\u2029', 'a': '\\u2028'}
        self.assertIn('\u2028'.encode(), h.native_bytes(value))
        self.assertNotEqual(h.native_digest(value), c.digest(value))
        self.assertIn(b'\\\\u2028', h.native_bytes(value))
        self.assertEqual(h.native_digest(value), 'sha256:' + h.sha(h.native_bytes(value)))

    def test_initial_plan_semantics_ignore_only_observation_timestamp(self):
        profile, observation, boot, *_ = fixture()
        before = h.semantic_plan_digest(boot['plan'], h.stable_inventory(observation))
        old_inventory = h.stable_inventory(observation)
        observation['observed_at'] = '2026-11-15T00:00:01Z'
        seal_observation(observation)
        self.assertEqual(old_inventory, h.stable_inventory(observation))
        boot['plan']['observation_digest'] = observation['observation_digest']
        reseal_boot(boot)
        self.assertEqual(before, h.semantic_plan_digest(boot['plan'], h.stable_inventory(observation)))
        boot['plan']['actions'][2]['kind'] = 'activate'
        self.assertNotEqual(before, h.semantic_plan_digest(boot['plan'], h.stable_inventory(observation)))

    def test_duplicate_and_nonintegral_json_refuse(self):
        for value in (b'{"key":1,"key":2}', b'{"key":NaN}', b'{"key":1.1}', b'{"key":9007199254740992}'):
            with self.assertRaises(ValueError): h.strict_json(value)

    def test_payload_and_file_substitution_symlinks_hardlinks_refuse(self):
        with tempfile.TemporaryDirectory(prefix='d05-scope-', dir=str(Path(tempfile.gettempdir()).resolve())) as tmp:
            root = Path(tmp); file = root / 'input'; file.write_bytes(b'fixture'); file.chmod(0o600)
            expected = h.sha(file.read_bytes())
            self.assertEqual(h.read_regular(file, expected), b'fixture')
            with self.assertRaises(ValueError): h.read_regular(file, '0' * 64)
            link = root / 'link'; link.symlink_to(file)
            with self.assertRaises(OSError): h.read_regular(link, expected)
            os.link(file, root / 'hardlink')
            with self.assertRaises(ValueError): h.read_regular(file, expected)

    def test_scope_output_is_private_and_never_overwritten(self):
        with tempfile.TemporaryDirectory(prefix='d05-scope-', dir=str(Path(tempfile.gettempdir()).resolve())) as tmp:
            output = Path(tmp) / 'proposal'; scope = self.prepare()
            with patch.object(h.subprocess, 'check_output', side_effect=AssertionError('no owner call allowed')):
                h.write_proposal(output, scope, {'execution_authorized': False}, {})
            self.assertEqual(output.stat().st_mode & 0o777, 0o700)
            self.assertEqual((output / 'execution-scope.json').stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError): h.write_proposal(output, scope, {}, {})

    def test_cli_proposal_emits_bound_scope_without_invoking_any_owner(self):
        # Source negotiation is deliberately stubbed only in this synthetic test;
        # production CLI always reads immutable Git objects and checks clean HEAD.
        with tempfile.TemporaryDirectory(prefix='d05-scope-', dir=str(Path(tempfile.gettempdir()).resolve())) as tmp:
            root = Path(tmp); source_root = root / 'stage'; source_root.mkdir()
            repository = root / 'repository'; repository.mkdir()
            qxctl = root / 'qxctl'; coordinator = root / 'coordinator'
            for binary in (qxctl, coordinator):
                binary.write_bytes(b'#!/bin/sh\nexit 87\n'); binary.chmod(0o700)
            binary_sha = h.sha(qxctl.read_bytes())
            p, observation, boot, status, receipt, request = fixture()
            for key in ('qxctl_identity', 'coordinator_identity'):
                observation['platform'][key]['executable_digest'] = 'sha256:' + binary_sha
            seal_observation(observation)
            boot['plan']['observation_digest'] = observation['observation_digest']
            boot['journal']['current_observation_digest'] = observation['observation_digest']
            boot['journal']['current_stable_inventory_digest'] = h.stable_inventory(observation)
            reseal_boot(boot)
            payload = source_root / receipt['files'][0]['path']; payload.parent.mkdir(parents=True)
            payload.write_bytes(b'fixture-data')
            receipt_path = source_root / 'share/symphony/receipts/skvi-engine/0.2.0-dev/install-receipt.json'
            receipt_path.parent.mkdir(parents=True)
            source = {'commit': 'a' * 40, 'tree': 'b' * 40, 'files': [], 'synthetic_fixture': True}
            build = {'protocol': 'symphony.distribution.controller-build-binding.v1', 'format_version': 1,
                     'source_commit': source['commit'], 'source_tree': source['tree'],
                     'qxctl_sha256': binary_sha, 'coordinator_sha256': binary_sha}
            catalog = json.loads((Path(__file__).parent.parent / 'owner-catalog/catalog.json').read_text())
            docs = {'profile': p, 'observation': observation, 'boot': boot, 'apply-status': status,
                    'receipt': receipt, 'request': request, 'build-binding': build, 'catalog': catalog}
            paths = {'qxctl': qxctl, 'coordinator': coordinator}
            for name, value in docs.items():
                path = receipt_path if name == 'receipt' else root / (name + '.json')
                path.write_bytes(h.native_bytes(value)); path.chmod(0o600); paths[name] = path
            output = root / 'proposal'
            argv = ['handoff.py', '--repository', str(repository), '--source-root', str(source_root), '--output', str(output),
                    '--source-commit', source['commit'], '--source-tree', source['tree'], '--catalog-digest', catalog['catalog_digest']]
            for name, path in paths.items():
                argv += ['--' + name, str(path), '--' + name + '-sha256', h.sha(path.read_bytes())]
            with patch('sys.argv', argv), patch.object(h, 'bound_source', return_value=(self.registry, source)), \
                    patch.object(h.subprocess, 'check_output', side_effect=AssertionError('owner invocation')), patch('sys.stdout', io.StringIO()):
                h.main()
            proposal = json.loads((output / 'handoff.json').read_text())
            self.assertFalse(proposal['execution_authorized'])
            self.assertFalse(proposal['owner_invoked'])
            self.assertFalse(proposal['fallback_to_unscoped_apply'])
            self.assertEqual(proposal['runtime_capability_validation'], 'pending_native_negotiation')
            self.assertEqual(proposal['apply_argv_proposal'][-2:], ['--execution-scope', str(output / 'execution-scope.json')])
            self.assertEqual(proposal['excluded_action_ids'], ['select-skvi', 'uninstall-unrelated', 'activate-unrelated'])
            self.assertEqual(json.loads((output / 'profile.json').read_text()), p)
            # A supplied scope is pass-through only if it is exactly this proposal.
            supplied = json.loads((output / 'execution-scope.json').read_text())
            supplied['effects'][0]['kind'] = 'uninstall'; supplied['scope_digest'] = h.native_digest(c.without(supplied, 'scope_digest'))
            supplied_path = root / 'substituted-scope.json'; supplied_path.write_bytes(h.native_bytes(supplied))
            supplied_path.chmod(0o600)
            argv[argv.index('--output') + 1] = str(root / 'refused')
            argv += ['--reviewed-scope', str(supplied_path), '--reviewed-scope-sha256', h.sha(supplied_path.read_bytes())]
            with patch('sys.argv', argv), patch.object(h, 'bound_source', return_value=(self.registry, source)), \
                    patch('sys.stderr', io.StringIO()), self.assertRaises(SystemExit):
                h.main()
            self.assertFalse((root / 'refused').exists())

    def test_owner_catalog_unknown_go_and_version_substitution_refuse(self):
        path = Path(__file__).parent.parent / 'owner-catalog/catalog.json'
        catalog = json.loads(path.read_text()); values = fixture()
        h.validate_owner(catalog, catalog['catalog_digest'], values[5], values[4])
        for unit in ('unknown', 'PKG-GO-secure-identity-access-governance'):
            request = copy.deepcopy(values[5]); request['unit_id'] = unit
            with self.assertRaises(ValueError): h.validate_owner(catalog, catalog['catalog_digest'], request, values[4])
        values[4]['version'] = '0.3.0-dev'
        with self.assertRaises(ValueError): h.validate_owner(catalog, catalog['catalog_digest'], values[5], values[4])

    def test_runtime_build_binding_does_not_accept_substitution(self):
        observation = fixture()[1]
        source = {'commit': 'a'*40, 'tree': 'b'*40}
        build = {'protocol': 'symphony.distribution.controller-build-binding.v1', 'format_version': 1,
                 'source_commit': source['commit'], 'source_tree': source['tree'], 'qxctl_sha256': 'd'*64, 'coordinator_sha256': 'd'*64}
        h.verify_build(build, source, observation, 'd'*64, 'd'*64)
        for key in ('source_commit', 'qxctl_sha256', 'coordinator_sha256'):
            bad = dict(build); bad[key] = 'f' * len(bad[key])
            with self.assertRaises(ValueError): h.verify_build(bad, source, observation, 'd'*64, 'd'*64)

    def test_unsupported_schema_keywords_fail_closed(self):
        with self.assertRaises(SchemaError): Registry([{'$id': 'fixture', 'dependentRequired': {'x': ['y']}}])


if __name__ == '__main__':
    unittest.main()
