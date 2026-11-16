import argparse
import copy
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('repair_cohort', Path(__file__).with_name('d06_repair_cohort.py'))
r = importlib.util.module_from_spec(spec); spec.loader.exec_module(r)


class RepairCohortTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
    def tearDown(self): self.temp.cleanup()

    def test_exact_reverse_dependency_closure_is_eight_units(self):
        plan = r.read(r.ROOT / 'build-cohort/cohort.json')
        for profile in plan['profiles'].values():
            units = r.repair_units(profile['native_build_order'])
            self.assertEqual({u['component_id'] for u in units}, r.REPAIR_IDS)
            self.assertEqual(len(units), 8)
            self.assertEqual([u for u in profile['native_build_order'] if u in units], units)

    def test_new_transitive_dependant_is_refused_instead_of_expanding_scope(self):
        profile = next(iter(r.read(r.ROOT / 'build-cohort/cohort.json')['profiles'].values()))
        units = copy.deepcopy(profile['native_build_order'])
        units.append({'component_id': 'extra', 'source_root': 'modules/extra',
                      'dependency_source_roots': ['modules/sqav-capture-cpp']})
        with self.assertRaisesRegex(ValueError, 'eight-unit'): r.repair_units(units)

    def test_inherited_bytes_and_modes_cannot_change(self):
        before = [{'path': 'owned', 'sha256': 'a'}, {'path': 'keep', 'sha256': 'b', 'mode': 420},
                  {'path': r.EXTERNAL_REPAIR, 'sha256': 'c'}]
        r.verify_inherited(before, before, {'owned'})
        for changed in ([{'path': 'keep', 'sha256': 'x', 'mode': 420}, before[2]],
                        [{'path': 'keep', 'sha256': 'b', 'mode': 493}, before[2]],
                        [before[1]], [before[1], before[2], {'path': 'extra', 'sha256': 'x'}]):
            with self.assertRaises(ValueError): r.verify_inherited(before, changed, {'owned'}, allow_external=True)

    def test_only_external_zstd_archive_may_change_after_external_finalization(self):
        before = [{'path': 'owned'}, {'path': r.EXTERNAL_REPAIR, 'sha256': 'a'}, {'path': 'third-party/lib/libcurl.dylib', 'sha256': 'same'}]
        after = copy.deepcopy(before); after[1]['sha256'] = 'normalized'
        with self.assertRaises(ValueError): r.verify_inherited(before, after, {'owned'})
        self.assertEqual(r.verify_inherited(before, after, {'owned'}, True), [r.EXTERNAL_REPAIR])
        after[2]['sha256'] = 'different'
        with self.assertRaises(ValueError): r.verify_inherited(before, after, {'owned'}, True)

    def test_copy_preserves_original_sealed_configure_logs_and_provenance(self):
        original = self.root / 'origin'; target = self.root / 'target'
        for p in (original / 'logs', target / 'logs'): p.mkdir(parents=True)
        text = '-- The CXX compiler identification is AppleClang 21.0.0\n'
        path = original / 'logs/unit-configure.log'; path.write_text(text)
        sealed = [{'name': path.name, 'sha256': r.sha(path), 'exit_code': 0}]
        units = [{'component_id': 'unit'}, {'component_id': 'rebuilt'}]
        rows, proof = r.copy_configure_logs(original, target, units, {'rebuilt'}, sealed)
        self.assertEqual(rows, sealed)
        self.assertEqual((target / 'logs' / path.name).read_text(), text)
        self.assertTrue(proof[0]['original_log_sealed_by_round'])
        path.write_text(text + 'changed')
        with self.assertRaisesRegex(ValueError, 'sealed'): r.copy_configure_logs(original, target, units, {'rebuilt'}, sealed)

    def test_unsealed_retained_log_is_not_retroactively_claimed_sealed(self):
        original = self.root / 'origin'; target = self.root / 'target'
        for p in (original / 'logs', target / 'logs'): p.mkdir(parents=True)
        (original / 'logs/unit-configure.log').write_text('-- The CXX compiler identification is AppleClang 21.0.0\n')
        _, proof = r.copy_configure_logs(original, target, [{'component_id': 'unit'}], set(), None)
        self.assertFalse(proof[0]['original_log_sealed_by_round'])

    def test_origin_helper_binding_uses_reviewed_git_record_without_current_byte_equality(self):
        commit = next(iter(r.ORIGIN_COMMITS))
        names = ['build-cohort/build.py', 'build-cohort/finalize_native.py']
        blobs = {n: ('original-' + n).encode() for n in names + ['qualification/native_campaign.py', 'source-export/export_source.py']}
        def git(argv, **kwargs):
            if 'ls-tree' in argv: return ('\n'.join(names) + '\n').encode()
            return blobs[argv[-1].split(':', 1)[1]]
        summary = {'build_helpers': {Path(n).name: r.hashlib.sha256(blobs[n]).hexdigest() for n in names},
                   'imported_helpers': {n: r.hashlib.sha256(blobs[n]).hexdigest() for n in blobs if not n.startswith('build-cohort')}}
        summary['builder_sha256'] = summary['build_helpers']['build.py']
        with patch.object(r.subprocess, 'check_output', side_effect=git):
            self.assertEqual(r.original_helpers(summary, commit)['git_commit'], commit)
            summary['build_helpers']['finalize_native.py'] = 'altered'
            with self.assertRaisesRegex(ValueError, 'reviewed Git'): r.original_helpers(summary, commit)
        with self.assertRaisesRegex(ValueError, 'reviewed D06'): r.original_helpers({}, '0' * 40)

    def test_completed_origin_rejects_incomplete_or_mutated_round(self):
        origin = self.root / 'origin'; (origin / 'round-1').mkdir(parents=True)
        report = {'state': 'built_and_sdk_checked', 'native_count': 51, 'go_commands': [{}] * 6,
                  'sdk_audit': {'status': 'passed'}, 'installed_owner_audit': {'status': 'passed'},
                  'loader_audit': {'status': 'passed'}, 'logs': []}
        r.dump(origin / 'round-1/result.json', report)
        summary = {'protocol': 'symphony.distribution.clean-cohort.v1', 'acceptance_complete': False,
                   'publication_authorized': False, 'source_commit': 'commit', 'source_tree': 'tree',
                   'plan_sha256': r.sha(r.ROOT / 'build-cohort/cohort.json'), 'state': 'built_and_sdk_checked',
                   'rounds': [{'directory': 'round-1', 'native_count': 51, 'go_count': 6,
                               'result_sha256': r.sha(origin / 'round-1/result.json')}]}
        args = argparse.Namespace(origin=origin, origin_tool_commit='ignored', retained_qualification=None, retained_qualification_sha256=None)
        with patch.object(r, 'original_helpers'):
            self.assertEqual(r.admit_record(args, summary, {'source_commit': 'commit', 'source_tree': 'tree'})[1]['kind'], 'completed_full_cohort')
            (origin / 'INCOMPLETE.json').write_text('{}')
            with self.assertRaisesRegex(ValueError, 'did not complete'): r.admit_record(args, summary, {'source_commit': 'commit', 'source_tree': 'tree'})
            (origin / 'INCOMPLETE.json').unlink(); report['native_count'] = 50; r.dump(origin / 'round-1/result.json', report)
            with self.assertRaisesRegex(ValueError, 'round differs'): r.admit_record(args, summary, {'source_commit': 'commit', 'source_tree': 'tree'})

    def test_retained_origin_requires_explicit_exact_qualification_digest(self):
        origin = self.root / 'origin'; retained = self.root / 'retained'; origin.mkdir(); retained.mkdir()
        r.dump(retained / 'result.json', {})
        summary = {'protocol': 'symphony.distribution.clean-cohort.v1', 'acceptance_complete': False,
                   'publication_authorized': False, 'source_commit': 'commit', 'source_tree': 'tree',
                   'plan_sha256': r.sha(r.ROOT / 'build-cohort/cohort.json')}
        args = argparse.Namespace(origin=origin, origin_tool_commit='ignored', retained_qualification=retained, retained_qualification_sha256='0' * 64)
        with patch.object(r, 'original_helpers'):
            with self.assertRaisesRegex(ValueError, 'report digest differs'):
                r.admit_record(args, summary, {'source_commit': 'commit', 'source_tree': 'tree'})

    def test_go_artifacts_require_all_six_exact_bytes_versions(self):
        prefix = self.root / 'prefix'; rows, commands = [], []
        for i in range(6):
            cid = 'go-' + str(i); path = prefix / 'go' / cid / 'bin/command'; path.parent.mkdir(parents=True); path.write_bytes(b'binary')
            rows.append({'component_id': cid, 'version': '1.0', 'sha256': r.sha(path)})
            commands.append({'component_id': cid, 'package_version': '1.0', 'binary_name': 'command'})
        self.assertEqual(r.verify_go(prefix, rows, commands), rows)
        path.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'artifact differs'): r.verify_go(prefix, rows, commands)
        with self.assertRaisesRegex(ValueError, 'six unique'): r.verify_go(prefix, rows[:-1], commands)


if __name__ == '__main__': unittest.main()
