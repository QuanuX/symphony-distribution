"""Selection, closure, source-binding and false-acceptance regressions."""
import copy
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

import plan


def documents_from_reference():
    """Reconstitute independent source-shaped inputs for refusal mutations.

    Actual source-to-reference equality is checked separately by plan.py verify;
    these fixtures exercise semantics without a network/core checkout in tests.
    """
    reference = plan.read_json(Path(__file__).with_name('cohort.json').read_bytes())
    profile = reference['profiles']['macos15-arm64']
    units = profile['native_build_order'] + reference['optional_native_units']
    recipes, native = [], []
    for row in units:
        recipes.append({'id': row['recipe_id'], 'kind': 'native_receipt_unit',
            'source_roots': [row['source_root']], 'proposed_selection': row['selection'],
            'project_version': row['project_version'], 'proposed_package_version': row['version'],
            'installed_options': row['installed_options'], 'build_targets': row['build_targets'],
            'sdk_exports': row['exported_packages'], 'qualification_group': row['qualification_group'],
            'dependency_recipe_ids': ['PKG-NATIVE-' + path.rsplit('/', 1)[1] for path in row['dependency_source_roots']],
            'candidate_profiles': row['candidate_profiles'], 'external_dependency_refs': row['external_dependency_refs']})
        native.append({'component_id': row['component_id'], 'path': row['source_root'],
            'project_version': row['project_version'], 'package_release_version': row['version'],
            'installed_options': row['installed_options'], 'artifact_targets': row['build_targets'],
            'first_party_sdk_dependencies': row['first_party_sdk_dependencies'],
            'dependency_paths_in_build_order': row['dependency_source_roots'],
            'exported_packages': row['exported_packages'], 'installable': True,
            'installed_sdk_consumer_checks': row['installed_sdk_consumer_checks'],
            'qualification_group': row['qualification_group']})
    native.append({'path': 'tools/authoring-cpp', 'installable': False,
                   'dependency_paths_in_build_order': [], 'exported_packages': []})
    commands = profile['go_commands'] + reference['optional_go_commands']
    for row in commands:
        recipes.append({'id': row['recipe_id'], 'kind': 'go_command', 'source_roots': [row['source_root']],
            'proposed_selection': row['selection'], 'proposed_package_version': row['package_version'],
            'candidate_profiles': row['candidate_profiles'], 'binary_name': row['binary_name'],
            'main_package': row['main_package']})
    construction = {}
    for name, row in reference['profiles'].items():
        construction[name] = {'native_build_order': row['native_build_order'],
            'go_commands': [{'id': x['recipe_id'], 'binary_name': x['binary_name'],
                'main_package': x['main_package'], 'proposed_package_version': x['package_version'],
                'version_symbol': x['version_symbol']} for x in row['go_commands']]}
    modules = copy.deepcopy(reference['go_module_requirements'])
    for row in modules:
        row['module_replacements'] = []
    return {'dependencies': {'native_components': native,
                'native_build_order': [x['path'] for x in native],
                'component_roots': [{'path': x['source_root']} for x in reference['source_root_dispositions']],
                'go_workspace': {'go': '1.26.5'}, 'go_modules': modules,
                'external_dependencies': reference['external_dependency_requirements']},
            'identities': {'required_profiles': list(plan.PROFILES), 'go_artifacts': commands},
            'packages': {'package_recipes': recipes, 'source_root_dispositions': reference['source_root_dispositions']},
            'construction': {'profiles': construction},
            'platforms': {'profiles': [row['platform_contract'] for row in reference['profiles'].values()]},
            'sdk': reference['sdk_contract']}


class PlanTests(unittest.TestCase):
    def setUp(self):
        self.docs = documents_from_reference()
        self.binding = {'source_commit': 'a' * 40, 'source_tree': 'b' * 40, 'binding_digest': 'c' * 64}

    def derive(self):
        return plan.derive(self.docs, self.binding, [])

    def test_full_cohort_keeps_optional_and_host_claims_separate(self):
        result = self.derive()
        self.assertEqual(len(result['source_root_dispositions']), 73)
        for name, row in result['profiles'].items():
            self.assertEqual(len(row['native_build_order']), 51)
            self.assertEqual(len(row['go_commands']), 6)
            self.assertEqual(len(row['sdk_producers']), 20)
            self.assertEqual(len(row['separately_selectable_recipe_ids']), 8 if name == 'macos15-arm64' else 9)
            self.assertFalse(row['release_supported'])
            self.assertFalse(row['fresh_host_accepted'])
        self.assertFalse(result['release_acceptance_complete'])
        self.assertFalse(result['publication_authorized'])
        self.assertFalse(result['build_policy']['development_absolute_rpath_allowed'])
        self.assertIn('copied_sdk_consumers_against_final_stage', result['required_final_stage_gates'])

    def test_core_dependency_only_receipts_not_sliced(self):
        selected = self.derive()['profiles']['macos15-arm64']['native_build_order']
        closure = [r for r in selected if r['selection'] == 'include_complete_receipt_as_core_dependency_only']
        self.assertEqual(len(closure), 4)
        self.assertTrue(all(r['receipt_scope'] == 'complete_native_receipt_v2' for r in closure))

    def test_core_unit_omission_refused(self):
        self.docs['packages']['package_recipes'][0]['proposed_selection'] = 'separately_selectable_native_unit'
        with self.assertRaisesRegex(ValueError, '51/8'): self.derive()

    def test_duplicate_source_recipe_refused(self):
        row = copy.deepcopy(self.docs['packages']['package_recipes'][0]); row['id'] += '-duplicate'
        self.docs['packages']['package_recipes'].append(row)
        with self.assertRaisesRegex(ValueError, '59'): self.derive()

    def test_reversed_dependency_order_refused(self):
        order = self.docs['dependencies']['native_build_order']; order[0], order[1] = order[1], order[0]
        with self.assertRaisesRegex(ValueError, 'dependency order'): self.derive()

    def test_core_dependency_outside_selected_closure_refused(self):
        row = self.docs['dependencies']['native_components'][0]
        row['dependency_paths_in_build_order'] = ['modules/shv-pdf-adapter']
        order = self.docs['dependencies']['native_build_order']; order.remove('modules/shv-pdf-adapter'); order.insert(0, 'modules/shv-pdf-adapter')
        with self.assertRaises(ValueError): self.derive()

    def test_stale_w12_version_refused(self):
        self.docs['construction']['profiles']['macos15-arm64']['native_build_order'][0]['version'] = 'unexpected'
        with self.assertRaisesRegex(ValueError, 'version'): self.derive()

    def test_missing_source_disposition_refused(self):
        self.docs['packages']['source_root_dispositions'].pop()
        with self.assertRaisesRegex(ValueError, '73'): self.derive()

    def test_missing_sdk_export_coverage_refused(self):
        self.docs['sdk']['sdk_producers'][0]['exports'] = []
        with self.assertRaisesRegex(ValueError, 'SDK producer/export'): self.derive()

    def test_go_workspace_replacement_refused(self):
        self.docs['dependencies']['go_modules'][0]['module_replacements'] = [{'Path': '../other'}]
        with self.assertRaisesRegex(ValueError, 'replacement'): self.derive()

    def test_go_command_version_drift_refused(self):
        row = next(r for r in self.docs['packages']['package_recipes'] if r['kind'] == 'go_command')
        row['proposed_package_version'] = 'unexpected'
        with self.assertRaisesRegex(ValueError, 'Go recipe'): self.derive()

    def test_optional_observer_stays_linux_only(self):
        result = self.derive()
        observer = 'PKG-NATIVE-snv-local-observer'
        self.assertNotIn(observer, result['profiles']['macos15-arm64']['separately_selectable_recipe_ids'])
        self.assertIn(observer, result['profiles']['ubuntu24.04-arm64']['separately_selectable_recipe_ids'])

    def test_exact_curl_pin_refused_when_changed(self):
        next(x for x in self.docs['dependencies']['external_dependencies'] if x['id'] == 'CURL')['version'] = '9.0.0'
        with self.assertRaisesRegex(ValueError, 'pins'): self.derive()

    def test_duplicate_json_field_refused(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'): plan.read_json('{"scope":1,"scope":2}')

    def test_unsafe_source_root_refused(self):
        self.docs['dependencies']['component_roots'][0]['path'] = '../outside'
        self.docs['packages']['source_root_dispositions'][0]['source_root'] = '../outside'
        with self.assertRaisesRegex(ValueError, 'unsafe'): self.derive()


class SourceBindingTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        documents = documents_from_reference()
        for key, name in plan.INPUTS.items():
            path = self.root / name; path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(json.dumps(documents[key]))
        self.git('init', '-q')
        self.git('add', '.')
        self.git('-c', 'user.name=D06 fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        self.binding = {'source_commit': self.git('rev-parse', 'HEAD').strip(),
                        'source_tree': self.git('rev-parse', 'HEAD^{tree}').strip(), 'binding_digest': 'c' * 64}

    def tearDown(self):
        self.temp.cleanup()

    def git(self, *args):
        return subprocess.check_output(['git', '-C', str(self.root), *args], text=True)

    def test_exact_git_source_and_every_input_hash_bound(self):
        result = plan.generate(self.root, self.binding)
        self.assertEqual(len(result['source_inputs']), len(plan.INPUTS))
        plan.validate(result, self.root, self.binding)
        result['profiles']['macos15-arm64']['release_supported'] = True
        with self.assertRaisesRegex(ValueError, 'cohort differs'): plan.validate(result, self.root, self.binding)

    def test_dirty_map_cannot_be_relabelled_as_commit(self):
        target = self.root / plan.INPUTS['dependencies']; target.write_text(target.read_text() + '\n')
        with self.assertRaisesRegex(ValueError, 'dirty source'): plan.generate(self.root, self.binding)

    def test_wrong_source_head_refused(self):
        self.binding['source_commit'] = '0' * 40
        with self.assertRaisesRegex(ValueError, 'HEAD differs'): plan.generate(self.root, self.binding)

    def test_symlink_map_refused(self):
        target = self.root / plan.INPUTS['dependencies']; moved = target.with_suffix('.other'); target.rename(moved); target.symlink_to(moved.name)
        with self.assertRaisesRegex(ValueError, 'symlink'): plan.generate(self.root, self.binding)


if __name__ == '__main__':
    unittest.main()
