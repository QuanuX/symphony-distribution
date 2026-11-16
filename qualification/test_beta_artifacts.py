import copy
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from qualification import beta_artifacts as b


class BetaArtifactTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
        self.row = {'run_id': 12, 'run_attempt': 1, 'workflow_commit': 'a' * 40,
            'workflow_path': b.ROLES['package'][0], 'artifact': {'id': 99,
            'name': 'd10-rewrapped-macos15-arm64-1', 'size': 25, 'sha256': 'b' * 64}, 'result_sha256': 'c' * 64}
        self.selection = {'protocol': b.PROTOCOL, 'repository': b.REPOSITORY,
            'profile': 'macos15-arm64', 'artifacts': {'package': self.row}}
        self.run = {'id': 12, 'run_attempt': 1, 'head_sha': 'a' * 40, 'path': b.ROLES['package'][0],
            'status': 'completed', 'conclusion': 'success', 'event': 'workflow_dispatch',
            'repository': {'full_name': b.REPOSITORY}, 'head_repository': {'full_name': b.REPOSITORY}}
        self.artifact = {'id': 99, 'name': self.row['artifact']['name'], 'size_in_bytes': 25,
            'digest': 'sha256:' + 'b' * 64, 'expired': False, 'workflow_run': {'id': 12, 'head_sha': 'a' * 40}}

    def tearDown(self): self.temp.cleanup()

    def check_selection(self, selected=None):
        path = self.root / 'selection.json'; path.write_text(json.dumps(selected or self.selection))
        return b.validate_selection(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_exact_source_selection_and_successful_transport(self):
        self.assertEqual(self.check_selection(), self.selection)
        self.assertEqual(b.validate_metadata(self.row, self.run, self.artifact)['conclusion'], 'success')

    def test_failed_or_incomplete_run_cannot_supply_release_inputs(self):
        for field, value in [('status', 'in_progress'), ('conclusion', 'failure'), ('conclusion', 'cancelled')]:
            altered = dict(self.run, **{field: value})
            with self.subTest(field=field,value=value), self.assertRaises(ValueError): b.validate_metadata(self.row, altered, self.artifact)

    def test_wrong_attempt_commit_workflow_or_repository_refused(self):
        for field, value in [('run_attempt', 2), ('head_sha', 'd' * 40), ('path', 'another.yml'),
                ('event', 'pull_request'), ('head_repository', {'full_name': 'another/repo'})]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                b.validate_metadata(self.row, dict(self.run, **{field: value}), self.artifact)

    def test_expired_replaced_or_different_artifact_refused(self):
        for field, value in [('expired', True), ('id', 100), ('digest', 'sha256:' + 'd' * 64),
                ('size_in_bytes', 26), ('workflow_run', {'id': 13, 'head_sha': 'a' * 40})]:
            with self.subTest(field=field), self.assertRaises(ValueError):
                b.validate_metadata(self.row, self.run, dict(self.artifact, **{field: value}))

    def test_different_platform_name_and_arbitrary_role_refused(self):
        other = copy.deepcopy(self.selection); other['profile'] = 'ubuntu24.04-amd64'
        with self.assertRaises(ValueError): self.check_selection(other)
        other = copy.deepcopy(self.selection); other['artifacts']['unselected'] = other['artifacts'].pop('package')
        with self.assertRaises(ValueError): self.check_selection(other)

    def test_selection_digest_and_duplicate_json_key_refused(self):
        path = self.root / 'selection.json'; path.write_text(json.dumps(self.selection))
        with self.assertRaises(ValueError): b.validate_selection(path, '0' * 64)
        path.write_text('{"protocol":"first","protocol":"second"}')
        with self.assertRaises(ValueError): b.validate_selection(path, hashlib.sha256(path.read_bytes()).hexdigest())

    def test_client_result_requires_actual_package_cases(self):
        value = {'profile':'macos15-arm64','state':'primary_client_engineering_checks_passed',
            'actual_codex_cases':22,'client_executed_from_verified_package':True,'package_is_original_git_tree':False}
        path=self.root/'result.json';path.write_text(json.dumps(value));digest=hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(b.result_identity(self.root,'macos15-arm64','client',digest),value)
        value['actual_codex_cases']=0;path.write_text(json.dumps(value));digest=hashlib.sha256(path.read_bytes()).hexdigest()
        with self.assertRaises(ValueError): b.result_identity(self.root,'macos15-arm64','client',digest)

    def test_nested_consumer_result_does_not_use_tools_result(self):
        path=self.root/'d12-consumer/result.json';path.parent.mkdir()
        path.write_text(json.dumps({'profile':'macos15-arm64','state':'primary_shell_install_refusals_and_named_removal_passed'}))
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(b.result_identity(self.root,'macos15-arm64','consumer',digest)['profile'],'macos15-arm64')
        with self.assertRaises(ValueError): b.result_identity(self.root,'ubuntu24.04-amd64','consumer',digest)

    def test_native_pkg_uses_exact_nested_result_and_platform(self):
        value={'profile':'macos15-arm64','state':'native_pkg_install_and_named_carrier_removal_passed',
               'native_pkg_executed':True,'all_named_carriers_removed':True,'original_inputs_unchanged':True}
        path=self.root/'d14-pkg-public/result.json';path.parent.mkdir();path.write_text(json.dumps(value))
        digest=hashlib.sha256(path.read_bytes()).hexdigest()
        self.assertEqual(b.result_identity(self.root,'macos15-arm64','native_pkg',digest),value)
        with self.assertRaises(ValueError):b.result_identity(self.root,'ubuntu24.04-amd64','native_pkg',digest)
        value['native_pkg_executed']=False;path.write_text(json.dumps(value))
        with self.assertRaises(ValueError):b.result_identity(self.root,'macos15-arm64','native_pkg',hashlib.sha256(path.read_bytes()).hexdigest())


if __name__ == '__main__': unittest.main()
