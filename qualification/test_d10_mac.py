import copy
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

from qualification import d10_mac as m


class MacTests(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(); self.root = Path(self.temporary.name).resolve()
    def tearDown(self): self.temporary.cleanup()

    def test_explicit_optin_precedes_any_input_or_execution(self):
        with patch.object(m.delivery_check, 'admit_delivery') as admission:
            with self.assertRaisesRegex(ValueError, 'opt-in'):
                m.qualify(SimpleNamespace(allow_selected_mac=False))
            admission.assert_not_called()

    def test_only_selected_supplemental_intel_mac_is_admitted(self):
        host = {'system': 'darwin', 'architecture': 'amd64', 'distribution': 'macos', 'version': '26.7.1', 'wsl': False}
        m.host_admission(m.PROFILE, host)
        for profile, observed in [('macos15-arm64', host), (m.PROFILE, host | {'architecture': 'arm64'}),
                                  (m.PROFILE, host | {'system': 'linux'})]:
            with self.assertRaises(ValueError): m.host_admission(profile, observed)

    def test_unsigned_or_changed_auxiliary_record_refused(self):
        path = self.root / 'record.json'; path.write_bytes(b'original')
        signed = {'record.json': {'sha256': m.signing.digest(path), 'size': 8}}
        self.assertEqual(m.signed_artifact(self.root, signed, 'record.json'), path)
        with self.assertRaisesRegex(ValueError, 'not in the signed'): m.signed_artifact(self.root, {}, 'record.json')
        path.write_bytes(b'modified')
        with self.assertRaisesRegex(ValueError, 'bytes or size'): m.signed_artifact(self.root, signed, 'record.json')

    def fixture(self):
        rows = [{'unit_id': str(i), 'filename': f'package-{i}-1-build.conda', 'sha256': 'a'*64, 'md5': 'b'*32,
                 'size': 1, 'name': f'package-{i}', 'version': '1', 'build': 'build', 'build_number': 0,
                 'subdir': 'osx-64', 'depends': []} for i in range(59)]
        cohort = {'state': 'archives_audited', 'archives': rows, 'entries': [{}]*59, 'conda_subdir': 'osx-64',
                  'profile': m.PROFILE, 'cohort_digest': 'sha256:'+'c'*64}
        shell = {'format': 'sh', 'archive_count': 59, 'filename': 'review.sh', 'sha256': 'd'*64, 'bootstrap_sha256': 'e'*64}
        wrapper = {'protocol': 'symphony.distribution.d08-unsigned-wrapper.v1', 'state': 'unsigned_wrappers_audited',
                   'profile': m.PROFILE, 'cohort_digest': cohort['cohort_digest'], 'archives': rows,
                   'publication_authorized': False, 'release_acceptance_complete': False, 'runtime_activated': False,
                   'wrappers': [shell]}
        return cohort, wrapper

    def test_wrapper_cohort_and_no_activation_are_bound(self):
        cohort, wrapper = self.fixture(); self.assertEqual(m.wrapper_selection(cohort, wrapper)['filename'], 'review.sh')
        for key, value in [('profile', 'macos15-arm64'), ('cohort_digest', 'sha256:'+'f'*64),
                           ('runtime_activated', True), ('publication_authorized', True)]:
            bad = copy.deepcopy(wrapper); bad[key] = value
            with self.assertRaises(ValueError): m.wrapper_selection(cohort, bad)
        bad = copy.deepcopy(wrapper); bad['archives'][0]['sha256'] = 'f'*64
        with self.assertRaises(ValueError): m.wrapper_selection(cohort, bad)

    def test_missing_duplicate_or_traversing_shell_refused(self):
        for kind in ('missing', 'duplicate', 'traversal'):
            cohort, wrapper = self.fixture()
            if kind == 'missing': wrapper['wrappers'] = []
            elif kind == 'duplicate': wrapper['wrappers'] *= 2
            else: wrapper['wrappers'][0]['filename'] = '../review.sh'
            with self.assertRaises(ValueError): m.wrapper_selection(cohort, wrapper)

    def test_isolated_environment_does_not_inherit_credentials_or_home(self):
        env = m.isolated_environment(self.root)
        self.assertEqual(env['HOME'], str(self.root / 'home'))
        self.assertNotIn('CONDA_SOLVER', env)
        self.assertEqual(env['CONDA_ALWAYS_COPY'], 'true'); self.assertEqual(env['CONDA_OFFLINE'], 'true'); self.assertEqual(env['CONDA_REGISTER_ENVS'], 'false')
        self.assertFalse(any(key in env for key in ('AWS_ACCESS_KEY_ID', 'GH_TOKEN', 'ANACONDA_API_TOKEN', 'DYLD_INSERT_LIBRARIES')))
        self.assertEqual((self.root / 'home/.zshrc').read_bytes(), b'# isolated caller state must survive\n')
        self.assertFalse((self.root / 'prefix').exists())

    def test_carrier_namespace_detects_extra_bytes_modes_and_aliases(self):
        base = self.root / 'share/symphony/carriers/unit/1/build'; base.mkdir(parents=True)
        path = base / 'payload.tar'; path.write_bytes(b'original'); path.chmod(0o644)
        before = m.carrier_namespace(self.root)
        path.chmod(0o755); self.assertNotEqual(m.carrier_namespace(self.root), before)
        path.unlink(); path.symlink_to(self.root / 'outside')
        with self.assertRaises(ValueError): m.carrier_namespace(self.root)

    def test_timeout_signal_and_wrong_refusal_exit_never_pass(self):
        for code in (124, -9, 2):
            with patch.object(m, 'bounded_run', return_value=code):
                with self.assertRaises(ValueError): m.invoke(['command'], {}, self.root / f'log-{code}', expected=1)

    def test_installed_metadata_requires_exact_identity_and_count(self):
        directory = self.root / 'conda-meta'; directory.mkdir()
        row = {'name': 'unit', 'version': '1', 'build': 'exact', 'subdir': 'osx-64'}
        p = directory / 'unit.json'; p.write_text(json.dumps(row))
        self.assertEqual(m.installed_metadata(self.root, [row]), ['unit'])
        p.write_text(json.dumps(row | {'build': 'different'}))
        with self.assertRaises(ValueError): m.installed_metadata(self.root, [row])

    def test_execution_uses_private_readonly_snapshot_after_original_changes(self):
        source = self.root / 'source.sh'; source.write_bytes(b'exact signed script')
        out = self.root / 'private'; out.mkdir(mode=0o700)
        row = {'sha256': m.signing.digest(source), 'size': source.stat().st_size}
        selected = m.snapshot_wrapper(source, row, out)
        source.write_bytes(b'changed original')
        self.assertEqual(selected.read_bytes(), b'exact signed script')
        self.assertEqual(selected.stat().st_mode & 0o777, 0o400)
        self.assertEqual(m.signing.digest(selected), row['sha256'])

    def test_snapshot_rejects_mismatch_alias_and_existing_target(self):
        source = self.root / 'source.sh'; source.write_bytes(b'exact signed script')
        out = self.root / 'private'; out.mkdir(mode=0o700)
        row = {'sha256': m.signing.digest(source), 'size': source.stat().st_size}
        with self.assertRaises(ValueError): m.snapshot_wrapper(source, row | {'sha256': 'f'*64}, out)
        self.assertFalse((out / 'selected-wrapper.sh').exists())
        alias = self.root / 'alias.sh'; alias.symlink_to(source)
        with self.assertRaises((ValueError, OSError)): m.snapshot_wrapper(alias, row, out)
        (out / 'selected-wrapper.sh').write_bytes(b'caller')
        with self.assertRaises(FileExistsError): m.snapshot_wrapper(source, row, out)
        self.assertEqual((out / 'selected-wrapper.sh').read_bytes(), b'caller')

if __name__ == '__main__': unittest.main()
