"""Negative evidence-binding tests; these synthetic records are not qualification.

No Conda import, native executable, host service, or account operation is needed.
Actual archives/transactions remain the separate explicit conda_journeys gate.
"""
from copy import deepcopy
from pathlib import Path
import tempfile
import unittest

import conda_journeys as j


class JourneyEvidence(unittest.TestCase):
    def setUp(self):
        self.catalog = j.load(j.ROOT / 'go-owner-catalog.json')
        recipes = []
        archives = []
        for component in sorted(j.d.owners.OWNERS):
            for number in (0, 1):
                row = {'component_id': component, 'build_number': number,
                       'recipe': f'{component}/{number}/recipe', 'manifest_digest': 'sha256:' + '1' * 64,
                       'carrier_destination': f'share/symphony/carriers/{component}/fixture/build{number}',
                       'build_string': f'fixture{number}'}
                recipes.append(row)
                archives.append({**row, 'archive': f'{component}-{number}/fixture.conda', 'audit': {}})
        self.inputs = {'protocol': 'symphony.distribution.conda-journey-inputs.v1',
                       'source_commit': self.catalog['source_commit'], 'catalog_digest': self.catalog['catalog_digest'],
                       'profile': j.d.owners.FIXTURE_PROFILE, 'fixture': True, 'recipes': recipes,
                       'archives': archives, 'two_packaging_builds': True, 'two_native_versions': False,
                       'publication_authorized': False}

    def test_exact_fourteen_identity_rows_validate_without_asserting_execution(self):
        profile, fixture, units = j.validate_inputs(self.inputs, self.catalog)
        self.assertEqual(profile, j.d.owners.FIXTURE_PROFILE)
        self.assertIs(fixture, True)
        self.assertEqual(units, {(component, number) for component in j.d.owners.OWNERS for number in (0, 1)})
        self.assertNotIn('transactions', self.inputs)

    def test_source_catalog_and_qualification_claim_mismatch_refused(self):
        for field, value in [('source_commit', '0' * 40), ('catalog_digest', 'sha256:' + '0' * 64),
                             ('two_packaging_builds', False), ('two_native_versions', True),
                             ('publication_authorized', True), ('fixture', False), ('profile', 'unreviewed-host')]:
            with self.subTest(field=field):
                changed = deepcopy(self.inputs)
                changed[field] = value
                with self.assertRaises(ValueError):
                    j.validate_inputs(changed, self.catalog)

    def test_missing_duplicate_unknown_and_extra_coverage_refused(self):
        changes = []
        missing = deepcopy(self.inputs)
        missing['archives'].pop()
        changes.append(missing)
        duplicate = deepcopy(self.inputs)
        duplicate['archives'][-1] = deepcopy(duplicate['archives'][0])
        changes.append(duplicate)
        extra = deepcopy(self.inputs)
        extra['archives'].append(deepcopy(extra['archives'][0]))
        changes.append(extra)
        unknown = deepcopy(self.inputs)
        unknown['archives'][0]['component_id'] = 'unqualified-owner'
        changes.append(unknown)
        boolean_number = deepcopy(self.inputs)
        boolean_number['archives'][0]['build_number'] = False
        changes.append(boolean_number)
        for number, changed in enumerate(changes):
            with self.subTest(case=number), self.assertRaises(ValueError):
                j.validate_inputs(changed, self.catalog)

    def test_recipe_drift_unknown_fields_and_archive_escape_refused(self):
        for field, value in [('build_string', 'stale-build'), ('manifest_digest', 'sha256:' + 'f' * 64),
                             ('archive', '../../outside.conda'), ('audit', 'claimed-success')]:
            with self.subTest(field=field):
                changed = deepcopy(self.inputs)
                changed['archives'][0][field] = value
                with self.assertRaises(ValueError):
                    j.validate_inputs(changed, self.catalog)
        changed = deepcopy(self.inputs)
        changed['archives'][0]['claimed_complete'] = True
        with self.assertRaises(ValueError):
            j.validate_inputs(changed, self.catalog)
        changed = deepcopy(self.inputs)
        changed['recipes'][-1] = deepcopy(changed['recipes'][0])
        with self.assertRaises(ValueError):
            j.validate_inputs(changed, self.catalog)

    def test_stale_audit_cannot_attest_changed_or_different_archive(self):
        # An observed audit represents fresh archive inspection by the builder;
        # the helper only binds its result to the actual copy and saved report.
        data = b'actual inspected archive bytes'
        digest = j.d.sha(data)
        observed = {'source_commit': self.catalog['source_commit'], 'exact_payload_verified': True,
                    'lifecycle_hooks': [], 'runtime_dependencies': [], 'publication_authorized': False}
        row = {'audit': {**observed, 'archive_sha256': digest, 'archive_size': len(data), 'archive_filename': 'selected.conda'}}
        j.validate_archive_evidence(row, observed, 'selected.conda', digest, len(data), data)
        for field, value in [('source_commit', '0' * 40), ('exact_payload_verified', False),
                             ('lifecycle_hooks', ['post-link']), ('runtime_dependencies', ['python']),
                             ('publication_authorized', True), ('archive_sha256', '0' * 64),
                             ('archive_size', len(data) + 1), ('archive_filename', 'other.conda')]:
            changed = deepcopy(row)
            changed['audit'][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'audit does not match'):
                j.validate_archive_evidence(changed, observed, 'selected.conda', digest, len(data), data)
        with self.assertRaisesRegex(ValueError, 'changed between copy and audit'):
            j.validate_archive_evidence(row, observed, 'selected.conda', digest, len(data), b'changed bytes of same length!')
        with self.assertRaisesRegex(ValueError, 'changed between copy and audit'):
            j.validate_archive_evidence(row, observed, 'selected.conda', digest, len(data) + 1, data)

    def retirement(self, prefix):
        record = {'native_version': '0.2.1', 'runtime_installation': {'receipt_relative': 'share/receipt.json'}}
        receipt = {'receipt_digest': 'sha256:' + '2' * 64,
                   'files': [{'path': 'libexec/owner', 'digest': 'sha256:' + '3' * 64, 'size': 123}]}
        root = prefix.stat()
        state = {'protocol': 'symphony.package-retirement-state.v1', 'phase': 'retired',
                 'root_device': root.st_dev, 'root_inode': root.st_ino,
                 'identity': {'owner': 'stav-append-authority', 'version': '0.2.1',
                              'receipt_digest': receipt['receipt_digest'], 'binary_digest': receipt['files'][0]['digest'],
                              'binary_relative': 'libexec/owner', 'receipt_relative': 'share/receipt.json', 'binary_size': 123}}
        return record, receipt, root, state

    def test_retirement_requires_exact_owner_receipt_binary_and_root_identity(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp).resolve()
            record, receipt, root, state = self.retirement(prefix)
            j.validate_retirement(prefix, 'stav-append-authority', record, receipt, root, state)
            for field, value in [('owner', 'other-owner'), ('version', '0.2.2'), ('receipt_digest', 'sha256:' + '0' * 64),
                                 ('binary_digest', 'sha256:' + '0' * 64), ('binary_relative', 'libexec/other'),
                                 ('receipt_relative', 'share/other.json'), ('binary_size', 124)]:
                changed = deepcopy(state)
                changed['identity'][field] = value
                with self.subTest(field=field), self.assertRaisesRegex(ValueError, 'exact owner tombstone'):
                    j.validate_retirement(prefix, 'stav-append-authority', record, receipt, root, changed)
            for field, value in [('phase', 'retiring'), ('protocol', 'other'),
                                 ('root_device', root.st_dev + 1), ('root_inode', root.st_ino + 1)]:
                changed = deepcopy(state)
                changed[field] = value
                with self.subTest(field=field), self.assertRaises(ValueError):
                    j.validate_retirement(prefix, 'stav-append-authority', record, receipt, root, changed)
            other = prefix / 'replacement-root'
            other.mkdir()
            with self.assertRaises(ValueError):
                j.validate_retirement(other, 'stav-append-authority', record, receipt, root, state)

    def test_retirement_rejects_existing_files_and_dangling_symlinks(self):
        with tempfile.TemporaryDirectory() as temp:
            prefix = Path(temp).resolve()
            record, receipt, root, state = self.retirement(prefix)
            for relative in ('share/receipt.json', 'libexec/owner'):
                path = prefix / relative
                path.parent.mkdir(exist_ok=True)
                for symlink in (False, True):
                    with self.subTest(path=relative, symlink=symlink):
                        if symlink:
                            path.symlink_to(prefix / 'missing-target')
                            self.assertFalse(path.exists())  # regression for Path.exists()
                        else:
                            path.write_bytes(b'owned bytes remain')
                        with self.assertRaisesRegex(ValueError, 'remains'):
                            j.validate_retirement(prefix, 'stav-append-authority', record, receipt, root, state)
                        path.unlink()


if __name__ == '__main__':
    unittest.main()
