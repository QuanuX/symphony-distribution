import copy
import hashlib
import io
import json
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

from qualification import d10_mac_overlay as m


class OverlayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name).resolve()
        self.artifacts = self.root / 'artifacts'; self.artifacts.mkdir()
        (self.root / 'signature').mkdir()
        self.plan = {'signed_manifest_sha256': 'a'*64, 'plan_sha256': 'b'*64, 'source_bindings': {'core': 'selected-original'}}
        self.cohort = {'cohort_digest': 'sha256:'+'c'*64, 'archives': []}
        self.original_audit = 'd'*64
        self.helpers = ('first.py', 'second.py')
        contents = {name: ('source ' + name + '\n').encode() for name in self.helpers}
        tree_data = b''; stream = io.BytesIO(); self.files = []
        with tarfile.open(fileobj=stream, mode='w', format=tarfile.PAX_FORMAT) as archive:
            for name, raw in sorted(contents.items()):
                member = tarfile.TarInfo(name); member.size = len(raw); member.mode = 0o644
                archive.addfile(member, io.BytesIO(raw))
                blob = hashlib.sha1(b'blob ' + str(len(raw)).encode() + b'\0' + raw).digest()
                tree_data += b'100644 ' + name.encode() + b'\0' + blob
                self.files.append({'path': name, 'sha256': m.c.sha(raw), 'size': len(raw), 'mode': 0o644})
        tree = hashlib.sha1(b'tree ' + str(len(tree_data)).encode() + b'\0' + tree_data).hexdigest()
        archive_raw = stream.getvalue(); (self.artifacts / 'WRAPPER-TOOLKIT-SOURCE.tar').write_bytes(archive_raw)
        (self.artifacts / 'review.sh').write_bytes(b'fixture wrapper')
        self.wrapper = {'wrappers': [{'filename': 'review.sh'}]}
        self.source = {'protocol': m.SOURCE, 'source': {'commit': 'e'*40, 'tree': tree, 'file_count': 2},
                       'files': self.files, 'archive_sha256': m.c.sha(archive_raw),
                       'executing_helpers': {r['path']: r['sha256'] for r in self.files},
                       'privacy_scan': 'pass', 'publication_authorized': False}
        self.binding = {'protocol': m.PROTOCOL, 'state': 'local_review_wrapper_repair',
            'base_signed_manifest_sha256': self.plan['signed_manifest_sha256'], 'base_plan_sha256': self.plan['plan_sha256'],
            'base_source_bindings': self.plan['source_bindings'], 'carrier_cohort_digest': self.cohort['cohort_digest'],
            'unchanged_carrier_archives': [], 'original_wrapper_audit_sha256': self.original_audit,
            'executing_helpers': copy.deepcopy(self.source['executing_helpers']), 'repair_toolkit_source': self.source['source'],
            'carrier_bytes_changed': False, 'public_channel_mutated': False,
            'publication_authorized': False, 'release_acceptance_complete': False}

    def tearDown(self): self.temp.cleanup()
    def seal(self):
        for name, value in [('WRAPPER-AUDIT.json', self.wrapper), ('WRAPPER-TOOLKIT-SOURCE.json', self.source)]:
            (self.artifacts / name).write_bytes(m.signing.canonical(value))
        self.binding['wrapper_audit_sha256'] = m.signing.digest(self.artifacts / 'WRAPPER-AUDIT.json')
        self.binding['toolkit_source_index_sha256'] = m.signing.digest(self.artifacts / 'WRAPPER-TOOLKIT-SOURCE.json')
        (self.artifacts / 'WRAPPER-REPAIR.json').write_bytes(m.signing.canonical(self.binding))
        manifest = {'artifacts': [{'name': p.name, 'sha256': m.signing.digest(p), 'size': p.stat().st_size}
                                 for p in sorted(self.artifacts.iterdir())]}
        path = self.root / 'signature/review-manifest.json'; path.write_bytes(m.signing.canonical(manifest))
        return m.signing.digest(path)
    def admit(self, digest):
        with patch.object(m, 'HELPERS', self.helpers), patch.object(m.signing, 'verify'):
            return m.admit(self.root, digest, 'f'*64, Path('/explicit/openssl'), self.plan, self.cohort,
                           original_wrapper_audit_sha256=self.original_audit)

    def test_source_bound_overlay_preserves_original_authority(self):
        _, _, binding = self.admit(self.seal())
        self.assertFalse(binding['carrier_bytes_changed']); self.assertFalse(binding['public_channel_mutated'])
        self.assertFalse(binding['release_acceptance_complete'])

    def test_missing_or_partial_executing_helper_map_refused_even_when_consistent(self):
        for keys in ((), self.helpers[:1]):
            expected = {r['path']: r['sha256'] for r in self.files if r['path'] in keys}
            self.binding['executing_helpers'] = expected; self.source['executing_helpers'] = expected
            with self.assertRaisesRegex(ValueError, 'helper closure'): self.admit(self.seal())

    def test_wrong_original_audit_source_or_carriers_refused(self):
        original = copy.deepcopy(self.binding)
        for key, value in [('original_wrapper_audit_sha256', 'f'*64), ('base_source_bindings', {'core': 'changed'}),
                           ('unchanged_carrier_archives', [{'unselected': True}]), ('carrier_bytes_changed', True),
                           ('publication_authorized', True)]:
            self.binding = copy.deepcopy(original); self.binding[key] = value
            with self.assertRaises(ValueError): self.admit(self.seal())

    def test_changed_source_inventory_or_helper_bytes_refused(self):
        self.source['files'][0]['sha256'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'inventory'): self.admit(self.seal())
        self.source['files'][0]['sha256'] = self.binding['executing_helpers']['first.py']
        self.binding['executing_helpers']['first.py'] = 'f'*64
        self.source['executing_helpers']['first.py'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'helper absent'): self.admit(self.seal())

    def test_unsigned_auxiliary_or_source_member_not_admitted(self):
        digest = self.seal(); (self.artifacts / 'WRAPPER-AUDIT.json').write_bytes(b'{}')
        with self.assertRaisesRegex(ValueError, 'Signed overlay bytes'): self.admit(digest)

    def test_recipe_reconstruction_matches_original_generator_and_rejects_drift(self):
        unit = {'unit_id': 'native:fixture', 'kind': 'native_receipt_unit', 'component_id': 'fixture',
                'native_version': '1.0.0', 'dependency_units': [], 'external_dependency_units': [], 'sdk_exports': []}
        raw = b'fixture owned bytes'; rows = [m.c.file_row('fixture', raw)]
        entry = m.c.recipe(unit, self.root / 'recipe', rows, {'fixture': lambda: raw},
                           'local-macos-amd64-fixture', {}, None)
        regenerated = m.recipe_metadata(entry)
        self.assertEqual(regenerated['meta.yaml'], (self.root / 'recipe/meta.yaml').read_bytes())
        entry['recipe_files']['stage_payload.py'] = 'f'*64
        with self.assertRaisesRegex(ValueError, 'metadata'): m.recipe_metadata(entry)

if __name__ == '__main__': unittest.main()
