import hashlib
import importlib.util
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('upstream_source', Path(__file__).with_name('d06_upstream_source.py'))
u = importlib.util.module_from_spec(spec); spec.loader.exec_module(u)


class UpstreamSourceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.root = Path(self.temp.name)
        spec = importlib.util.spec_from_file_location('upstream_privacy', Path(__file__).resolve().parents[1] / 'source-export/export_source.py')
        self.scanner = importlib.util.module_from_spec(spec); spec.loader.exec_module(self.scanner)
        self.set_markers(['SYNTHETIC_PUBLISHER_IDENTITY'])

    def tearDown(self):
        self.temp.cleanup()

    def set_markers(self, markers):
        path = self.root / 'policy.json'
        path.write_text(json.dumps({'schema': 'symphony.source-privacy-policy.v1', 'markers': markers, 'document_attributions': {}}))
        self.scanner.configure_policy(path)

    def key(self):
        # Construct the synthetic complete rejection fixture at runtime only.
        return b'-----' + b'BEGIN ' + b'PRIVATE KEY' + b'-----\n' + b'A' * 40 + b'\n-----' + b'END ' + b'PRIVATE KEY' + b'-----'

    def fixture(self, data=None):
        raw = self.key() if data is None else data
        name = next(iter(u.TLS_FIXTURES))
        return name, raw, patch.dict(u.TLS_FIXTURES, {name: hashlib.sha256(raw).hexdigest()})

    def test_exact_fixture_changes_scan_view_only_and_is_hash_bound(self):
        name, raw, trust = self.fixture(); before = bytes(raw)
        with trust:
            result = u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, name, raw)
            self.assertEqual(result['reviewed_occurrence_count'], 1)
            self.assertFalse(result['archived_source_bytes_changed'])
            self.assertEqual(raw, before)
            with self.assertRaisesRegex(ValueError, 'archive identity'):
                u.scan_member(self.scanner, '0' * 64, name, raw)
            for changed in (raw + b'changed', raw + b'\n' + self.key()):
                with self.assertRaisesRegex(ValueError, 'member bytes changed'):
                    u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, name, changed)
        with self.assertRaisesRegex(ValueError, 'private key'):
            u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, 'curl-8.7.1/tests/unreviewed.key', raw)

    def test_fixture_does_not_exempt_new_publisher_data_or_aws_values(self):
        name, raw, trust = self.fixture(self.key() + b'\nSYNTHETIC_PUBLISHER_IDENTITY')
        with trust, self.assertRaisesRegex(ValueError, 'publisher private marker'):
            u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, name, raw)
        name, raw, trust = self.fixture(self.key() + b'\n' + b'AK' + b'IA' + b'B' * 16)
        with trust, self.assertRaisesRegex(ValueError, 'credential-shaped'):
            u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, name, raw)
        name, raw, trust = self.fixture(self.key() + b'\n' + self.key())
        with trust, self.assertRaisesRegex(ValueError, 'key count'):
            u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, name, raw)

    def attribution(self):
        raw = b'Public Credit\nPublic Other\nAdditional attribution\n'
        ranges = {(0, 6), (14, 6)}
        self.set_markers(['Public'])
        return raw, patch.object(u, 'THANKS_SHA256', hashlib.sha256(raw).hexdigest()), patch.object(u, 'THANKS_OVERLAPS', ranges)

    def test_attribution_allows_only_exact_reviewed_substrings_without_editing_source(self):
        raw, trust, locations = self.attribution()
        with trust, locations:
            result = u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, u.THANKS_PATH, raw)
            self.assertEqual(result['reviewed_occurrence_count'], 2)
            self.assertFalse(result['archived_source_bytes_changed'])
            self.set_markers(['Public', 'Additional'])
            with self.assertRaisesRegex(ValueError, 'publisher private marker'):
                u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, u.THANKS_PATH, raw)
            self.set_markers(['Public Credit'])
            with self.assertRaisesRegex(ValueError, 'publisher private marker'):
                u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, u.THANKS_PATH, raw)
            with self.assertRaisesRegex(ValueError, 'member bytes changed'):
                u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, u.THANKS_PATH, raw + b'changed')

    def test_attribution_does_not_exempt_complete_key(self):
        raw = self.key()
        with patch.object(u, 'THANKS_SHA256', hashlib.sha256(raw).hexdigest()):
            with self.assertRaisesRegex(ValueError, 'complete private key'):
                u.scan_member(self.scanner, u.CURL_ARCHIVE_SHA256, u.THANKS_PATH, raw)

    def test_manifest_requires_the_entire_exact_exception_set(self):
        self.assertIsNone(u.manifest([]))
        records = [{'member_path': name} for name in [*u.TLS_FIXTURES, u.THANKS_PATH]]
        result = u.manifest(records)
        self.assertEqual(len(result['exceptions']), 15)
        self.assertFalse(result['provenance']['source_bytes_modified'])
        self.assertFalse(result['publication_authorized'])
        with self.assertRaisesRegex(ValueError, 'coverage differs'):
            u.manifest(records[:-1])


if __name__ == '__main__': unittest.main()
