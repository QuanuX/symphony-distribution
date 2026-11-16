import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('review_signing', Path(__file__).with_name('review_signing.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for real signature regressions')
class ReviewSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='d08-signing-test-')
        cls.root = Path(cls.temp.name).resolve()
        cls.openssl = Path(shutil.which('openssl')).resolve()
        cls.custody = cls.root / 'custody'
        cls.identity = m.initialize(cls.custody, cls.openssl)
        cls.pin = cls.identity['certificate_sha256']

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(dir=self.root)).resolve()
        self.artifact = self.work / 'Symphony-review.pkg'
        self.artifact.write_bytes(b'exact opaque installer review bytes')
        self.signed = self.work / 'signature'

    def sign(self):
        return m.sign([self.artifact], self.custody, self.pin, self.signed, self.openssl)

    def test_real_signature_and_pinned_certificate_verify_without_payload_change(self):
        before = self.artifact.read_bytes(); result = self.sign()
        proof = m.verify(self.signed, self.work, self.pin, self.openssl)
        self.assertEqual(proof['state'], 'review_signature_and_artifacts_verified')
        self.assertEqual(self.artifact.read_bytes(), before)
        self.assertFalse(result['notarized']); self.assertFalse(result['publication_authorized'])
        self.assertEqual((self.custody / 'review-key.pem').stat().st_mode & 0o077, 0)
        self.assertIn(b'ENCRYPTED PRIVATE KEY', (self.custody / 'review-key.pem').read_bytes())
        self.assertEqual(set(p.name for p in self.signed.iterdir()),
                         {'review-cert.pem', 'review-manifest.json', 'review-manifest.sig'})

    def test_tampered_or_missing_artifact_refuses_after_valid_signature(self):
        self.sign(); self.artifact.write_bytes(b'tampered')
        with self.assertRaisesRegex(ValueError, 'Signed artifact'): m.verify(self.signed, self.work, self.pin, self.openssl)
        self.artifact.unlink()
        with self.assertRaises(OSError): m.verify(self.signed, self.work, self.pin, self.openssl)

    def test_wrong_key_pin_and_changed_certificate_are_refused(self):
        self.sign()
        with self.assertRaisesRegex(ValueError, 'Certificate differs'):
            m.verify(self.signed, self.work, '0' * 64, self.openssl)
        cert = self.signed / 'review-cert.pem'; cert.write_bytes(cert.read_bytes() + b'\n')
        with self.assertRaisesRegex(ValueError, 'Certificate differs'):
            m.verify(self.signed, self.work, self.pin, self.openssl)

    def test_signed_manifest_edit_and_signature_corruption_refuse(self):
        self.sign(); path = self.signed / 'review-manifest.json'; original = path.read_bytes()
        data = json.loads(original); data['scope'] = 'forged'; path.write_bytes(m.canonical(data))
        with self.assertRaisesRegex(ValueError, 'scope'): m.verify(self.signed, self.work, self.pin, self.openssl)
        path.write_bytes(original)
        signature = self.signed / 'review-manifest.sig'; signature.write_bytes(b'wrong signature')
        with self.assertRaisesRegex(ValueError, 'OpenSSL'): m.verify(self.signed, self.work, self.pin, self.openssl)

    def test_approval_claim_and_traversal_fail_closed(self):
        self.sign(); path = self.signed / 'review-manifest.json'; original = path.read_bytes()
        for change in ('approval', 'traversal'):
            data = json.loads(original)
            if change == 'approval': data['publication_authorized'] = True
            else: data['artifacts'][0]['name'] = '../outside'
            path.write_bytes(m.canonical(data))
            with self.assertRaises(ValueError): m.verify(self.signed, self.work, self.pin, self.openssl)

    def test_existing_outputs_linked_inputs_and_duplicate_names_refused(self):
        self.sign()
        with self.assertRaisesRegex(ValueError, 'new directory'): self.sign()
        alias = self.work / 'alias.pkg'; alias.symlink_to(self.artifact)
        with self.assertRaisesRegex(ValueError, 'Linked'): m.artifact_rows([alias])
        with self.assertRaisesRegex(ValueError, 'duplicate'): m.artifact_rows([self.artifact, self.artifact])

    def test_wrong_private_key_with_pinned_certificate_cannot_report_success(self):
        other = self.work / 'other-custody'
        m.initialize(other, self.openssl)
        (other / 'review-cert.pem').write_bytes((self.custody / 'review-cert.pem').read_bytes())
        with self.assertRaisesRegex(ValueError, 'OpenSSL'):
            m.sign([self.artifact], other, self.pin, self.signed, self.openssl)

    def test_other_private_custody_material_is_never_an_artifact(self):
        container = self.custody / 'review-identity.p12'
        container.write_bytes(b'private encrypted container fixture')
        try:
            with self.assertRaisesRegex(ValueError, 'Credential custody'):
                m.sign([container], self.custody, self.pin, self.signed, self.openssl)
        finally: container.unlink()

    def test_exposed_private_key_or_custody_refuses(self):
        key = self.custody / 'review-key.pem'
        try:
            key.chmod(0o644)
            with self.assertRaisesRegex(ValueError, 'private'): self.sign()
        finally: key.chmod(0o600)
        try:
            self.custody.chmod(0o755)
            with self.assertRaisesRegex(ValueError, 'custody'): self.sign()
        finally: self.custody.chmod(0o700)


if __name__ == '__main__': unittest.main()
