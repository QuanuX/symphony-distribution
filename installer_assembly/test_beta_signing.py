import importlib.util
import json
import os
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('beta_signing', Path(__file__).with_name('beta_signing.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for actual signature tests')
class BetaSigningTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='beta-integrity-test-'); cls.root = Path(cls.temp.name).resolve()
        cls.openssl = Path(shutil.which('openssl')).resolve(); cls.custody = cls.root / 'custody'
        cls.identity = m.initialize(cls.custody, cls.openssl)
        cls.pin, cls.pub = (cls.identity[k] for k in ('certificate_sha256', 'public_key_sha256'))

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(dir=self.root)).resolve()
        self.release = self.work / 'release'; self.release.mkdir()
        (self.release / 'osx-arm64').mkdir()
        self.artifact = self.release / 'osx-arm64/SymphonyBeta.pkg'; self.artifact.write_bytes(b'exact beta package')
        self.index = self.release / 'release-index.json'; self.index.write_text(json.dumps({'release': m.RELEASE, 'scope': 'test only'}))
        self.decision = self.release / 'publisher-decision.json'
        self.decision.write_bytes((Path(__file__).resolve().parents[1] / 'evidence/d14-publisher-decision.json').read_bytes())
        self.paths = [self.artifact, self.index, self.decision]; self.output = self.work / 'signatures'

    def sign(self, custody=None, paths=None):
        return m.sign(self.release, paths or self.paths, self.index, self.decision, custody or self.custody,
                      self.pin, self.pub, self.output, self.openssl)

    def verify(self, pin=None, pub=None):
        return m.verify(self.output, self.release, pin or self.pin, pub or self.pub, self.openssl)

    def test_actual_beta_signature_binds_nested_artifacts_pins_and_decision(self):
        original = self.artifact.read_bytes(); value = self.sign(); proof = self.verify()
        self.assertEqual(proof['state'], 'public_beta_signature_and_artifacts_verified')
        self.assertEqual(proof['publisher_decision_sha256'], m.DECISION)
        self.assertEqual(value['release_index']['sha256'], m.base.digest(self.index))
        self.assertIn('osx-arm64/SymphonyBeta.pkg', [r['path'] for r in value['artifacts']])
        self.assertEqual(self.artifact.read_bytes(), original)
        for key in ('apple_developer_id', 'notarized', 'gatekeeper_acceptance', 'system_trust_changed'):
            self.assertIs(value[key], False)
        self.assertEqual((self.custody / 'beta-key.pem').stat().st_mode & 0o077, 0)
        self.assertIn(b'ENCRYPTED PRIVATE KEY', (self.custody / 'beta-key.pem').read_bytes())

    def test_changed_artifact_is_not_accepted_with_valid_manifest(self):
        self.sign(); self.artifact.write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'artifact bytes'): self.verify()

    def test_independent_certificate_and_public_key_pins_are_required(self):
        self.sign()
        with self.assertRaisesRegex(ValueError, 'Certificate differs'): self.verify(pin='0' * 64)
        with self.assertRaisesRegex(ValueError, 'public key differs'): self.verify(pub='0' * 64)

    def test_review_only_identity_cannot_be_promoted(self):
        custody = self.work / 'review'; identity = m.base.initialize(custody, self.openssl)
        cert = custody / 'review-cert.pem'; pub = m.public_key_pin(self.openssl, cert)
        with self.assertRaisesRegex(ValueError, 'public-beta purpose'):
            m.certificate(self.openssl, cert, identity['certificate_sha256'], pub)

    def test_wrong_private_key_cannot_report_signing_success(self):
        other = self.work / 'wrong-key'; m.initialize(other, self.openssl)
        (other / 'beta-cert.pem').write_bytes((self.custody / 'beta-cert.pem').read_bytes())
        with self.assertRaisesRegex(ValueError, 'OpenSSL'): self.sign(custody=other)

    def test_exact_publisher_decision_and_included_release_index_required(self):
        self.decision.write_bytes(b'forged decision')
        with self.assertRaisesRegex(ValueError, 'publisher decision'): self.sign()
        self.decision.write_bytes((Path(__file__).resolve().parents[1] / 'evidence/d14-publisher-decision.json').read_bytes())
        with self.assertRaisesRegex(ValueError, 'among exact signed'): self.sign(paths=[self.artifact, self.decision])
        self.index.write_text(json.dumps({'release': 'future-version'}))
        with self.assertRaisesRegex(ValueError, 'version differs'): self.sign()
        self.assertFalse(self.output.exists())

    def test_trust_claim_or_traversal_is_rejected(self):
        self.sign(); path = self.output / 'beta-manifest.json'; original = path.read_bytes()
        for change in ('trust', 'path'):
            value = json.loads(original)
            if change == 'trust': value['apple_developer_id'] = True
            else: value['artifacts'][0]['path'] = '../outside'
            path.write_bytes(m.base.canonical(value))
            with self.assertRaises(ValueError): self.verify()

    def test_existing_output_duplicate_and_alias_refuse(self):
        self.sign()
        with self.assertRaisesRegex(ValueError, 'new directory'): self.sign()
        with self.assertRaisesRegex(ValueError, 'Duplicate'): m.artifact_rows(self.release, [self.artifact, self.artifact])
        link = self.release / 'linked.pkg'; link.symlink_to(self.artifact)
        with self.assertRaisesRegex(ValueError, 'Linked'): m.artifact_rows(self.release, [link])
        hard = self.release / 'hard.pkg'; os.link(self.artifact, hard)
        with self.assertRaisesRegex(ValueError, 'unaliased'): m.artifact_rows(self.release, [hard])

    def test_artifact_mutation_during_signing_is_refused(self):
        original_run = m.base.run
        def changing_run(openssl, args, **kwargs):
            result = original_run(openssl, args, **kwargs)
            if '-sign' in args: self.artifact.write_bytes(b'changed while signing')
            return result
        with patch.object(m.base, 'run', side_effect=changing_run):
            with self.assertRaisesRegex(ValueError, 'artifact bytes'): self.sign()

    def test_credential_custody_cannot_be_output_or_artifact(self):
        self.output = self.custody / 'invalid-output'
        with self.assertRaisesRegex(ValueError, 'cannot enter'): self.sign()
        self.assertFalse(self.output.exists())
        with self.assertRaisesRegex(ValueError, 'outside selected root'):
            m.artifact_rows(self.release, [self.custody / 'beta-key.pem'])


if __name__ == '__main__': unittest.main()
