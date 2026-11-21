"""Real signature, immutable release routing and cross-release refusal contracts."""
import hashlib
import json
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'installer_assembly'))
import beta_signing as signing
import beta_downloads as downloads
import beta_publish as publisher
import verify_beta as verifier


@unittest.skipUnless(shutil.which('openssl'), 'OpenSSL required for actual signature tests')
class Beta2ReleaseTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory(prefix='beta2-release-policy-')
        cls.root = Path(cls.temp.name).resolve(); cls.openssl = Path(shutil.which('openssl')).resolve()
        cls.key = cls.root / 'custody'; cls.identity = signing.initialize(cls.key, cls.openssl)
        cls.cert, cls.public = cls.identity['certificate_sha256'], cls.identity['public_key_sha256']

    @classmethod
    def tearDownClass(cls): cls.temp.cleanup()

    def setUp(self):
        self.work = Path(tempfile.mkdtemp(dir=self.root)).resolve()
        self.art = self.work / 'art'; self.art.mkdir(); self.sig = self.work / 'signature'
        self.rows = []
        for name, selection in [('symphony-source-payload', 'optional-source'), ('symphony-qxctl-payload', 'default')]:
            raw = ('inert archive ' + name).encode(); filename = name + '-1.0.0-beta2_1.conda'
            (self.art / filename).write_bytes(raw)
            self.rows.append({'profile': 'macos15-arm64', 'path': filename, 'name': name, 'version': '1.0.0',
                'build': 'beta2_1', 'build_number': 1, 'subdir': 'osx-arm64', 'filename': filename,
                'sha256': signing.sha(raw), 'size': len(raw), 'selection': selection})
        self.index = self.art / 'release-index.json'; self.decision = self.art / 'publisher-decision.json'
        self.index.write_bytes(signing.base.canonical({'release': '0.2.0-beta.2', 'conda_packages': self.rows,
                                                     'public_downloads': ['release-index.json', 'publisher-decision.json']}))
        self.decision.write_bytes((Path(__file__).resolve().parents[1] / 'evidence/beta2-publisher-decision.json').read_bytes())

    def sign(self):
        return signing.sign(self.art, list(self.art.iterdir()), self.index, self.decision, self.key,
                            self.cert, self.public, self.sig, self.openssl)

    def test_beta2_real_signature_routes_only_to_beta2_prefix_and_immutable_label(self):
        self.sign()
        proof = signing.verify(self.sig, self.art, self.cert, self.public, self.openssl)
        self.assertEqual(proof['release'], '0.2.0-beta.2')
        with patch.object(verifier, 'CERTIFICATE_SHA256', self.cert), patch.object(verifier, 'PUBLIC_KEY_SHA256', self.public):
            value = verifier.verify(self.sig, self.art, ['release-index.json'], self.openssl, '0.2.0-beta.2')
            self.assertEqual(value['release'], '0.2.0-beta.2')
            with self.assertRaisesRegex(ValueError, 'release or trust'):
                verifier.verify(self.sig, self.art, ['release-index.json'], self.openssl, '0.2.0-beta.1')
        plan = downloads.prepare(self.art, self.sig, self.cert, self.public, self.openssl)
        self.assertEqual(plan['release'], '0.2.0-beta.2')
        self.assertTrue(all(row['key'].startswith('symphony/0.2.0-beta.2/') for row in plan['objects']))
        with patch.object(publisher, 'audit_archive'):
            plan = publisher.prepare(self.art, self.sig, self.cert, self.public, self.openssl)
        self.assertEqual(plan['labels'][0], 'beta')
        self.assertTrue(plan['labels'][1].startswith('beta-0.2.0-beta.2-'))
        self.assertEqual(plan['publisher_decision_sha256'], proof['publisher_decision_sha256'])
        self.assertEqual(downloads.release_prefix('0.2.0-beta.1'), 'symphony/0.2.0-beta.1/')

    def test_beta1_decision_cannot_sign_beta2_and_unknown_version_refuses(self):
        self.decision.write_bytes((Path(__file__).resolve().parents[1] / 'evidence/d14-publisher-decision.json').read_bytes())
        with self.assertRaisesRegex(ValueError, 'publisher decision'): self.sign()
        self.assertFalse(self.sig.exists())
        value = json.loads(self.index.read_bytes()); value['release'] = '0.2.0-beta.3'
        self.index.write_bytes(signing.base.canonical(value))
        with self.assertRaisesRegex(ValueError, 'version differs'): self.sign()
        with self.assertRaises(ValueError): downloads.release_prefix('../beta.2')
        self.assertFalse(self.sig.exists())

    def test_public_and_publisher_policy_pins_match_exact_committed_authorities(self):
        root = Path(__file__).resolve().parents[1]
        for release, path in [('0.2.0-beta.1', 'evidence/d14-publisher-decision.json'),
                              ('0.2.0-beta.2', 'evidence/beta2-publisher-decision.json'),
                              ('0.2.0-beta.2.1', 'evidence/beta21-publisher-decision.json')]:
            pin = hashlib.sha256((root / path).read_bytes()).hexdigest()
            self.assertEqual(pin, signing.release_policy(release)['decision_sha256'])
            self.assertEqual(pin, verifier.RELEASE_DECISIONS[release])
        decision = json.loads(self.decision.read_bytes())
        binding = decision['candidate_authorization']
        self.assertEqual(hashlib.sha256((root / binding['path']).read_bytes()).hexdigest(), binding['sha256'])
        self.assertFalse(json.loads((root / binding['path']).read_bytes())['publication_authorized'])

    def test_beta21_requires_its_own_decision_and_download_prefix(self):
        release = '0.2.0-beta.2.1'
        index = json.loads(self.index.read_bytes())
        index['release'] = release
        self.index.write_bytes(signing.base.canonical(index))
        with self.assertRaisesRegex(ValueError, 'publisher decision'):
            self.sign()
        self.assertFalse(self.sig.exists())
        self.decision.write_bytes((Path(__file__).resolve().parents[1] / 'evidence/beta21-publisher-decision.json').read_bytes())
        self.sign()
        plan = downloads.prepare(self.art, self.sig, self.cert, self.public, self.openssl)
        self.assertTrue(all(row['key'].startswith('symphony/0.2.0-beta.2.1/') for row in plan['objects']))
        with patch.object(verifier, 'CERTIFICATE_SHA256', self.cert), patch.object(verifier, 'PUBLIC_KEY_SHA256', self.public):
            self.assertEqual(verifier.verify(self.sig, self.art, ['release-index.json'], self.openssl, release)['release'], release)

if __name__ == '__main__': unittest.main()
