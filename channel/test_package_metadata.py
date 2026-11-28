import json
import re
import unittest

import package_metadata as metadata


class PackageMetadataTests(unittest.TestCase):
    def test_every_published_and_historical_name_has_a_distinct_summary(self):
        records = metadata.ROOT / 'evidence/beta21-publication'
        expected = set(metadata.D09_NAMES)
        for path in records.glob('*-anaconda.json'):
            for row in json.loads(path.read_text()):
                name, _, _ = row['filename'].removesuffix('.conda').rsplit('-', 2)
                expected.add(name)
        self.assertEqual(len(expected), 63)
        self.assertEqual(set(metadata.SUMMARIES), expected)
        self.assertEqual(len(set(metadata.SUMMARIES.values())), len(expected))
        for name in expected:
            fields = metadata.overview(name)
            self.assertEqual(set(fields), {'summary', 'description', 'home', 'doc_url'})
            self.assertEqual(fields['home'], 'https://quanux.org')
            self.assertEqual(fields['doc_url'], 'https://quanux.org/downloads/anaconda')
            self.assertTrue(fields['description'].startswith(fields['summary'] + '\n\n'))
            description = fields['description']
            self.assertEqual(f'<{metadata.REVIEW_SOURCE}>' in description, name in metadata.D09_NAMES)
            self.assertTrue(description.endswith(f'Installation and verification: <{metadata.DOCS}>.'))
            self.assertNotRegex(description, r'(?<!<)https://')
        self.assertNotIn('quanux', expected)

    def test_selection_and_source_guidance_follow_the_actual_package(self):
        active = metadata.overview('symphony-qxctl-payload')['description']
        self.assertIn('command-line', active)
        self.assertIn('explicit package list', active)
        self.assertIn('historical Intel macOS D09', active)
        for name in metadata.REVIEW_NAMES:
            review = metadata.overview(name, review_source='https://example.org/source.conda')['description']
            self.assertIn('staged for D09 review', review)
            self.assertIn('https://example.org/source.conda', review)
            self.assertIn('SOURCE-SCOPE.json', review)
        keyring = metadata.overview(metadata.KEYRING)['description']
        self.assertIn('Debian package manager', keyring)
        self.assertIn('signed supplement index', keyring)
        self.assertNotIn('optional source package in a separate environment', keyring)

    def test_original_beta1_cards_keep_four_distinct_source_links(self):
        paths = sorted((metadata.ROOT / 'evidence/beta-publication').glob('*-anaconda.json'))
        self.assertEqual(len(paths), 4)
        expected = []
        for path in paths:
            receipt = json.loads(path.read_text())
            profile, = receipt['profiles']
            source, = [p for p in receipt['packages'] if p['selection'] == 'optional-source']
            url = source['immutable_source_retrieval']['final_url']
            self.assertIn('/label/beta-0.2.0-beta.1-', url)
            expected.append((profile, url))
        for name in metadata.SUMMARIES:
            with self.subTest(name=name):
                links = re.findall(r'^- ([\w.-]+): <([^>]+)>$', metadata.overview(name)['description'], re.M)
                self.assertEqual(links, expected if name in {
                    'symphony-client-payload', 'symphony-corresponding-source-payload'} else [])


if __name__ == '__main__':
    unittest.main()
