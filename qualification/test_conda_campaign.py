"""Qualification cannot promote missing, skipped, or failed cases into acceptance."""
import io
import unittest

import conda_campaign as campaign


class RecorderTests(unittest.TestCase):
    def run_cases(self, case):
        return campaign.record_suite(unittest.defaultTestLoader.loadTestsFromTestCase(case), io.StringIO())

    def test_passes_record_successful_subtest_oracles(self):
        class Fixture(unittest.TestCase):
            def test_cells(self):
                for cell in ('before-execute', 'after-execute'):
                    with self.subTest(cell=cell):
                        self.assertTrue(True)
        result = self.run_cases(Fixture)
        self.assertEqual(result['status'], 'passed')
        self.assertEqual(len(result['cases']), 3)
        self.assertEqual(sum(row['subtest'] for row in result['cases']), 2)

    def test_empty_suite_is_incomplete(self):
        self.assertEqual(campaign.record_suite(unittest.TestSuite(), io.StringIO())['status'], 'incomplete_or_failed')

    def test_missing_or_duplicate_required_case_is_incomplete(self):
        class Fixture(unittest.TestCase):
            def test_case(self):
                pass
        item = Fixture('test_case')
        for suite, required in ((unittest.TestSuite([item]), [item.id(), 'missing.test_case']),
                                (unittest.TestSuite([item, item]), [item.id()])):
            with self.subTest(required=required):
                result = campaign.record_suite(suite, io.StringIO(), required)
                self.assertEqual(result['status'], 'incomplete_or_failed')
                self.assertFalse(result['required_case_coverage'])

    def test_skip_expected_failure_and_subtest_failure_are_not_acceptance(self):
        class Skipped(unittest.TestCase):
            @unittest.skip('unavailable host')
            def test_case(self):
                pass
        class ExpectedFailure(unittest.TestCase):
            @unittest.expectedFailure
            def test_case(self):
                self.fail('known gap')
        class SubtestFailure(unittest.TestCase):
            def test_case(self):
                with self.subTest(cell='unknown-owner'):
                    self.fail('unsafe outcome')
        for case in (Skipped, ExpectedFailure, SubtestFailure):
            with self.subTest(case=case.__name__):
                self.assertEqual(self.run_cases(case)['status'], 'incomplete_or_failed')


if __name__ == '__main__':
    unittest.main()
