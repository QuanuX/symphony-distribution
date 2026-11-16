"""Execute the actual workflow selector without allocating native runners."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import textwrap
import unittest


WORKFLOW = Path(__file__).resolve().parents[1] / '.github/workflows/build-cohort.yml'
ROWS = [
    {'profile': 'macos15-arm64', 'runner': 'macos-15', 'cc': '/usr/bin/clang', 'cxx': '/usr/bin/clang++'},
    {'profile': 'ubuntu24.04-amd64', 'runner': 'ubuntu-24.04', 'cc': 'clang-18', 'cxx': 'clang++-18'},
    {'profile': 'ubuntu24.04-arm64', 'runner': 'ubuntu-24.04-arm', 'cc': 'clang-18', 'cxx': 'clang++-18'},
    {'profile': 'ubuntu26.04-amd64', 'runner': 'ubuntu-26.04', 'cc': 'clang-21', 'cxx': 'clang++-21'},
]


class WorkflowSelectionTests(unittest.TestCase):
    def select(self, event, selection):
        workflow = WORKFLOW.read_text()
        self.assertIn('matrix: ${{ fromJSON(needs.contracts.outputs.matrix) }}', workflow)
        self.assertIn('matrix: ${{ steps.source.outputs.matrix }}', workflow)
        self.assertIn("REQUESTED_PLATFORMS: ${{ inputs.platforms || 'all' }}", workflow)
        block = re.search(r"          python3 - <<'PY'\n(.*?)\n          PY", workflow, re.S)
        self.assertIsNotNone(block)
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / 'source-binding.json').write_text(json.dumps({'source_commit': 'a' * 40}))
            output = root / 'outputs'
            env = dict(os.environ, EVENT_NAME=event, REQUESTED_PLATFORMS=selection, GITHUB_OUTPUT=str(output))
            result = subprocess.run([sys.executable, '-B', '-c', textwrap.dedent(block.group(1))],
                                    cwd=root, env=env, capture_output=True, text=True, timeout=10)
            if result.returncode:
                self.assertFalse(output.exists(), 'Invalid selection must emit no actionable outputs')
                return result, None
            values = dict(line.split('=', 1) for line in output.read_text().splitlines())
            self.assertEqual(values['commit'], 'a' * 40)
            return result, json.loads(values['matrix'])['include']

    def test_manual_all_preserves_exact_four_platform_mapping(self):
        result, rows = self.select('workflow_dispatch', 'all')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(rows, ROWS)

    def test_manual_linux_selects_only_three_failed_platforms(self):
        result, rows = self.select('workflow_dispatch', 'linux')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(rows, ROWS[1:])

    def test_manual_macos_selects_only_apple_mapping(self):
        result, rows = self.select('workflow_dispatch', 'macos')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(rows, ROWS[:1])

    def test_push_cannot_silently_narrow_platforms(self):
        result, rows = self.select('push', 'linux')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(rows, ROWS)

    def test_unknown_manual_selection_refuses_before_outputs(self):
        result, rows = self.select('workflow_dispatch', 'other')
        self.assertEqual(result.returncode, 1)
        self.assertIn('Unknown native platform selection', result.stderr)
        self.assertIsNone(rows)


if __name__ == '__main__':
    unittest.main()
