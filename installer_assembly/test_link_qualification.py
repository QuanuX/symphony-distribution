import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).parent))
import link_qualification as q


class LinkBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.prefix = Path(self.temp.name).resolve() / 'prefix'; self.prefix.mkdir()
        (self.prefix / 'conda-meta').mkdir()
        (self.prefix / 'conda-meta/history').write_text('isolated generated metadata')
        (self.prefix / 'user-state.txt').write_text('preserved user state')
        (self.prefix / 'payload').write_bytes(b'opaque carrier'); (self.prefix / 'payload').chmod(0o644)
        self.expected = {'payload': (b'opaque carrier', 0o644)}

    def test_exact_bytes_and_unrelated_user_file_are_preserved(self):
        self.assertEqual(q.verify_linked(self.prefix, self.expected), 1)
        (self.prefix / 'payload').unlink()
        self.assertEqual(q.verify_linked(self.prefix, {}), 0)
        self.assertEqual((self.prefix / 'user-state.txt').read_text(), 'preserved user state')

    def test_modified_or_extra_payload_is_refused(self):
        (self.prefix / 'payload').write_bytes(b'changed')
        with self.assertRaisesRegex(ValueError, 'bytes or modes'): q.verify_linked(self.prefix, self.expected)
        (self.prefix / 'payload').write_bytes(b'opaque carrier')
        (self.prefix / 'untracked-install-state').write_bytes(b'extra')
        with self.assertRaisesRegex(ValueError, 'bytes or modes'): q.verify_linked(self.prefix, self.expected)

    def test_link_or_mode_change_is_refused(self):
        (self.prefix / 'payload').chmod(0o755)
        with self.assertRaisesRegex(ValueError, 'bytes or modes'): q.verify_linked(self.prefix, self.expected)
        (self.prefix / 'payload').unlink(); (self.prefix / 'payload').symlink_to('user-state.txt')
        with self.assertRaisesRegex(ValueError, 'linked prefix'): q.verify_linked(self.prefix, self.expected)

if __name__ == '__main__': unittest.main()
