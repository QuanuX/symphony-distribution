import importlib.util
from pathlib import Path
import stat
import struct
import tempfile
import unittest
import zlib

spec = importlib.util.spec_from_file_location('pkg_finalize', Path(__file__).with_name('pkg_finalize.py'))
p = importlib.util.module_from_spec(spec); spec.loader.exec_module(p)


def cpio(entries, *, owner=0):
    output = bytearray()
    for index, (name, mode, content) in enumerate(entries):
        header = bytearray(p.cpio_header(name, mode, len(content), index))
        header[24:30] = f'{owner:06o}'.encode()
        output += header + content
    output += p.cpio_header('TRAILER!!!', 0, 0, len(entries))
    output += b'\0' * (-len(output) % 512)
    return bytes(output)


def apple_double():
    return bytes.fromhex('0005160700020000') + b'\0' * 16 + struct.pack('>HIIIIII', 2, 9, 50, 32, 2, 82, 0) + b'\0' * 32


BASE = [('.', stat.S_IFDIR | 0o755, b''), ('./payload', stat.S_IFREG | 0o644, b'exact nested archive bytes')]


class PackageFinalizerContracts(unittest.TestCase):
    def test_recognized_metadata_removal_preserves_real_bytes_and_modes(self):
        raw = cpio([*BASE, ('./._payload', stat.S_IFREG | 0o644, apple_double())], owner=501)
        changed, report = p.normalize_cpio(raw)
        self.assertEqual(report['apple_double_members_removed'], 1)
        self.assertEqual(p.content_inventory(p.cpio_records(raw)), p.content_inventory(p.cpio_records(changed)))
        self.assertTrue(all(row['uid'] == row['gid'] == row['mtime'] == 0 for row in p.cpio_records(changed)))

    def test_arbitrary_dot_underscore_file_is_not_discarded(self):
        raw = cpio([*BASE, ('./._payload', stat.S_IFREG | 0o644, b'ordinary data')])
        with self.assertRaisesRegex(ValueError, 'unrecognized AppleDouble'):
            p.normalize_cpio(raw)

    def test_orphan_metadata_refuses(self):
        raw = cpio([*BASE, ('./._absent', stat.S_IFREG | 0o644, apple_double())])
        with self.assertRaisesRegex(ValueError, 'orphan AppleDouble'):
            p.normalize_cpio(raw)

    def test_resource_fork_data_is_not_discarded(self):
        metadata = bytearray(apple_double()); metadata[46:50] = struct.pack('>I', 1); metadata += b'x'
        raw = cpio([*BASE, ('./._payload', stat.S_IFREG | 0o644, bytes(metadata))])
        with self.assertRaisesRegex(ValueError, 'nonmetadata or unqualified resource'):
            p.normalize_cpio(raw)

    def test_duplicate_and_traversal_members_refuse(self):
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            p.normalize_cpio(cpio([*BASE, BASE[1]]))
        with self.assertRaisesRegex(ValueError, 'unsafe generated CPIO path'):
            p.normalize_cpio(cpio([*BASE, ('./../escape', stat.S_IFREG | 0o644, b'x')]))

    def test_parent_file_collision_and_absent_directory_refuse(self):
        for name in ('./payload/child', './absent/child'):
            with self.subTest(name=name), self.assertRaisesRegex(ValueError, 'parent directory'):
                p.normalize_cpio(cpio([*BASE, (name, stat.S_IFREG | 0o644, b'x')]))

    def test_root_must_be_a_directory(self):
        with self.assertRaisesRegex(ValueError, 'directory root'):
            p.normalize_cpio(cpio([('.', stat.S_IFREG | 0o644, b'')]))

    def test_nonzero_trailing_bytes_refuse(self):
        raw = bytearray(cpio(BASE)); raw[-1] = 1
        with self.assertRaisesRegex(ValueError, 'hidden trailing bytes'):
            p.normalize_cpio(bytes(raw))

    def test_links_and_privileged_modes_refuse(self):
        for mode in (stat.S_IFLNK | 0o777, stat.S_IFREG | 0o4755):
            with self.subTest(mode=mode), self.assertRaisesRegex(ValueError, 'link/special/privileged'):
                p.normalize_cpio(cpio([BASE[0], ('./payload', mode, b'target')]))

    def test_hardlink_semantics_are_not_normalized(self):
        rows = [*BASE, ('./alias', stat.S_IFREG | 0o644, b'')]
        raw = bytearray(cpio(rows)); offset = sum(len(p.cpio_header(n, m, len(d), i)) + len(d) for i, (n, m, d) in enumerate(BASE))
        raw[offset + 12:offset + 18] = b'000001'
        raw[offset + 36:offset + 42] = b'000002'
        with self.assertRaisesRegex(ValueError, 'hard-link alias'):
            p.normalize_cpio(bytes(raw))

    def test_external_cache_link_count_without_archive_alias_is_neutralized(self):
        raw = bytearray(cpio(BASE)); first_size = len(p.cpio_header('.', BASE[0][1], 0, 0)); raw[first_size + 36:first_size + 42] = b'000002'
        final, _ = p.normalize_cpio(bytes(raw))
        self.assertEqual(p.content_inventory(p.cpio_records(bytes(raw))), p.content_inventory(p.cpio_records(final)))
        self.assertTrue(all(row['link_count'] == 1 for row in p.cpio_records(final)))

    def test_bom_filters_only_matching_recognized_metadata(self):
        rows = p.cpio_records(cpio([*BASE, ('./._payload', stat.S_IFREG | 0o644, apple_double())]))
        listing = '.\t40755\t0/0\n./payload\t100644\t0/0\t26\t1234\n./._payload\t100644\t0/0\t0\t0\n'
        self.assertEqual(p.filtered_bom(listing, rows), '.\t40755\t0/0\n./payload\t100644\t0/0\t26\t1234\n')
        with self.assertRaisesRegex(ValueError, 'ownership'):
            p.filtered_bom(listing.replace('0/0', '501/20'), rows)

    def test_bom_missing_or_extra_entries_refuse(self):
        rows = p.cpio_records(cpio(BASE))
        with self.assertRaisesRegex(ValueError, 'omits CPIO'):
            p.filtered_bom('.\t40755\t0/0\n', rows)
        with self.assertRaisesRegex(ValueError, 'membership differs'):
            p.filtered_bom('.\t40755\t0/0\n./unknown\t100644\t0/0\t0\t0\n', rows)

    def test_gzip_trailing_data_and_concatenated_stream_refuse(self):
        import gzip
        raw = gzip.compress(cpio(BASE), mtime=0)
        self.assertEqual(p.gzip_bytes(raw), cpio(BASE))
        for tail in (b'hidden data', raw):
            with self.subTest(tail=tail[:12]), self.assertRaisesRegex(ValueError, 'trailing bytes'):
                p.gzip_bytes(raw + tail)

    def test_finalizer_refuses_dangling_and_ancestor_output_links(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); source = root / 'source.pkg'; source.write_bytes(b'not executed')
            (root / 'out.pkg').symlink_to(root / 'absent')
            with self.assertRaisesRegex(ValueError, 'linked wrapper'):
                p.finalize(source, root / 'out.pkg', root / 'work', {})
            actual = root / 'actual'; actual.mkdir(); (root / 'alias').symlink_to(actual, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, 'linked wrapper'):
                p.finalize(source, root / 'alias/out.pkg', root / 'work', {})


if __name__ == '__main__':
    unittest.main()
