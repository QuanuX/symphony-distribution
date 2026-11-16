import importlib.util
import struct
from pathlib import Path
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('archive_padding', Path(__file__).with_name('archive_padding.py'))
m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)


def member(name, payload, *, timestamp='0', uid='0'):
    if len(name) > 15:
        encoded = name.encode(); width = (len(encoded) + 3) // 4 * 4
        payload = encoded.ljust(width, b'\0') + payload; name = '#1/' + str(width)
    else:
        name += '/'
    header = f'{name:<16}{timestamp:<12}{uid:<6}{"0":<6}{"100644":<8}{len(payload):<10}`\n'.encode()
    return header + payload + (b'\n' if len(payload) % 2 else b'')


def fixture(symbols=(b'_foo',), padding=0xAA, table='__.SYMDEF', object_data=b'OBJECT-BYTES'):
    strings, offsets = b'', []
    for name in symbols:
        offsets.append(len(strings)); strings += name + b'\0'
    strings += bytes([padding]) * (-len(strings) % 8)
    def body(object_offset):
        return struct.pack('<I', len(symbols) * 8) + b''.join(struct.pack('<II', off, object_offset) for off in offsets) + struct.pack('<I', len(strings)) + strings
    object_offset = 8 + len(member(table, body(0)))
    return m.MAGIC + member(table, body(object_offset)) + member('unit.o', object_data)


class PaddingTests(unittest.TestCase):
    def test_only_unused_tail_changes_and_second_pass_is_idempotent(self):
        raw = fixture(); fixed, proof = m.normalize_bytes(raw)
        self.assertEqual(proof['padding_size'], 3)
        self.assertEqual(proof['changed_byte_count'], 3)
        begin = proof['padding_offset']; end = begin + proof['padding_size']
        self.assertEqual(fixed[:begin], raw[:begin]); self.assertEqual(fixed[end:], raw[end:])
        self.assertEqual(fixed[begin:end], b'\0' * 3)
        again, record = m.normalize_bytes(fixed)
        self.assertEqual(again, fixed); self.assertEqual(record['changed_byte_count'], 0)
        self.assertEqual(proof['object_members'], record['object_members'])

    def test_independent_padding_values_converge_without_touching_objects(self):
        first, a = m.normalize_bytes(fixture(padding=0xAB))
        second, b = m.normalize_bytes(fixture(padding=0xCD))
        self.assertEqual(first, second); self.assertEqual(a['referenced_symbol_semantics_sha256'], b['referenced_symbol_semantics_sha256'])
        different, _ = m.normalize_bytes(fixture(object_data=b'ALTERED-BYTES'))
        self.assertNotEqual(first, different)

    def test_bsd_extended_sorted_name_and_all_symbol_references_checked(self):
        fixed, proof = m.normalize_bytes(fixture(symbols=(b'_aaa', b'_zzz'), table='__.SYMDEF SORTED'))
        self.assertEqual(proof['symbol_reference_count'], 2)
        self.assertEqual(proof['padding_size'], 6)
        with self.assertRaisesRegex(ValueError, 'not sorted'):
            m.normalize_bytes(fixture(symbols=(b'_zzz', b'_aaa'), table='__.SYMDEF SORTED'))

    def test_referenced_string_bytes_are_not_normalized_away(self):
        first, _ = m.normalize_bytes(fixture(symbols=(b'_foo',)))
        second, _ = m.normalize_bytes(fixture(symbols=(b'_goo',)))
        self.assertNotEqual(first, second)

    def test_empty_index_has_no_padding_or_changes(self):
        fixed, proof = m.normalize_bytes(fixture(symbols=()))
        self.assertEqual(proof['padding_size'], 0); self.assertEqual(proof['changed_byte_count'], 0)

    def test_unknown_symbol_layout_and_gnu_thin_archives_refused(self):
        for raw in (b'!<thin>\n', b'!<arch>\n', fixture(table='__.SYMDEF_64'), fixture(table='other'),
                    m.MAGIC + b'/               ' + fixture()[24:]):
            with self.assertRaises(ValueError): m.normalize_bytes(raw)

    def test_every_object_offset_and_string_offset_is_bounded(self):
        raw = fixture()
        for pos, value in ((72, 999999), (76, 0), (68, 7), (80, 1000000)):
            altered = bytearray(raw); struct.pack_into('<I', altered, pos, value)
            with self.assertRaises(ValueError): m.normalize_bytes(bytes(altered))

    def test_non_alignment_tail_is_not_silently_erased(self):
        raw = fixture(); index = m.archive_members(raw)[0]
        payload = raw[index['payload_start']:index['payload_end']] + b'HIDDEN!!'
        payload = bytearray(payload); struct.pack_into('<I', payload, 12, 16)
        # Repair member reference so only the oversized unreferenced tail is invalid.
        symbol = member('__.SYMDEF', payload)
        struct.pack_into('<I', payload, 8, 8 + len(symbol))
        altered = m.MAGIC + member('__.SYMDEF', payload) + member('unit.o', b'OBJECT-BYTES')
        with self.assertRaisesRegex(ValueError, 'alignment padding'):
            m.normalize_bytes(altered)

    def test_unterminated_symbols_and_truncation_refused(self):
        raw = fixture(); index = m.archive_members(raw)[0]
        no_null = bytearray(raw); no_null[index['payload_start'] + 16:index['payload_end']] = b'X' * 8
        for bad in (bytes(no_null), raw[:-1], raw[:30], raw + b'extra'):
            with self.assertRaises(ValueError): m.normalize_bytes(bad)

    def test_personal_archive_metadata_is_refused_not_rewritten(self):
        for start, width, value in ((24, 12, b'123456'), (36, 6, b'501'), (42, 6, b'20')):
            raw = bytearray(fixture()); raw[start:start + width] = value.ljust(width, b' ')
            with self.assertRaisesRegex(ValueError, 'identity or timestamp'):
                m.normalize_bytes(bytes(raw))

    def test_explicit_unsealed_finalization_converges_and_preserves_object_semantics(self):
        raw = fixture(); members = m.archive_members(raw)
        altered = bytearray(raw)
        for item in members:
            for start, width, value in ((16, 12, b'123456'), (28, 6, b'501'), (34, 6, b'20')):
                begin = item['header_offset'] + start
                altered[begin:begin + width] = value.ljust(width, b' ')
        fixed, proof = m.finalize_unsealed_bytes(bytes(altered))
        expected, _ = m.normalize_bytes(raw)
        self.assertEqual(fixed, expected)
        self.assertEqual(m.archive_members(fixed), members)
        for item in members[1:]:
            start, end = item['payload_start'], item['payload_end']
            self.assertEqual(fixed[start:end], altered[start:end])
        self.assertEqual(len(proof['metadata_fields']), 6)
        self.assertEqual(m.finalize_unsealed_bytes(fixed)[1]['changed_byte_count'], 0)
        self.assertEqual(proof['source_sha256'], m.sha(bytes(altered)))
        self.assertEqual(proof['normalized_sha256'], m.sha(fixed))

    def test_unsealed_finalization_cannot_hide_malformed_metadata_or_references(self):
        for value in (b'-1', b'0x99', b'12\x00'):
            raw = bytearray(fixture()); raw[36:42] = value.ljust(6, b' ')
            with self.assertRaisesRegex(ValueError, 'numeric field'):
                m.finalize_unsealed_bytes(bytes(raw))
        raw = bytearray(fixture()); raw[24:36] = b'123'.ljust(12, b' ')
        struct.pack_into('<I', raw, 76, 0)
        with self.assertRaisesRegex(ValueError, 'object-member header'):
            m.finalize_unsealed_bytes(bytes(raw))
        with self.assertRaises(ValueError): m.finalize_unsealed_bytes(fixture(table='__.SYMDEF_64'))

    def test_copy_requires_exact_bytes_and_new_nonaliased_output(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary).resolve(); source = root / 'source.a'; source.write_bytes(fixture())
            output = root / 'new.a'
            with self.assertRaises(ValueError): m.normalize_copy(source, output, '0' * 64)
            self.assertFalse(output.exists())
            old = source.read_bytes(); proof = m.normalize_copy(source, output, m.sha(old))
            self.assertEqual(source.read_bytes(), old); self.assertEqual(m.sha(output.read_bytes()), proof['normalized_sha256'])
            with self.assertRaises(ValueError): m.normalize_copy(source, output, m.sha(old))
            alias = root / 'alias'; alias.symlink_to(source)
            with self.assertRaises(ValueError): m.normalize_copy(alias, root / 'another.a', m.sha(old))
            with self.assertRaises(ValueError): m.normalize_copy(source, source, m.sha(old))


if __name__ == '__main__':
    unittest.main()
