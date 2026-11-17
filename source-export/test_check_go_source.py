"""Failed preparation must not mutate source, prior output or foreign custody."""
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest

import check_go_source as builder


class OutputCustody(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name).resolve()
        self.args=SimpleNamespace(output=self.root/'output')
        for name in ('export','repository','candidates','gomodcache'):
            path=self.root/name;path.mkdir();setattr(self.args,name,path)
        tools=self.root/'tools';tools.mkdir();self.args.go=tools/'go';self.args.go.touch()
        self.args.privacy_policy=self.root/'private.json';self.args.privacy_policy.write_text('{}')

    def test_existing_output_refused_without_marker_or_sentinel_change(self):
        for name in ('export','repository','candidates'):
            self.args.output=getattr(self.args,name)
            sentinel=self.args.output/'sentinel';sentinel.write_text('preserve')
            with self.assertRaisesRegex(ValueError,'new'):builder.new_output(self.args)
            builder.mark_incomplete(self.args)
            self.assertEqual(sentinel.read_text(),'preserve')
            self.assertFalse((self.args.output/'INCOMPLETE').exists())

    def test_new_child_inside_protected_inputs_refused(self):
        for name in ('export','repository','candidates','gomodcache'):
            self.args.output=getattr(self.args,name)/'new'
            with self.assertRaisesRegex(ValueError,'disjoint'):builder.new_output(self.args)
            self.assertFalse(self.args.output.exists())

    def test_owned_output_can_retain_failure_but_replacement_cannot(self):
        builder.new_output(self.args)
        builder.mark_incomplete(self.args)
        self.assertTrue((self.args.output/'INCOMPLETE').exists())
        self.args.output.rename(self.root/'retained')
        self.args.output.mkdir(mode=0o700)
        builder.mark_incomplete(self.args)
        self.assertFalse((self.args.output/'INCOMPLETE').exists())

    def test_alias_and_foreign_failure_marker_refused(self):
        alias=self.root/'alias';alias.symlink_to(self.args.repository,target_is_directory=True)
        self.args.output=alias/'new'
        with self.assertRaisesRegex(ValueError,'symlinks'):builder.new_output(self.args)
        self.args.output=self.root/'owned'
        builder.new_output(self.args)
        foreign=self.root/'foreign';foreign.write_text('preserve')
        (self.args.output/'INCOMPLETE').symlink_to(foreign)
        builder.mark_incomplete(self.args)
        self.assertEqual(foreign.read_text(),'preserve')


if __name__=='__main__':unittest.main()
