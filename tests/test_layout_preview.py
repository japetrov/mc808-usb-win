import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from control_flow import discover
from layout_preview import preview


class PreviewTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (Path(__file__).resolve().parents[1]/'Files/64bit/Files/RDWM1064.SYS').read_bytes()
        cls.flow = discover(cls.data)
        cls.plan = preview(cls.data,cls.flow)

    def test_never_authorizes_emission_and_lists_blockers(self):
        self.assertFalse(self.plan['emission_allowed'])
        self.assertTrue(self.plan['blockers'])

    def test_layout_is_aligned_and_nonoverlapping(self):
        end = 0x1000
        raw_end = 0x400
        for r in self.plan['regions']:
            self.assertEqual(r['new_begin']%4096,0)
            self.assertEqual(r['new_raw_offset']%512,0)
            self.assertEqual(r['new_raw_size']%512,0)
            self.assertGreaterEqual(r['new_begin'],end)
            self.assertGreaterEqual(r['new_raw_offset'],raw_end)
            end = r['new_begin']+r['old_extent']
            raw_end = r['new_raw_offset']+r['new_raw_size']

    def test_displacement_fields_match_original_and_fit(self):
        import pefile
        p = pefile.PE(data=self.data)
        occupied = set()
        for f in self.plan['fixups']:
            signed = f['kind'] in ('rip_displacement','relative_control_transfer')
            original = int.from_bytes(p.get_data(f['site'],f['width']),'little',signed=signed)
            self.assertEqual(original,f['old_value'])
            self.assertEqual(f['changes'],f['old_value']!=f['new_value'])
            for byte in range(f['site'],f['site']+f['width']):
                self.assertNotIn(byte,occupied)
                occupied.add(byte)
            if signed:
                self.assertGreaterEqual(f['new_value'],-(1<<(f['width']*8-1)))
                self.assertLess(f['new_value'],1<<(f['width']*8-1))
        self.assertFalse(self.plan['displacement_overflows'])

    def test_switch_integer_targets_are_moved_despite_no_relocation(self):
        tables = [f for f in self.plan['fixups'] if f['kind']=='switch_target_rva']
        self.assertTrue(tables)
        self.assertTrue(all(f['new_value']-f['old_value']==0xc80 for f in tables))
        indexed = [f for f in self.plan['fixups'] if f['kind']=='imagebase_indexed_displacement']
        self.assertEqual(len(indexed),12)
        self.assertTrue(all(f['changes'] for f in indexed))

    def test_runtime_function_lengths_are_preserved(self):
        self.assertEqual(len(self.plan['mapped_runtime_functions']),281)
        for f in self.plan['mapped_runtime_functions']:
            self.assertEqual(f['old']['end']-f['old']['begin'],f['new']['end']-f['new']['begin'])


if __name__ == '__main__':
    unittest.main()
