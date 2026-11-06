"""Discovery regressions and in-memory synthetic control-flow tests; no loading."""
from pathlib import Path
import struct
import sys
import unittest

import pefile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from control_flow import discover
from semantic_review import review

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'Files/64bit/Files/RDWM1064.SYS'


class ControlFlowTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = SOURCE.read_bytes()
        cls.flow = discover(cls.data)

    def test_exact_partition_and_original_byte_fidelity(self):
        f = self.flow
        p = pefile.PE(data=self.data)
        covered = set()
        for i in f['instructions']:
            self.assertEqual(bytes.fromhex(i['bytes']),p.get_data(i['rva'],i['size']))
            for at in range(i['rva'],i['rva']+i['size']):
                self.assertNotIn(at,covered)
                covered.add(at)
        for d in f['reviewed_data_ranges']+f['unclassified_executable_ranges']:
            for at in range(d['begin'],d['end']):
                s = p.get_section_by_rva(at)
                if s and s.Characteristics & 0x20000000 and at<s.VirtualAddress+s.Misc_VirtualSize:
                    self.assertNotIn(at,covered)
                    covered.add(at)
        self.assertEqual(len(covered),sum(s.Misc_VirtualSize for s in p.sections if s.Characteristics & 0x20000000))
        self.assertFalse(f['decode_failures'])
        self.assertFalse(f['conflicts'])

    def test_switch_targets_are_decoded_and_not_base_relocations(self):
        p = pefile.PE(data=self.data)
        relocs = {e.rva for b in p.DIRECTORY_ENTRY_BASERELOC for e in b.entries}
        decoded = {i['rva'] for i in self.flow['instructions']}
        self.assertEqual(len(self.flow['reviewed_switches']),8)
        for s in self.flow['reviewed_switches']:
            self.assertTrue(s['validated_dispatch'])
            self.assertTrue(set(s['targets'])<=decoded)
            self.assertNotIn(s['table'],relocs)
            for n,target in enumerate(s['targets']):
                self.assertEqual(target,struct.unpack('<I',p.get_data(s['table']+4*n,4))[0])

    def test_handler_payloads_match_real_cookie_prologues(self):
        result = review(self.data,self.flow)
        self.assertEqual(len(result['handlers']),6)
        self.assertEqual(sorted({h['cookie_offset'] for h in result['handlers']}),[0x278,0x2a8,0x2b0,0x460,0x480])
        self.assertEqual(sum(s['pool'].get('value')==0 for s in result['allocation_sites']),8)
        self.assertEqual(sum(s['pool']['kind']=='stack_argument_requires_interprocedural_review' for s in result['allocation_sites']),2)

    def test_import_strings_are_not_decoded_as_code(self):
        self.assertFalse(any(0x13104<=i['rva']<0x137e2 for i in self.flow['instructions']))
        self.assertFalse(any(0xfe10<=i['rva']<0xff80 for i in self.flow['instructions']))

    def synthetic(self,code):
        # In-memory fixture only: disable original function/relocation seeds and
        # replace the entry bytes; never save this PE-derived buffer to disk.
        p = pefile.PE(data=self.data)
        buf = bytearray(self.data)
        struct.pack_into('<I',buf,p.OPTIONAL_HEADER.get_field_absolute_offset('AddressOfEntryPoint'),0x380)
        for index in (3,5):
            struct.pack_into('<II',buf,p.OPTIONAL_HEADER.DATA_DIRECTORY[index].get_file_offset(),0,0)
        buf[0x380:0x380+len(code)] = code
        return discover(bytes(buf))

    def test_recursive_walk_skips_unreachable_bytes_and_follows_call(self):
        # jmp 386; unreachable UD2 bytes; call 390; ret; padding; leaf ret.
        f = self.synthetic(bytes.fromhex('eb040f0b0f0be805000000c3ccccccccccc3'))
        self.assertEqual({i['rva'] for i in f['instructions']},{0x380,0x386,0x38b,0x390})

    def test_overlapping_branch_target_is_rejected_as_conflict(self):
        # jne 383 targets the interior of the following mov eax,imm32.
        f = self.synthetic(bytes.fromhex('7501b811223344c3'))
        self.assertTrue(f['conflicts'])

    def test_undecodable_end_of_section_is_reported(self):
        p = pefile.PE(data=self.data)
        buf = bytearray(self.data)
        end = p.sections[0].VirtualAddress+p.sections[0].Misc_VirtualSize-1
        struct.pack_into('<I',buf,p.OPTIONAL_HEADER.get_field_absolute_offset('AddressOfEntryPoint'),end)
        for index in (3,5):
            struct.pack_into('<II',buf,p.OPTIONAL_HEADER.DATA_DIRECTORY[index].get_file_offset(),0,0)
        buf[end] = 0x0f
        self.assertEqual(discover(bytes(buf))['decode_failures'],[end])

    def test_original_unchanged(self):
        self.assertEqual(SOURCE.read_bytes(),self.data)


if __name__ == '__main__':
    unittest.main()
