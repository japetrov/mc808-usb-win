from pathlib import Path
import struct
import sys
import unittest

import pefile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from control_flow import discover
from ownership_review import inventory


class OwnershipEvidenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(__file__).resolve().parents[1]/'Files/64bit/Files/RDWM1064.SYS'
        cls.data = cls.path.read_bytes()
        cls.flow = discover(cls.data)
        cls.report = inventory(cls.data,cls.flow)

    def test_candidate_table_entries_are_original_relocated_code_pointers(self):
        p = pefile.PE(data=self.data)
        relocated = {e.rva for b in p.DIRECTORY_ENTRY_BASERELOC for e in b.entries}
        for table in self.report['candidate_tables']:
            self.assertTrue(table['slots'])
            for slot in table['slots']:
                self.assertIn(slot['pointer_site'],relocated)
                original = struct.unpack('<Q',p.get_data(slot['pointer_site'],8))[0]
                self.assertEqual(original,p.OPTIONAL_HEADER.ImageBase+slot['target'])
                self.assertTrue(p.get_section_by_rva(slot['target']).Characteristics & 0x20000000)

    def test_six_location_links_are_not_labeled_ownership_proofs(self):
        self.assertEqual(len(self.report['location_links']),6)
        self.assertEqual({x['allocation'] for x in self.report['location_links']},{0xa2bb,0xa5e0,0xc11e,0xc4ca})
        self.assertTrue(all(x['conclusion']=='matching_storage_location_only' for x in self.report['location_links']))

    def test_known_object_sizes_and_pool_arguments(self):
        sites = {a['site']:a for a in self.report['allocations']}
        self.assertEqual(len(sites),11)
        for at,size in [(0x334b,0x2848),(0x8688,0x38),(0x94d1,0x50),(0x9612,0x40),(0xc4ca,0x804),(0xea5e,0xac70),(0xf95b,0x40)]:
            self.assertEqual(sites[at]['slice']['register_arguments']['rdx'],('constant',size))
        self.assertTrue(all(not a['nx_conversion_approved'] for a in sites.values()))

    def test_candidate_allocator_edge_remains_conditional(self):
        path = self.report['conditional_allocator_path']
        self.assertEqual(path['candidate_target'],0xf930)
        self.assertEqual(path['status'],'conditional_object_identity_not_proven')
        self.assertFalse(any(e['source']==path['call'] and e['target']==0xf930 for e in self.flow['edges']))

    def test_original_null_failure_branch_is_retained_as_evidence(self):
        ins = {i['rva']:i for i in self.flow['instructions']}
        self.assertEqual(ins[0x84f]['mnemonic'],'jne')
        self.assertEqual(ins[0x84f]['operands'][0]['value']-0x10000,0x862)
        self.assertEqual(ins[0x860]['mnemonic'],'rep stosb')

    def test_wrong_original_is_rejected_and_file_is_unchanged(self):
        with self.assertRaises(ValueError):
            inventory(self.data+b'x',self.flow)
        self.assertEqual(self.path.read_bytes(),self.data)


if __name__=='__main__':
    unittest.main()
