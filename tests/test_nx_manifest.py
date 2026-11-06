import copy
from pathlib import Path
import sys
import unittest

import capstone
import pefile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from control_flow import discover
from emulate_nx_shims import compare_redirect
from nx_manifest import manifest,validate_actions


class NxManifestTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(__file__).resolve().parents[1]/'Files/64bit/Files/RDWM1064.SYS'
        cls.data = cls.path.read_bytes()
        cls.flow = discover(cls.data)
        cls.design = manifest(cls.data,cls.flow)

    def test_only_ten_reviewed_calls_redirect_and_paged_pool_stays_original(self):
        selected = {r['source_rva'] for r in self.design['redirects']}
        self.assertEqual(selected,{0x835,0x334b,0x8688,0x94d1,0x9612,0xa2bb,0xc11e,0xc4ca,0xea5e,0xf95b})
        self.assertEqual(self.design['skipped_allocations'][0]['source_rva'],0xa5e0)
        self.assertNotIn(0xa5e0,selected)

    def test_original_text_is_retained_and_shims_are_appended(self):
        p = pefile.PE(data=self.data)
        text = next(r for r in self.design['layout'] if r['name']=='.text')
        self.assertEqual(text['new_virtual_size'],0xfc20)
        self.assertEqual(text['new_raw_size'],0xfe00)
        self.assertEqual(self.design['shims'][0]['rva'],text['new_begin']+p.sections[0].SizeOfRawData)
        self.assertEqual([s['rva'] for s in self.design['shims']],[0x10c00,0x10c10])

    def test_redirect_encodes_call_and_nop_with_exact_continuation(self):
        md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        md.detail = True
        for r in self.design['redirects']:
            a = next(a for a in self.design['actions'] if a['kind']=='nx_call_redirect' and a['source_rva']==r['source_rva'])
            ops = list(md.disasm(bytes.fromhex(a['new_bytes']),r['new_rva']))
            self.assertEqual([i.mnemonic for i in ops],['call','nop'])
            self.assertEqual(ops[0].size,5)
            self.assertEqual(ops[0].operands[0].imm,r['shim_rva'])
            self.assertEqual(ops[1].address+ops[1].size,r['resume_rva'])

    def test_leaf_shims_do_not_allocate_stack_or_modify_nonvolatile_registers(self):
        md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        md.detail = True
        for s in self.design['shims']:
            ops = list(md.disasm(bytes.fromhex(s['bytes']),s['rva']))
            self.assertEqual([i.mnemonic for i in ops],['test','jne','mov','jmp','int3'])
            written = {i.reg_name(r) for i in ops[:-1] for r in i.regs_access()[1]}
            self.assertFalse(written & {'rsp','rbx','rbp','rsi','rdi','r12','r13','r14','r15'})
            self.assertEqual(sum(i.size for i in ops),16)

    def test_superseded_iat_operands_are_removed_instead_of_double_patched(self):
        old_sites = {f['site'] for f in self.design['superseded_fixups']}
        self.assertEqual(len(old_sites),10)
        self.assertFalse(any(a['kind']=='rip_displacement' and a['source_rva'] in old_sites for a in self.design['actions']))

    def test_header_and_debug_raw_offsets_account_for_extra_code(self):
        self.assertEqual(self.design['proposed_unsigned_file_size'],0x14600)
        self.assertEqual(self.design['header_values']['SizeOfCode'],0x10600)
        self.assertEqual(self.design['header_values']['SizeOfImage'],0x18000)
        raw = next(a for a in self.design['actions'] if a['kind']=='debug_payload_file_offset')
        virtual = next(a for a in self.design['actions'] if a['kind']=='debug_payload_rva')
        self.assertEqual(int.from_bytes(bytes.fromhex(raw['new_bytes']),'little'),0x10910)
        self.assertEqual(int.from_bytes(bytes.fromhex(virtual['new_bytes']),'little'),0x11710)

    def test_actions_are_disjoint_and_match_original_expected_bytes(self):
        validate_actions(self.data,self.design['actions'],self.design['proposed_unsigned_file_size'])
        occupied = set()
        for a in self.design['actions']:
            count = len(bytes.fromhex(a['new_bytes']))
            positions = set(range(a['target_file_offset'],a['target_file_offset']+count))
            self.assertFalse(occupied & positions)
            occupied.update(positions)
        self.assertEqual(self.path.read_bytes(),self.data)

    def test_action_checker_rejects_overlaps_and_wrong_original_bytes(self):
        actions = copy.deepcopy(self.design['actions'])
        with self.assertRaises(ValueError):
            validate_actions(self.data,actions+[actions[0]],self.design['proposed_unsigned_file_size'])
        actions[0]['old_bytes'] = 'ff'*len(bytes.fromhex(actions[0]['old_bytes']))
        with self.assertRaises(ValueError):
            validate_actions(self.data,actions,self.design['proposed_unsigned_file_size'])

    def test_copy_plan_covers_original_once_without_dropping_raw_padding(self):
        source,target = 0,0
        for c in self.design['copies']:
            self.assertEqual(c['source_file_offset'],source)
            self.assertEqual(c['target_file_offset'],target)
            self.assertGreaterEqual(c['zero_extension'],0)
            source += c['size']
            target += c['size']+c['zero_extension']
        self.assertEqual(source,len(self.data))
        self.assertEqual(target,self.design['proposed_unsigned_file_size'])

    def test_emulated_original_and_redirected_calls_preserve_abi_across_bases(self):
        representative = [next(r for r in self.design['redirects'] if r['api']==name)
                          for name in ('ExAllocatePool','ExAllocatePoolWithTag')]
        for r in representative:
            for base in (0x10000,0x180000000,0xfffff80000000000):
                for pool in (0,1,0x200,0x10,0xaaaaaaaa00000000):
                    for returned in (0,0x123456780):
                        with self.subTest(api=r['api'],base=base,pool=pool,returned=returned):
                            compare_redirect(self.design,r,pool,image_base=base,allocation_result=returned)

    def test_all_redirect_fragments_are_emulated_at_least_once(self):
        for r in self.design['redirects']:
            compare_redirect(self.design,r,0,allocation_result=0x123456780)

    def test_conditional_design_never_claims_permission_or_hvci_approval(self):
        self.assertFalse(self.design['emission_allowed'])
        self.assertTrue(self.design['blockers'])
        self.assertEqual(sum(a['conditional'] for a in self.design['actions']),13)
        self.assertTrue(any(d['kind']=='checksum' for d in self.design['deferred']))


if __name__=='__main__':
    unittest.main()
