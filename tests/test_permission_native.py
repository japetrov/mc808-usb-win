import copy
from pathlib import Path
import struct
import sys
import unittest

from unicorn import UcError
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from control_flow import discover
from emulate_init import run_init,verify,DEFAULT_COOKIE
from nx_manifest import manifest
from permission_review import review
from verify_native_shims import build,verify_object,coff


ROOT = Path(__file__).resolve().parents[1]


class EvidenceBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (ROOT/'Files/64bit/Files/RDWM1064.SYS').read_bytes()
        cls.flow = discover(cls.data)
        cls.design = manifest(cls.data,cls.flow)


class PermissionTests(EvidenceBase):
    def test_no_discovered_direct_init_data_pointer_or_relocation_site(self):
        r = review(self.data,self.flow)
        self.assertFalse(r['init_absolute_pointer_targets'])
        self.assertFalse(r['init_relocation_sites'])
        self.assertFalse(r['init_rip_data_references'])

    def test_known_image_stores_are_data_but_unresolved_aliases_remain_visible(self):
        r = review(self.data,self.flow)
        self.assertEqual({w['target_section'] for w in r['concrete_image_writes']},{'.data'})
        self.assertFalse(r['known_executable_image_writes'])
        self.assertGreater(r['explicit_memory_writes']['unresolved_object_or_alias'],0)
        self.assertFalse(r['emission_allowed'])

    def test_all_six_pending_indexed_offsets_are_accounted_for(self):
        rows = review(self.data,self.flow)['object_displacements']
        self.assertEqual({r['source'] for r in rows},{0x3a1e,0x3e25,0x3f90,0x4fcd,0x507a,0x8133})
        self.assertTrue(all(r['treatment'].startswith('retain_object') for r in rows))

    def test_image_base_materializations_are_exactly_reviewed_switches(self):
        r = review(self.data,self.flow)
        self.assertEqual(len(r['image_base_uses']),8)
        self.assertEqual({x['source'] for x in r['image_base_uses']},
                         {x['source'] for x in self.flow['references'] if x['target']==0})

    def test_registry_access_scalar_is_not_relocated(self):
        scalar = review(self.data,self.flow)['scalar_immediate']
        self.assertEqual(scalar['value'],0x20019)
        self.assertFalse(any(a['source_rva']==0xce32 for a in self.design['actions']))

    def test_wrong_input_cannot_inherit_review(self):
        with self.assertRaises(ValueError):
            review(self.data+b'x',self.flow)


class NativeTests(EvidenceBase):
    def fixture(self):
        text = bytearray(b''.join(bytes.fromhex(s['bytes']) for s in self.design['shims']))
        text[11:15]=text[27:31]=b'\0'*4
        names = ['__imp_ExAllocatePool','__imp_ExAllocatePoolWithTag',
                 'MC808_NxExAllocatePool','MC808_NxExAllocatePoolWithTag']
        symbols,strings = b'',b''
        for n,name in enumerate(names):
            encoded = b'\0'*4+struct.pack('<I',4+len(strings))
            strings += name.encode()+b'\0'
            symbols += struct.pack('<8sIhHBB',encoded,0 if n<3 else 16,0 if n<2 else 1,0,2,0)
        header = struct.pack('<HHIIIHH',0x8664,1,0,112,4,0,0)
        section = struct.pack('<8sIIIIIIHHI',b'.text',0,0,32,60,92,0,2,0,0x60000020)
        relocs = struct.pack('<IIHIIH',11,0,4,27,1,4)
        return header+section+bytes(text)+relocs+symbols+struct.pack('<I',4+len(strings))+strings

    def test_coff_relocations_link_to_exact_emulated_bytes(self):
        self.assertTrue(verify_object(self.fixture(),self.design)['match'])

    def test_wrong_coff_relocation_type_is_rejected(self):
        raw = bytearray(self.fixture())
        struct.pack_into('<H',raw,100,5)
        with self.assertRaises(ValueError):
            verify_object(bytes(raw),self.design)

    def test_native_byte_disagreement_is_rejected(self):
        raw = bytearray(self.fixture())
        raw[60] ^= 1
        with self.assertRaises(ValueError):
            verify_object(bytes(raw),self.design)

    def test_truncated_coff_does_not_succeed(self):
        with self.assertRaises(ValueError):
            coff(self.fixture()[:50])

    @unittest.skipUnless((ROOT/'.tools/uasm-2.57/uasm64.exe').exists(),'Portable UASM is not installed locally')
    def test_pinned_native_assembler_builds_current_source(self):
        result = build(ROOT/'.tools/uasm-2.57/uasm64.exe',output=ROOT/'build/native/test_nx_pool_shims.obj')
        self.assertTrue(result['match'])
        self.assertEqual(result['code_bytes'],32)
        self.assertFalse(result['driver_emitted'])


class InitRxTests(EvidenceBase):
    def test_all_48_cases_run_with_init_pages_nonwritable(self):
        r = verify(self.data,self.design)
        self.assertEqual(r['cases'],48)
        self.assertFalse(r['driver_loaded'])
        self.assertTrue(all(x['init_page_rx'] for x in r['results']))
        self.assertTrue(all(x['final_status']==0 for x in r['results']))

    def test_address_salted_cookie_can_change_while_invariant_is_preserved(self):
        old = run_init(self.data,self.design,cookie=0,tick=0)
        new = run_init(self.data,self.design,rebuilt=True,cookie=0,tick=0)
        self.assertNotEqual(old['cookie'],new['cookie'])
        self.assertEqual(old['cookie']^old['complement'],(1<<64)-1)
        self.assertEqual(new['cookie']^new['complement'],(1<<64)-1)

    def test_zero_seed_fallback_preserves_cookie_default(self):
        for rebuilt in (False,True):
            self.assertEqual(run_init(self.data,self.design,rebuilt=rebuilt,tick='force_fallback')['cookie'],DEFAULT_COOKIE)

    def test_emulator_rejects_an_injected_attempt_to_write_init(self):
        altered = copy.deepcopy(self.design)
        a = next(a for a in altered['actions'] if a['source_rva']==0x130ce)
        # Redirect the cookie store into INIT itself. Only the emulator input is
        # altered; the original SYS and manifest on disk remain untouched.
        a['new_bytes'] = struct.pack('<i',-0x52).hex()
        with self.assertRaises(UcError):
            run_init(self.data,altered,rebuilt=True,cookie=0,tick=0)

    def test_wrong_original_is_rejected(self):
        with self.assertRaises(ValueError):
            run_init(self.data+b'x',self.design)


if __name__=='__main__':
    unittest.main()
