from collections import Counter
from pathlib import Path
import struct
import sys
import unittest
from types import SimpleNamespace

import pefile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from control_flow import discover
from layout_preview import preview
from metadata_plan import Layout, decode_unwind, plan, regroup_relocations


class MetadataPrimitiveTests(unittest.TestCase):
    def test_exclusive_end_uses_owner_when_next_section_begins_at_same_old_address(self):
        pe = SimpleNamespace(OPTIONAL_HEADER=SimpleNamespace(SizeOfHeaders=0))
        layout = Layout(pe,[dict(old_begin=0x1000,old_extent=0x100,old_virtual_size=0x100,new_begin=0x2000),
                            dict(old_begin=0x1100,old_extent=0x100,old_virtual_size=0x100,new_begin=0x4000)])
        self.assertEqual(layout.rva(0x1100),0x4000)
        self.assertEqual(layout.end(0x1100,0x1000),0x2100)

    def test_large_allocation_extension_is_not_decoded_as_an_operation(self):
        r = decode_unwind(bytes([1,9,2,0]),bytes([9,1])+struct.pack('<H',0x100))
        self.assertEqual(len(r['operations']),1)
        self.assertEqual(r['stack_size'],0x800)
        self.assertEqual(r['operations'][0]['slots'],2)

    def test_unscaled_large_allocation_consumes_three_slots(self):
        r = decode_unwind(bytes([1,9,3,0]),bytes([9,0x11])+struct.pack('<I',0x100000))
        self.assertEqual(r['stack_size'],0x100000)
        self.assertEqual(r['operations'][0]['slots'],3)

    def test_save_offset_is_distinct_from_stack_allocation(self):
        r = decode_unwind(bytes([1,8,2,0]),bytes([8,0x34])+struct.pack('<H',4))
        self.assertEqual(r['operations'][0]['stack_offset'],32)
        self.assertEqual(r['stack_size'],0)

    def test_truncated_reserved_and_wrong_version_unwind_are_rejected(self):
        for head,codes in [(bytes([1,9,1,0]),bytes([9,1])),
                           (bytes([1,9,1,0]),bytes([9,6])),
                           (bytes([2,9,1,0]),bytes([9,2])),
                           (bytes([1,9,2,0]),bytes([9,2]))]:
            with self.subTest(head=head,codes=codes),self.assertRaises(ValueError):
                decode_unwind(head,codes)

    def test_relocation_pages_offsets_and_absolute_padding_are_rebuilt(self):
        rows = regroup_relocations([0x2008,0x1008,0x1010])
        self.assertEqual([r['page_rva'] for r in rows],[0x1000,0x2000])
        self.assertEqual(rows[1]['entries'],[0xa008,0])
        self.assertEqual(rows[1]['size'],12)
        with self.assertRaises(ValueError):
            regroup_relocations([0x1008,0x1008])


class MetadataPlanTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(__file__).resolve().parents[1]/'Files/64bit/Files/RDWM1064.SYS'
        cls.data = cls.path.read_bytes()
        cls.pe = pefile.PE(data=cls.data)
        cls.flow = discover(cls.data)
        cls.before = preview(cls.data,cls.flow)
        cls.plan = plan(cls.data,cls.flow)
        cls.layout = Layout(cls.pe,cls.plan['layout'])

    def test_fields_match_original_bytes_and_do_not_overlap_other_patches(self):
        occupied = {byte for f in self.before['fixups'] for byte in range(f['site'],f['site']+f['width'])}
        for f in self.plan['fields']:
            value = int.from_bytes(self.data[f['old_file_offset']:f['old_file_offset']+f['width']],'little')
            self.assertEqual(value,f['old_value'])
            for byte in range(f['old_site_rva'],f['old_site_rva']+f['width']):
                self.assertNotIn(byte,occupied)
                occupied.add(byte)

    def test_import_names_counts_and_mapped_iat_locations_match_original(self):
        self.assertEqual(sum(len(d['symbols']) for d in self.plan['imports']),56)
        for new,old in zip(self.plan['imports'],self.pe.DIRECTORY_ENTRY_IMPORT):
            self.assertEqual(new['dll'],old.dll.decode())
            for n,s in enumerate(new['symbols']):
                self.assertEqual(s['name'],old.imports[n].name.decode())
                self.assertEqual(s['hint'],old.imports[n].hint)
                self.assertEqual(s['new_iat_rva'],0x11000+old.struct.FirstThunk-0xff80+8*n)

    def test_debug_file_pointer_and_rva_are_mapped_independently(self):
        d = self.plan['debug'][0]
        self.assertEqual(d['old_rva'],0x10690)
        self.assertEqual(d['new_rva'],0x11710)
        self.assertEqual(d['new_file_offset'],0x10710)
        self.assertNotEqual(d['new_rva'],d['new_file_offset'])

    def test_shared_unwind_records_and_frame_relative_cookie_values_are_preserved(self):
        self.assertEqual(len(self.plan['unwind_records']),82)
        self.assertEqual(len(self.plan['runtime_functions']),281)
        handler_rows = [u for u in self.plan['unwind_records'] if 'handler_rva' in u]
        self.assertEqual(len(handler_rows),5)
        self.assertEqual({u['cookie_offset'] for u in handler_rows},{0x278,0x2a8,0x2b0,0x460,0x480})
        cookies = [b for b in self.plan['preserved_blobs'] if 'gs_cookie_stack_offset' in b['roles']]
        self.assertEqual(len(cookies),5)
        self.assertEqual(Counter(f['new_unwind'] for f in self.plan['runtime_functions']),
                         Counter(self.layout.rva(e.struct.UnwindData) for e in self.pe.DIRECTORY_ENTRY_EXCEPTION))

    def test_all_prologue_stack_sizes_agree_with_independent_frame_analysis(self):
        by_unwind = {u['new_rva']:u for u in self.plan['unwind_records']}
        for f in self.plan['runtime_functions']:
            self.assertEqual(f['prologue_stack_bytes'],by_unwind[f['new_unwind']]['stack_size'])
            self.assertEqual(f['new_end']-f['new_begin'],f['old_end']-f['old_begin'])

    def test_relocation_rebuild_has_exactly_the_mapped_original_sites(self):
        rebuild = self.plan['relocation_rebuild']
        sites = [b['page_rva']+(e & 0xfff) for b in rebuild['blocks'] for e in b['entries'] if e>>12==10]
        originals = [e.rva for b in self.pe.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type==10]
        self.assertEqual(sorted(sites),sorted(self.layout.rva(x) for x in originals))
        self.assertEqual(len(rebuild['blocks']),3)
        self.assertEqual(rebuild['new_size'],0x1b8)
        self.assertLessEqual(rebuild['new_size'],rebuild['virtual_capacity'])

    def test_abstract_rebasing_preserves_pointer_target_identity_at_three_bases(self):
        # Arithmetic dictionaries only; no PE bytes are built or kernel code run.
        patches = [f for f in self.before['fixups'] if f['kind']=='dir64_value']
        for load_base in (0x10000,0x180000000,0xfffff80000000000):
            for f in patches:
                old_rebased = f['old_value']-self.pe.OPTIONAL_HEADER.ImageBase+load_base
                new_rebased = f['new_value']-self.pe.OPTIONAL_HEADER.ImageBase+load_base
                self.assertEqual(new_rebased-load_base,self.layout.rva(old_rebased-load_base))

    def test_resource_payload_mapping_preserves_root_relative_links(self):
        leaf = self.plan['resources'][0]
        self.assertEqual(leaf['old_payload_rva'],0x13860)
        self.assertEqual(leaf['new_payload_rva'],0x16060)
        links = [b for b in self.plan['preserved_blobs'] if 'resource_root_relative_link' in b['roles']]
        self.assertEqual(len(links),3)
        self.assertTrue(all(b['new_rva']-b['old_rva']==0x2800 for b in links))

    def test_every_preserved_blob_is_disjoint_from_planned_field_changes(self):
        changed = {byte for f in self.plan['fields'] if f['changes'] for byte in range(f['old_site_rva'],f['old_site_rva']+f['width'])}
        for blob in self.plan['preserved_blobs']:
            self.assertFalse(changed & set(range(blob['old_rva'],blob['old_rva']+blob['size'])))

    def test_exclusive_region_end_is_not_mistaken_for_next_region_start(self):
        old_end = 0x380+0xfbe0
        self.assertEqual(self.layout.end(old_end,0x380),0x1000+0xfbe0)
        with self.assertRaises(ValueError):
            self.layout.end(0xff81,0x380)

    def test_deferred_checksum_and_conditional_permissions_do_not_approve_emission(self):
        self.assertFalse(self.plan['emission_allowed'])
        self.assertTrue(self.plan['blockers'])
        self.assertTrue(any(d['kind']=='checksum' for d in self.plan['deferred']))
        permissions = [f for f in self.plan['fields'] if f['conditional']]
        self.assertEqual(len(permissions),1)
        self.assertEqual(permissions[0]['kind'],'section_permissions')
        self.assertEqual(self.path.read_bytes(),self.data)

    def test_wrong_original_hash_is_rejected(self):
        with self.assertRaises(ValueError):
            plan(self.data+b'x',self.flow)


if __name__=='__main__':
    unittest.main()
