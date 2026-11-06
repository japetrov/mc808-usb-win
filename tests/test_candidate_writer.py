import copy
import hashlib
from pathlib import Path
import struct
import subprocess
import sys
import tempfile
import unittest

import pefile
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from candidate_writer import OUTPUT_ROOT,serialize_experimental,guarded_write
from compare_candidate import compare
from control_flow import discover
from nx_manifest import manifest


ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT/'Files/64bit/Files/RDWM1064.SYS'


class CandidateTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = SOURCE.read_bytes()
        cls.design = manifest(cls.data,discover(cls.data))
        cls.candidate,cls.checksum = serialize_experimental(cls.data,cls.design,experimental=True,accept_init=True,accept_nx=True)

    def test_default_and_partial_acknowledgments_refuse_serialization(self):
        for options in ({},{'experimental':True},{'experimental':True,'accept_init':True},
                        {'experimental':True,'accept_nx':True},{'accept_init':True,'accept_nx':True}):
            with self.subTest(options=options),self.assertRaises(ValueError):
                serialize_experimental(self.data,self.design,**options)

    def test_actual_original_candidate_comparison_passes_with_two_parsers(self):
        result = compare(self.data,self.candidate,self.design)
        self.assertTrue(result['passed'])
        self.assertEqual(result['byte_coverage'],83456)
        self.assertEqual(result['preserved_instructions_compared'],12096)
        self.assertEqual(result['intentional_call_redirects'],10)
        self.assertFalse(result['windows_loader_tested'])
        self.assertFalse(result['hvci_compatibility_proven'])

    def test_checksum_agrees_with_independent_16_bit_word_algorithm(self):
        offset = self.checksum['file_offset']
        total = 0
        for at in range(0,len(self.candidate),2):
            if offset<=at<offset+4:
                continue
            total += int.from_bytes(self.candidate[at:at+2],'little')
            total = (total & 0xffff)+(total >> 16)
        total = (total & 0xffff)+(total >> 16)
        self.assertEqual(total+len(self.candidate),self.checksum['new_value'])
        self.assertEqual(pefile.PE(data=self.candidate).OPTIONAL_HEADER.CheckSum,total+len(self.candidate))

    def test_corruption_of_code_import_unwind_resource_and_padding_is_rejected(self):
        # Chosen from actual candidate regions, not the checksum field.
        for rva in (0x1010,0x11028,0x117f0,0x16060,0x10c00,0x1504e):
            p = pefile.PE(data=self.candidate)
            at = p.get_offset_from_rva(rva)
            broken = bytearray(self.candidate)
            broken[at] ^= 1
            with self.subTest(rva=hex(rva)),self.assertRaises(ValueError):
                compare(self.data,bytes(broken),self.design)
        # A newly introduced raw-padding byte is also covered.
        broken = bytearray(self.candidate)
        broken[0x10100] = 0xff
        with self.assertRaises(ValueError):
            compare(self.data,bytes(broken),self.design)

    def test_recomputing_checksum_cannot_hide_an_unexplained_change(self):
        broken = bytearray(self.candidate)
        broken[0x10100] = 0x12
        p = pefile.PE(data=bytes(broken))
        struct.pack_into('<I',broken,self.checksum['file_offset'],p.generate_checksum())
        with self.assertRaises(ValueError):
            compare(self.data,bytes(broken),self.design)

    def test_existing_original_and_wrong_input_are_never_written(self):
        with self.assertRaises(ValueError):
            serialize_experimental(self.data+b'x',self.design,experimental=True,accept_init=True,accept_nx=True)
        with self.assertRaises(ValueError):
            guarded_write(SOURCE,SOURCE,self.candidate)
        self.assertEqual(SOURCE.read_bytes(),self.data)

    def test_invalid_copy_spans_fail_before_a_file_is_written(self):
        d = copy.deepcopy(self.design)
        d['copies'][1]['target_file_offset'] = 0
        with self.assertRaises(ValueError):
            serialize_experimental(self.data,d,experimental=True,accept_init=True,accept_nx=True)

    def test_deterministic_serialization_and_candidate_has_no_embedded_signature(self):
        again,_ = serialize_experimental(self.data,self.design,experimental=True,accept_init=True,accept_nx=True)
        self.assertEqual(again,self.candidate)
        p = pefile.PE(data=again)
        self.assertEqual(p.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress,0)
        self.assertEqual(p.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size,0)

    def test_output_guard_refuses_outside_build_root_and_non_sys_extension(self):
        for path in (ROOT/'build/forbidden.sys',OUTPUT_ROOT/'not-a-driver.txt'):
            with self.subTest(path=path),self.assertRaises(ValueError):
                guarded_write(path,SOURCE,self.candidate)

    def test_guarded_write_reuses_identical_artifact_but_refuses_overwrite(self):
        OUTPUT_ROOT.mkdir(parents=True,exist_ok=True)
        with tempfile.TemporaryDirectory(prefix='writer-test-',dir=OUTPUT_ROOT) as temp:
            folder = Path(temp).resolve()
            self.assertTrue(folder.is_relative_to(OUTPUT_ROOT.resolve()))
            path = folder/'candidate.sys'
            self.assertTrue(guarded_write(path,SOURCE,self.candidate))
            self.assertFalse(guarded_write(path,SOURCE,self.candidate))
            with self.assertRaises(ValueError):
                guarded_write(path,SOURCE,b'different')
            self.assertEqual(path.read_bytes(),self.candidate)

    def test_cli_without_flags_stops_before_native_build_or_emission(self):
        result = subprocess.run([sys.executable,str(ROOT/'tools/candidate_writer.py')],cwd=ROOT,capture_output=True,text=True)
        self.assertNotEqual(result.returncode,0)
        self.assertIn('All three experimental acknowledgments',result.stderr)
        self.assertEqual(SOURCE.read_bytes(),self.data)


if __name__=='__main__':
    unittest.main()
