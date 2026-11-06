from pathlib import Path
import struct
import sys
import unittest

import pefile
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from prepare_test_package import ROOT
from verify_test_signature import preserved_payload, verify


class TestSignatureTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.unsigned = (ROOT / 'build/experimental/RDWM1064.experimental.sys').read_bytes()

    def envelope(self):
        data = bytearray(self.unsigned + struct.pack('<IHH', 16, 0x200, 2) + b'12345678')
        pe = pefile.PE(data=data, fast_load=True)
        struct.pack_into('<II', data, pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(), len(self.unsigned), 16)
        struct.pack_into('<I', data, pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'), pefile.PE(data=data).generate_checksum())
        return data

    def test_only_signing_envelope_changes_are_allowed(self):
        self.assertEqual(preserved_payload(self.unsigned, self.envelope())['appended_certificate_size'], 16)

    def test_code_mutation_rejected(self):
        data = self.envelope()
        data[1024] ^= 1
        with self.assertRaisesRegex(ValueError, 'Signing changed'):
            preserved_payload(self.unsigned, data)

    def test_additional_overlay_rejected(self):
        with self.assertRaisesRegex(ValueError, 'sole appended'):
            preserved_payload(self.unsigned, self.envelope() + b'extra')

    def test_false_checksum_rejected(self):
        data = self.envelope()
        data[328] ^= 1
        with self.assertRaisesRegex(ValueError, 'checksum'):
            preserved_payload(self.unsigned, data)

    def test_fake_signature_fails_cryptographic_verification(self):
        with self.assertRaises(ValueError):
            verify(self.unsigned, self.envelope(), b'not a certificate')

    def test_real_signed_artifact_when_available(self):
        complete = sorted((ROOT / 'build/test-signed').glob('*/manifest.json'))
        if not complete:
            self.skipTest('Optional native offline signing has not been run')
        folder = complete[-1].parent
        signed = (folder / 'RDWM1064.test-signed.sys').read_bytes()
        cert = (folder / 'MC808-Research-Test.cer').read_bytes()
        self.assertTrue(verify(self.unsigned, signed, cert)['offline_signature_valid'])
        with self.assertRaisesRegex(ValueError, 'certificate differs'):
            verify(self.unsigned, signed, cert + b'tamper')
        # Change the RSA encrypted digest, leaving payload and layout intact.
        damaged = bytearray(signed)
        certificate_length = struct.unpack_from('<I', signed, len(self.unsigned))[0]
        damaged[len(self.unsigned) + certificate_length - 8] ^= 1
        pe = pefile.PE(data=damaged)
        struct.pack_into('<I', damaged, pe.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'), pe.generate_checksum())
        preserved_payload(self.unsigned, damaged)
        with self.assertRaises(ValueError):
            verify(self.unsigned, damaged, cert)


if __name__ == '__main__':
    unittest.main()
