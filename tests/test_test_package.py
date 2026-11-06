import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import prepare_test_package as package


class PackageTests(unittest.TestCase):
    def test_payload_identity_and_exclusions(self):
        files = package.plan_package()
        payload = {name for name in files if name.startswith('driver/')}
        self.assertEqual(payload, {'driver/' + n for n in package.HASHES})
        self.assertEqual(package.sha(files['driver/RDWM1064.SYS']), package.CANDIDATE_HASH)
        for name in ('RDCI1064.DLL', 'RDCP1064.CPL', 'RDDP1064.DAT'):
            self.assertEqual(package.sha(files['driver/' + name]), package.HASHES[name])
        self.assertFalse(json.loads(files['evidence/package.json'])['hvci_compatibility_proven'])

    def test_inf_preserves_install_behavior(self):
        data, diff = package.lab_inf((package.SOURCE / 'RDIF1064.INF').read_bytes())
        text = data.decode('utf-16')
        self.assertTrue(data.startswith(b'\xff\xfe'))
        self.assertIn('[Roland.' + package.DECORATION + ']', text)
        self.assertNotIn('[Roland.NTamd64.6.1]', text)
        self.assertIn('USB\\VID_0582&PID_00A9', text)
        original = (package.SOURCE / 'RDIF1064.INF').read_bytes().decode('utf-16')
        # All installation/service/interface/companion directives remain exact.
        marker = '[RDID0064Install.NTamd64]'
        self.assertEqual(text[text.index(marker):], original[original.index(marker):])
        self.assertIn('MC808_EXPERIMENTAL.CAT', diff)

    def test_reject_unreviewed_inputs(self):
        with self.assertRaises(ValueError):
            package.lab_inf(b'changed')
        with self.assertRaises(ValueError):
            package.plan_package(candidate=b'changed')

    def test_output_guard_and_idempotence(self):
        scratch = package.ROOT / 'build/package-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            root = Path(directory) / 'package'
            with patch.object(package, 'OUTPUT', root):
                files = {'driver/a.sys': b'candidate', 'evidence/a.txt': b'evidence'}
                package.write_package(files, root)
                package.write_package(files, root)
                with self.assertRaises(ValueError):
                    package.write_package({'driver/a.sys': b'changed'}, root)
                (root / 'driver/stale.cat').write_bytes(b'old catalog')
                with self.assertRaises(ValueError):
                    package.write_package(files, root)
                with self.assertRaises(ValueError):
                    package.write_package(files, root.parent)
                with self.assertRaises(ValueError):
                    package.write_package({'../escape': b'x'}, root)
                self.assertEqual((root / 'driver/a.sys').read_bytes(), b'candidate')


if __name__ == '__main__':
    unittest.main()
