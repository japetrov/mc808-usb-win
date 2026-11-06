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

    def test_reviewed_legacy_inf_builds_same_payload_without_editing_source(self):
        choices = [package.SOURCE / 'RDIF1064.INF.old', package.SOURCE / 'RDIF1064.INF']
        legacy = next((p for p in choices if p.exists() and package.sha(p.read_bytes()) == package.LEGACY_INF_HASH), None)
        if legacy is None:
            self.skipTest('Reviewed legacy INF fixture is not present')
        before = legacy.read_bytes()
        output, diff = package.lab_inf(before)
        self.assertEqual(package.sha(output), 'a53a8e56fb78de334f506ad53c6875611fe00cc0eca62844d5501a045314bef8')
        marker = '[RDID0064Install.NTamd64]'
        self.assertEqual(output.decode('utf-16').split(marker, 1)[1], before.decode('utf-16').split(marker, 1)[1])
        self.assertIn('NTamd64.6.2', diff)
        scratch = package.ROOT / 'build/package-tests'
        scratch.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=scratch) as directory:
            folder = Path(directory)
            for name in package.HASHES:
                (folder / name).write_bytes(before if name == 'RDIF1064.INF' else (package.SOURCE / name).read_bytes())
            planned = package.plan_package(source=folder)
            self.assertEqual(planned['driver/RDIF1064.INF'], output)
            evidence = json.loads(planned['evidence/package.json'])
            self.assertEqual(evidence['source_sha256']['RDIF1064.INF'], package.LEGACY_INF_HASH)
            self.assertEqual((folder / 'RDIF1064.INF').read_bytes(), before)
        self.assertEqual(legacy.read_bytes(), before)

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
