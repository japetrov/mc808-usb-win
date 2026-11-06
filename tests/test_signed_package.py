from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import verify_signed_package as package


class SignedPackageTests(unittest.TestCase):
    def scratch(self):
        root = package.ROOT / 'build/package-sign-tests'
        root.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=root)

    def test_fresh_stage_and_reuse_refusal(self):
        with self.scratch() as directory:
            root = Path(directory)
            folder = root / 'case'
            folder.mkdir()
            with patch.object(package, 'PACKAGE_ROOT', root):
                package.stage(folder)
                self.assertEqual(len(list((folder / 'driver').iterdir())), 5)
                self.assertEqual((folder / 'driver/RDWM1064.SYS').read_bytes(),
                                 (package.ROOT / 'build/experimental/RDWM1064.experimental.sys').read_bytes())
                with self.assertRaises(FileExistsError):
                    package.stage(folder)

    def test_stage_outside_allowed_root_rejected(self):
        with self.scratch() as directory:
            with self.assertRaises(ValueError):
                package.stage(Path(directory))

    def complete(self):
        manifests = sorted(package.PACKAGE_ROOT.glob('*/manifest.json'))
        if not manifests:
            self.skipTest('Optional native package signing has not been run')
        return manifests[-1].parent

    def test_real_membership_and_companion_tamper(self):
        folder = self.complete()
        self.assertEqual(len(package.verify_package(folder)['catalog_member_sha256']), 5)
        with self.scratch() as directory:
            copy = Path(directory) / 'copy'
            shutil.copytree(folder, copy)
            target = copy / 'driver/RDCI1064.DLL'
            data = bytearray(target.read_bytes())
            data[1024] ^= 1
            target.write_bytes(data)
            with self.assertRaisesRegex(ValueError, 'companion changed'):
                package.verify_package(copy)
            with self.assertRaisesRegex(ValueError, 'Missing catalog membership'):
                package.catalog_hashes(copy / 'driver/MC808_EXPERIMENTAL.CAT', [target])

    def test_catalog_cryptography_and_same_signer(self):
        folder = self.complete()
        pwsh = shutil.which('pwsh')
        if not pwsh:
            self.skipTest('PowerShell 7 unavailable')
        verifier = str(package.ROOT / 'tools/verify_catalog_signature.ps1')
        cert = str(folder / 'MC808-Research-Test.cer')
        catalog = folder / 'driver/MC808_EXPERIMENTAL.CAT'
        def run(path, certificate=cert):
            return subprocess.run([pwsh, '-NoProfile', '-File', verifier, '-Catalog', str(path),
                                   '-Certificate', certificate], capture_output=True, text=True)
        self.assertEqual(run(catalog).returncode, 0)
        with self.scratch() as directory:
            damaged = Path(directory) / 'damaged.cat'
            data = bytearray(catalog.read_bytes())
            data[-8] ^= 1
            damaged.write_bytes(data)
            self.assertNotEqual(run(damaged).returncode, 0)
        others = sorted((package.ROOT / 'build/test-signed').glob('*/manifest.json'))
        if others:
            self.assertNotEqual(run(catalog, str(others[-1].parent / 'MC808-Research-Test.cer')).returncode, 0)


if __name__ == '__main__':
    unittest.main()
