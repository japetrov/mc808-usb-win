from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
from audit_repository import check_file
import prepare_github_repository as publisher


class PublicationTests(unittest.TestCase):
    def scratch(self):
        root = Path(__file__).resolve().parents[1] / 'build/publication-tests'
        root.mkdir(parents=True, exist_ok=True)
        return tempfile.TemporaryDirectory(dir=root)

    def test_rejects_vendor_binary_keys_and_raw_evidence(self):
        for name in ['driver.SyS', 'Files/driver.inf', 'build/README.md', 'certificate.pfx',
                     'trace.etl', 'reports/research.md', 'asm/reviewed/init.asm']:
            with self.subTest(name=name):
                self.assertTrue(check_file(name, b'text'))
        self.assertTrue(check_file('tools/example.py', b'MZ fake image'))
        self.assertTrue(check_file('README.md', ('-----BEGIN ' + 'PRIVATE KEY-----').encode()))

    def test_accepts_source_and_rejects_traversal(self):
        self.assertFalse(check_file('tools/analysis.py', b'print(1)\n'))
        self.assertTrue(check_file('../escape.py', b'text'))

    def test_export_is_fresh_idempotent_and_never_overwrites(self):
        with self.scratch() as directory:
            output = Path(directory) / 'export'
            with patch.object(publisher, 'OUTPUT', output):
                files = {'README.md': b'guide', 'tools/example.py': b'print(1)\n'}
                publisher.export(files, output)
                publisher.export(files, output)
                with self.assertRaises(ValueError):
                    publisher.export({'README.md': b'different'}, output)
                self.assertEqual((output / 'README.md').read_bytes(), b'guide')
                with self.assertRaises(ValueError):
                    publisher.export({'../escape.py': b'x'}, output)
                with self.assertRaises(ValueError):
                    publisher.export(files, output.parent)
                (output / 'unexpected.txt').write_bytes(b'extra')
                with self.assertRaises(ValueError):
                    publisher.export(files, output)

    def test_allowlist_omits_vendor_and_research_material(self):
        files = publisher.publication_files()
        self.assertIn('README.md', files)
        self.assertIn('asm/reconstruction/nx_pool_shims.asm', files)
        self.assertTrue(all(not check_file(name, data) for name, data in files.items()))
        self.assertFalse(any(name.startswith(('Files/', 'reports/', 'asm/reviewed/', '.git/')) for name in files))


if __name__ == '__main__':
    unittest.main()
