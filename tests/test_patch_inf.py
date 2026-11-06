from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
import patch_inf as tool
from prepare_test_package import SOURCE, lab_inf


class InfPatchTests(unittest.TestCase):
    def test_separate_copy_diff_and_source_preservation(self):
        root = tool.ROOT / 'build/inf-tests'
        root.mkdir(parents=True, exist_ok=True)
        with tempfile.TemporaryDirectory(dir=root) as directory:
            folder = Path(directory)
            source = folder / 'original.inf'
            original = (SOURCE / 'RDIF1064.INF').read_bytes()
            source.write_bytes(original)
            output_root = folder / 'output'
            output = output_root / 'patched.inf'
            with patch.object(tool, 'OUTPUT_ROOT', output_root):
                result = tool.patch_inf(source, output)
                self.assertEqual(output.read_bytes(), lab_inf(original)[0])
                self.assertTrue(output.with_suffix('.diff').exists())
                self.assertFalse(result['source_modified'])
                tool.patch_inf(source, output)
                with self.assertRaisesRegex(ValueError, 'original INF'):
                    tool.patch_inf(source, source)
                with self.assertRaises(ValueError):
                    tool.patch_inf(source, folder / 'outside.inf')
                output.write_bytes(b'different')
                with self.assertRaises(ValueError):
                    tool.patch_inf(source, output)
            self.assertEqual(source.read_bytes(), original)

    def test_cli_help_needs_no_vendor_or_analysis_dependencies(self):
        result = subprocess.run([sys.executable, str(tool.ROOT / 'tools/patch_inf.py'), '--help'],
                                capture_output=True, text=True)
        self.assertEqual(result.returncode, 0)
        self.assertIn('never overwrite', result.stdout)


if __name__ == '__main__':
    unittest.main()
