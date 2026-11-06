import hashlib
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from analyze_pe import analyze
import pefile

ROOT = Path(__file__).resolve().parents[1]
DRIVER = ROOT/'Files/64bit/Files/RDWM1064.SYS'
EXPECTED = '984f00a9ffe11380e63392e7d7f6e3e5f70aa178a9764d47fc790a2170aaf084'


class AnalysisTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.before = DRIVER.read_bytes()
        cls.report = analyze(DRIVER)
        cls.pe = pefile.PE(data=cls.before)

    def test_original_identity_and_read_only(self):
        self.assertEqual(hashlib.sha256(self.before).hexdigest(), EXPECTED)
        self.assertEqual(DRIVER.read_bytes(), self.before)

    def test_inventory_counts_independent_of_report(self):
        r,p = self.report,self.pe
        self.assertEqual(len(r['directories']),p.OPTIONAL_HEADER.NumberOfRvaAndSizes)
        self.assertEqual(len(r['sections']),p.FILE_HEADER.NumberOfSections)
        self.assertEqual(len(r['exceptions'])*12,p.OPTIONAL_HEADER.DATA_DIRECTORY[3].Size)
        self.assertEqual(sum(len(b['entries']) for b in r['relocations']),208)
        self.assertEqual(sum(len(d['symbols']) for d in r['imports']),56)

    def test_relocation_values_are_backed_by_original_bytes(self):
        for b in self.report['relocations']:
            for e in b['entries']:
                self.assertEqual(e['type'],10)
                off = self.pe.get_offset_from_rva(e['rva'])
                self.assertEqual(e['value'],int.from_bytes(self.before[off:off+8],'little'))

    def test_known_hazards_are_visible(self):
        self.assertEqual(self.report['headers']['optional']['SectionAlignment'],128)
        self.assertTrue(any(s['write'] and s['execute'] for s in self.report['sections']))
        self.assertTrue(any(p['rva']==0xf000 for p in self.report['shared_pages']))
        self.assertEqual(sum('handler_rva' in e['unwind'] for e in self.report['exceptions']),6)

    def test_saved_report_is_reproducible(self):
        self.assertEqual(self.report,json.loads((ROOT/'reports/original-pe.json').read_text()))


if __name__ == '__main__':
    unittest.main()
