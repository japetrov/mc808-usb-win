"""Prepare an unsigned, hash-bound lab package; never sign, install or load it."""
import difflib
import hashlib
import json
from pathlib import Path
import re

ROOT = Path(__file__).resolve().parents[1]
SOURCE = ROOT / 'Files/64bit/Files'
OUTPUT = ROOT / 'build/test-package'
HASHES = {
    'RDIF1064.INF': 'bb86216efd50efebbac52e238658b6de1887d97561f4bf02377102a499b5fdc4',
    'RDWM1064.SYS': '984f00a9ffe11380e63392e7d7f6e3e5f70aa178a9764d47fc790a2170aaf084',
    'RDCI1064.DLL': '2405d9c5aea19beddb44fb077fad9c4d3fc3b1bab9e24522148ab1a467e56a8e',
    'RDCP1064.CPL': '5a40855c57be16b6173125d42729b483e5c8542f0fcaf64c3d5293792aec3a7f',
    'RDDP1064.DAT': '22430447fade7d07be49206dfe2d9d71a709afaabf4eec78d930f9532c9db34b',
}
CANDIDATE_HASH = '4d2a21846897975e615d095b94cfb54d39ffb88d61380205e501bbff6d4504c6'
DECORATION = 'NTamd64.10.0.1..26200'


def sha(data):
    return hashlib.sha256(data).hexdigest()


def lab_inf(data):
    if sha(data) != HASHES['RDIF1064.INF']:
        raise ValueError('Unreviewed source INF')
    old = data.decode('utf-16')
    text = old.replace('CatalogFile=RDID1064.CAT', 'CatalogFile=MC808_EXPERIMENTAL.CAT')
    text = text.replace('DriverVer=06/29/2011,1.00.00.0000', 'DriverVer=11/06/2026,1.0.0.1')
    text = text.replace('%MfgName%=Roland,NTamd64.6.1,NTamd64.10.0', '%MfgName%=Roland,' + DECORATION)
    text, count = re.subn(r'\[Roland\.NTamd64\.6\.1\].*?(?=\[Roland\.NTamd64\.10\.0\])', '', text, flags=re.S)
    if count != 1:
        raise ValueError('Unexpected model sections')
    text = text.replace('[Roland.NTamd64.10.0]', '[Roland.' + DECORATION + ']')
    text = text.replace(';; Windows 10 / Windows 11 64-bit', ';; Experimental Windows 11 workstation build 26200 or later; unvalidated')
    text = '; UNOFFICIAL UNSIGNED RESEARCH PACKAGE - NOT VALIDATED FOR INSTALLATION\n' + text
    text = text.replace('\r\n', '\n').replace('\n', '\r\n')
    diff = ''.join(difflib.unified_diff(old.splitlines(True), text.splitlines(True), fromfile='vendor/RDIF1064.INF', tofile='lab/RDIF1064.INF'))
    return text.encode('utf-16'), diff


def plan_package(source=SOURCE, candidate=None):
    source = Path(source)
    originals = {name: (source / name).read_bytes() for name in HASHES}
    for name, data in originals.items():
        if sha(data) != HASHES[name]:
            raise ValueError('Source identity differs: ' + name)
    if candidate is None:
        candidate = (ROOT / 'build/experimental/RDWM1064.experimental.sys').read_bytes()
    if sha(candidate) != CANDIDATE_HASH:
        raise ValueError('Unreviewed experimental candidate')
    inf, diff = lab_inf(originals['RDIF1064.INF'])
    files = {'driver/' + name: data for name, data in originals.items() if name not in ('RDIF1064.INF', 'RDWM1064.SYS')}
    files.update({'driver/RDIF1064.INF': inf, 'driver/RDWM1064.SYS': candidate})
    evidence = dict(source_sha256=HASHES, payload_sha256={name: sha(data) for name, data in files.items()},
                    target_decoration=DECORATION, signed=False, catalog_created=False,
                    hvci_compatibility_proven=False, installed=False,
                    caveats=['Conditional INIT RX safety', 'Unproven full NX buffer use',
                             'Legacy co-installer retained; modern Microsoft submission requires redesign'])
    files['evidence/package.json'] = (json.dumps(evidence, indent=2) + '\n').encode()
    files['evidence/inf.diff'] = diff.encode()
    files['README.txt'] = b'UNSIGNED RESEARCH PACKAGE. Do not install yet. See repository TEST_PACKAGE.md.\r\nNo catalog is supplied. Original vendor catalog is invalid for this payload.\r\nNo installer, co-installer or driver has been executed by this tool.\r\n'
    return files


def write_package(files, output=OUTPUT):
    output = Path(output).resolve()
    allowed = OUTPUT.resolve()
    if output != allowed:
        raise ValueError('Output must be build/test-package')
    # Preflight every destination before writing anything. Never clear a directory.
    for name, data in files.items():
        dest = (output / name).resolve()
        if not dest.is_relative_to(output):
            raise ValueError('Unsafe output path')
        if dest.exists() and dest.read_bytes() != data:
            raise ValueError('Refusing differing existing file: ' + name)
    driver = output / 'driver'
    expected = {Path(name).name for name in files if name.startswith('driver/')}
    if driver.exists() and {p.name for p in driver.iterdir()} - expected:
        raise ValueError('Unexpected payload file (possibly a stale catalog)')
    for name, data in files.items():
        dest = output / name
        dest.parent.mkdir(parents=True, exist_ok=True)
        if not dest.exists():
            dest.write_bytes(data)


if __name__ == '__main__':
    files = plan_package()
    write_package(files)
    print(json.dumps({'output': str(OUTPUT), 'payload_files': 5, 'signed': False, 'installed': False}, indent=2))
