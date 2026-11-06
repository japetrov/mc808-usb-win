"""Patch a reviewed MC-808 INF into build/inf; never overwrite the input."""
import argparse
import json
from pathlib import Path

from prepare_test_package import ROOT, SOURCE, lab_inf, sha

OUTPUT_ROOT = ROOT / 'build/inf'


def patch_inf(source, output=None):
    source = Path(source).resolve()
    output = Path(output or OUTPUT_ROOT / 'RDIF1064.INF').resolve()
    if output == source or (output.exists() and output.samefile(source)):
        raise ValueError('Refusing to overwrite the original INF')
    if not output.is_relative_to(OUTPUT_ROOT.resolve()) or output.suffix.casefold() != '.inf':
        raise ValueError('Patched INF must stay under build/inf')
    before = source.read_bytes()
    patched, diff = lab_inf(before)
    evidence = dict(source_sha256=sha(before), patched_sha256=sha(patched),
                    source_modified=False, catalog_created=False, signed=False,
                    changes=['Lab DriverVer and fresh catalog name',
                             'Windows 11 workstation build 26200+ model decoration',
                             'Old model/control-selection blocks replaced; install directives preserved'])
    files = {output: patched, output.with_suffix('.diff'): diff.encode(),
             output.with_suffix('.json'): (json.dumps(evidence, indent=2) + '\n').encode()}
    for path, data in files.items():
        if not path.resolve().is_relative_to(OUTPUT_ROOT.resolve()):
            raise ValueError('INF evidence path escapes build/inf')
        if path.exists() and path.samefile(source):
            raise ValueError('Refusing original INF alias')
        if path.exists() and path.read_bytes() != data:
            raise ValueError('Refusing a differing existing output: ' + path.name)
    for path, data in files.items():
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)
    if source.read_bytes() != before:
        raise RuntimeError('Source INF changed during preparation')
    return evidence


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('source', type=Path, nargs='?', default=SOURCE / 'RDIF1064.INF')
    parser.add_argument('--output', type=Path, default=OUTPUT_ROOT / 'RDIF1064.INF')
    args = parser.parse_args()
    result = patch_inf(args.source, args.output)
    print(json.dumps(dict(output=str(args.output), **result), indent=2))
