"""Download/extract pinned local tools only; no installer or system changes."""
import argparse
import hashlib
import json
from pathlib import Path
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def extract_archive(url, filename, algorithm, expected, output, mapping):
    archive = ROOT / '.tools' / filename
    archive.parent.mkdir(exist_ok=True)
    if not archive.exists():
        urllib.request.urlretrieve(url, archive)
    if hashlib.new(algorithm, archive.read_bytes()).hexdigest() != expected:
        raise ValueError('Archive fingerprint mismatch')
    with zipfile.ZipFile(archive) as package:
        files = {name: package.read(member) for name, member in mapping.items()}
    for name, data in files.items():
        path = output / name
        if not path.resolve().is_relative_to(output.resolve()):
            raise ValueError('Unsafe extraction path')
        if path.exists() and path.read_bytes() != data:
            raise ValueError('Refusing different existing tool: ' + name)
    for name, data in files.items():
        path = output / name
        path.parent.mkdir(parents=True, exist_ok=True)
        if not path.exists():
            path.write_bytes(data)
    print(output)


def uasm():
    pin = json.loads((ROOT / 'toolchains/uasm-2.57.json').read_text())
    output = ROOT / '.tools/uasm-2.57'
    extract_archive(pin['archive_url'], 'uasm257_x64.zip', 'sha256', pin['archive_sha256'], output,
                    {name: name for name in ['uasm64.exe', 'License.txt', 'Readme.txt']})
    if hashlib.sha256((output / 'uasm64.exe').read_bytes()).hexdigest() != pin['executable_sha256']:
        raise ValueError('Assembler executable mismatch')


def wdk():
    version = '10.0.26100.6584'
    name = 'microsoft.windows.wdk.x64.' + version + '.nupkg'
    digest = '8e175d6819e1303aaddc656bdf64554ed691d0a1e66438d8d09093327d74390a64e3e01285708af50034f6f05ace9f278b5323bbce2a3394865df21f9f2389fa'
    mapping = {'LICENSE.txt': 'LICENSE.txt'}
    for file in ['Inf2Cat.exe', 'Microsoft.UniversalStore.HardwareWorkflow.Cabinets.dll',
                 'Microsoft.UniversalStore.HardwareWorkflow.Catalogs.dll',
                 'Microsoft.UniversalStore.HardwareWorkflow.InfReader.dll',
                 'Microsoft.UniversalStore.HardwareWorkflow.SubmissionBuilder.dll', 'WindowsProtectedFiles.xml']:
        mapping['inf2cat/' + file] = 'c/bin/10.0.26100.0/x86/' + file
    mapping['infverif/infverif.exe'] = 'c/tools//10.0.26100.0/x64/infverif.exe'
    for file in ['infverif.dll', 'infverifhlk.dll']:
        mapping['infverif/' + file] = 'c/build/10.0.26100.0/bin/x64/' + file
    extract_archive('https://api.nuget.org/v3-flatcontainer/microsoft.windows.wdk.x64/' + version + '/' + name,
                    name, 'sha512', digest, ROOT / ('.tools/wdk-' + version), mapping)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('tool', choices=['uasm', 'wdk'])
    args = parser.parse_args()
    {'uasm': uasm, 'wdk': wdk}[args.tool]()
