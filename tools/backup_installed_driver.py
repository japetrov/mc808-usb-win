"""Copy the identified existing MC-808 package for rollback; never modify Windows.

This is a local driver-file backup, NOT a system image or guaranteed reinstall.
"""
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import uuid

from prepare_test_package import HASHES, ROOT

ROLLBACK_HASHES = dict(HASHES, **{
    'RDID1064.CAT': '2d8bac18071a38a2fd39e20d31a3402a9c216b4a8bfd3d70b50056f9405480be'})


def sha(data):
    return hashlib.sha256(data).hexdigest()


def read_package(folder):
    files = {p.name.casefold(): p for p in folder.iterdir() if p.is_file()}
    result = {}
    for name, expected in ROLLBACK_HASHES.items():
        source = files.get(name.casefold())
        if source is None or source.is_symlink() or source.resolve().parent != folder.resolve():
            raise ValueError('Missing or unsafe original package file: ' + name)
        data = source.read_bytes()
        if sha(data) != expected:
            raise ValueError('Unreviewed installed package identity: ' + name)
        result[name] = data
    return result


def backup():
    if os.name != 'nt':
        raise ValueError('Installed-package backup requires Windows')
    windows = Path(os.environ['SystemRoot']).resolve()
    published = []
    for inf in (windows / 'INF').glob('oem*.inf'):
        if sha(inf.read_bytes()) == HASHES['RDIF1064.INF']:
            published.append(inf)
    if len(published) != 1:
        raise ValueError('Expected exactly one hash-matching published Roland INF')
    repository = windows / 'System32/DriverStore/FileRepository'
    candidates = list(repository.glob('rdif1064.inf_amd64_*'))
    matches = []
    for folder in candidates:
        if not folder.is_dir() or folder.is_symlink() or folder.resolve().parent != repository.resolve():
            continue
        try:
            matches.append((folder, read_package(folder)))
        except ValueError:
            continue
    if len(matches) != 1:
        raise ValueError('Expected exactly one hash-matching driver-store package')
    source, files = matches[0]
    installed = windows / 'System32/drivers/rdwm1064.sys'
    installed_hash = sha(installed.read_bytes())
    if installed_hash != HASHES['RDWM1064.SYS']:
        raise ValueError('Installed SYS is not the reviewed original')
    root = ROOT / 'build/rollback'
    root.mkdir(parents=True, exist_ok=True)
    output = root / (datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ') + '-' + uuid.uuid4().hex)
    output.mkdir()
    payload = output / 'vendor-driver'
    payload.mkdir()
    for name, data in files.items():
        destination = payload / name
        destination.write_bytes(data)
        if destination.read_bytes() != data:
            raise ValueError('Backup verification failed: ' + name)
    (output / published[0].name).write_bytes(published[0].read_bytes())
    if read_package(source) != files or sha(installed.read_bytes()) != installed_hash:
        raise ValueError('Source changed during backup; no completed manifest will be written')
    evidence = dict(captured_utc=datetime.now(timezone.utc).isoformat(),
                    published_inf=published[0].name, driver_store_source=str(source),
                    installed_sys_sha256=installed_hash, files_sha256=ROLLBACK_HASHES,
                    verified_copy=True, system_image=False, off_machine_copy=False,
                    driver_uninstalled=False, windows_files_changed=False,
                    caveats=['Original modified INF and original catalog preserved as found; signature validity not asserted',
                             'Same-disk file backup does not replace a restorable system backup',
                             'PNF cache excluded; no installer executed'])
    (output / 'manifest.json').write_text(json.dumps(evidence, indent=2) + '\n')
    return output


if __name__ == '__main__':
    print(backup())
