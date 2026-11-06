"""Offline package identity and Windows catalog membership; no trust imports."""
import argparse
import ctypes as c
from ctypes import wintypes as w
import hashlib
import json
import os
from pathlib import Path

from prepare_test_package import ROOT, plan_package
from verify_test_signature import verify

PACKAGE_ROOT = ROOT / 'build/test-signed-packages'


def stage(folder):
    folder = Path(folder).resolve()
    if folder.parent != PACKAGE_ROOT.resolve() or not folder.is_dir():
        raise ValueError('Signing stage must be an existing fresh package folder')
    payload = folder / 'driver'
    payload.mkdir()  # Refuse reuse, including a partial/signature-bearing payload.
    for name, data in plan_package().items():
        if name.startswith('driver/'):
            (payload / Path(name).name).write_bytes(data)


def catalog_hashes(catalog, files):
    if os.name != 'nt':
        raise ValueError('Catalog membership requires Windows')
    import msvcrt
    api = c.WinDLL('wintrust', use_last_error=True)
    class Blob(c.Structure):
        _fields_ = [('size', w.DWORD), ('data', c.POINTER(c.c_ubyte))]
    class Attribute(c.Structure):
        _fields_ = [('oid', c.c_char_p), ('value', Blob)]
    class Algorithm(c.Structure):
        _fields_ = [('oid', c.c_char_p), ('parameters', Blob)]
    class Indirect(c.Structure):
        _fields_ = [('data', Attribute), ('algorithm', Algorithm), ('digest', Blob)]
    class Member(c.Structure):
        _fields_ = [('size', w.DWORD), ('tag', w.LPWSTR), ('filename', w.LPWSTR),
                    ('subject', c.c_ubyte * 16), ('flags', w.DWORD), ('indirect', c.POINTER(Indirect))]
    api.CryptCATOpen.argtypes = [w.LPWSTR, w.DWORD, w.HANDLE, w.DWORD, w.DWORD]
    api.CryptCATOpen.restype = w.HANDLE
    api.CryptCATClose.argtypes = [w.HANDLE]
    api.CryptCATAdminAcquireContext2.argtypes = [c.POINTER(w.HANDLE), c.c_void_p, w.LPCWSTR, c.c_void_p, w.DWORD]
    api.CryptCATAdminAcquireContext2.restype = w.BOOL
    api.CryptCATAdminReleaseContext.argtypes = [w.HANDLE, w.DWORD]
    api.CryptCATAdminCalcHashFromFileHandle2.argtypes = [w.HANDLE, w.HANDLE, c.POINTER(w.DWORD), c.c_void_p, w.DWORD]
    api.CryptCATAdminCalcHashFromFileHandle2.restype = w.BOOL
    api.CryptCATGetMemberInfo.argtypes = [w.HANDLE, w.LPWSTR]
    api.CryptCATGetMemberInfo.restype = c.POINTER(Member)
    handle = api.CryptCATOpen(str(Path(catalog).resolve()), 0, None, 0, 0)
    if not handle or handle == c.c_void_p(-1).value:
        raise ValueError('Cannot open catalog: ' + str(c.get_last_error()))
    context = w.HANDLE()
    try:
        if not api.CryptCATAdminAcquireContext2(c.byref(context), None, 'SHA256', None, 0):
            raise ValueError('Cannot acquire SHA256 catalog context')
        results = {}
        for path in files:
            with Path(path).open('rb') as stream:
                size = w.DWORD(32)
                digest = (c.c_ubyte * 32)()
                if not api.CryptCATAdminCalcHashFromFileHandle2(context, msvcrt.get_osfhandle(stream.fileno()), c.byref(size), digest, 0) or size.value != 32:
                    raise ValueError('Cannot calculate catalog hash: ' + Path(path).name)
            expected = bytes(digest)
            member = api.CryptCATGetMemberInfo(handle, expected.hex().upper())
            if not member or not member.contents.indirect:
                raise ValueError('Missing catalog membership: ' + Path(path).name)
            indirect = member.contents.indirect.contents
            actual = c.string_at(indirect.digest.data, indirect.digest.size)
            if indirect.algorithm.oid != b'2.16.840.1.101.3.4.2.1' or actual != expected:
                raise ValueError('Catalog member digest differs: ' + Path(path).name)
            results[Path(path).name] = expected.hex()
        return results
    finally:
        if context:
            api.CryptCATAdminReleaseContext(context, 0)
        api.CryptCATClose(handle)


def verify_package(folder):
    folder = Path(folder)
    driver = folder / 'driver'
    original_plan = plan_package()
    expected = {Path(n).name: data for n, data in original_plan.items() if n.startswith('driver/')}
    catalog = driver / 'MC808_EXPERIMENTAL.CAT'
    if {p.name.casefold() for p in driver.iterdir()} != {n.casefold() for n in expected} | {catalog.name.casefold()}:
        raise ValueError('Unexpected or missing package payload')
    for name, data in expected.items():
        if name != 'RDWM1064.SYS' and (driver / name).read_bytes() != data:
            raise ValueError('INF/companion changed: ' + name)
    unsigned = (ROOT / 'build/experimental/RDWM1064.experimental.sys').read_bytes()
    result = verify(unsigned, (driver / 'RDWM1064.SYS').read_bytes(), (folder / 'MC808-Research-Test.cer').read_bytes())
    result['catalog_member_sha256'] = catalog_hashes(catalog, [driver / name for name in sorted(expected)])
    result['payload_sha256'] = {p.name: hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(driver.iterdir())}
    result['catalog_signature_check'] = 'Separate .NET SignedCms check required'
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('folder', type=Path)
    parser.add_argument('--stage', action='store_true')
    args = parser.parse_args()
    if args.stage:
        stage(args.folder)
    else:
        print(json.dumps(verify_package(args.folder), indent=2))
