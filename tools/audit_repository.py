"""Limited source-publication audit, not legal clearance or a complete secret scanner."""
import argparse
import json
from pathlib import Path, PurePosixPath
import re
import subprocess

FORBIDDEN_SUFFIXES = {'.sys', '.dll', '.cpl', '.dat', '.cat', '.exe', '.obj', '.pdb',
                      '.pfx', '.p12', '.key', '.cer', '.crt', '.pem', '.zip', '.nupkg',
                      '.etl', '.evtx', '.dmp', '.msi', '.pnf'}
LOCAL_ROOTS = {'files', 'readme', 'build', 'dist', '.tools', '.venv', '.venv-analysis', '.uv-cache'}


def check_file(name, data):
    path = PurePosixPath(name)
    lower = name.casefold()
    errors = []
    if path.is_absolute() or '..' in path.parts or '\\' in name:
        errors.append('unsafe path')
    if path.parts and (path.parts[0].casefold() in LOCAL_ROOTS or '.git' in path.parts or '__pycache__' in path.parts):
        errors.append('local-only directory')
    if path.suffix.casefold() in FORBIDDEN_SUFFIXES:
        errors.append('binary, vendor file, signing material or raw evidence')
    if lower.startswith(('asm/reviewed/', 'asm/generated/', 'reports/')):
        errors.append('vendor-derived listing or historical research report')
    if data.startswith(b'MZ') or b'\0' in data:
        errors.append('binary content')
    for kind in ('PRIVATE KEY', 'RSA PRIVATE KEY', 'EC PRIVATE KEY', 'ENCRYPTED PRIVATE KEY'):
        marker = ('-----BEGIN ' + kind + '-----').encode()
        if marker in data:
            errors.append('private-key marker')
    if re.search(rb'(?i)[a-z]:[\\/]+Users[\\/]+[^\s\\/]+', data):
        errors.append('machine-specific user path')
    return [name + ': ' + error for error in errors]


def git(root, *args):
    return subprocess.check_output(['git', '-C', str(root), *args])


def audit(root, history=False):
    root = Path(root).resolve()
    top = Path(git(root, 'rev-parse', '--show-toplevel').decode().strip()).resolve()
    if top != root:
        raise ValueError('Audit root must be the repository root, not a nested export')
    names = [n.decode() for n in git(root, 'ls-files', '-z').split(b'\0') if n]
    errors = []
    for name in names:
        path = root / name
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            errors.append(name + ': symlink or outside repository')
        else:
            errors.extend(check_file(name, path.read_bytes()))
    blobs = 0
    if history:
        for row in git(root, 'rev-list', '--objects', '--all').decode().splitlines():
            oid, _, name = row.partition(' ')
            if git(root, 'cat-file', '-t', oid).strip() == b'blob':
                blobs += 1
                errors.extend(check_file(name, git(root, 'cat-file', 'blob', oid)))
    return dict(passed=not errors, tracked_files=len(names), history_blobs_checked=blobs,
                errors=sorted(set(errors)), limitations=['No legal clearance', 'Not a comprehensive secret scanner'])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path.cwd())
    parser.add_argument('--history', action='store_true')
    args = parser.parse_args()
    result = audit(args.root, args.history)
    print(json.dumps(result, indent=2))
    raise SystemExit(0 if result['passed'] else 1)
