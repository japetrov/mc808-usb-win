"""Export curated sources only. Never copy .git, vendor files or generated artifacts."""
import hashlib
import json
from pathlib import Path

from audit_repository import check_file

ROOT = Path(__file__).resolve().parents[1]
OUTPUT = ROOT / 'build/github-ready'
ROOT_FILES = ['README.md', 'RIGHTS.md', 'CONTRIBUTING.md', 'requirements-analysis.txt', '.gitignore', '.gitattributes']
FOLDERS = ['tools', 'tests', 'toolchains', 'docs', '.github', 'asm/reconstruction']
SUFFIXES = {'.py', '.ps1', '.json', '.md', '.asm', '.yml', '.yaml'}


def publication_files(root=ROOT):
    root = Path(root).resolve()
    paths = [root / name for name in ROOT_FILES]
    for folder in FOLDERS:
        paths.extend(p for p in (root / folder).rglob('*') if p.is_file() and
                     p.suffix.casefold() in SUFFIXES and '__pycache__' not in p.parts)
    files = {}
    for path in sorted(set(paths)):
        if path.is_symlink() or not path.resolve().is_relative_to(root):
            raise ValueError('Symlink/outside export input')
        name = path.relative_to(root).as_posix()
        data = path.read_bytes()
        errors = check_file(name, data)
        if errors:
            raise ValueError('\n'.join(errors))
        files[name] = data
    return files


def export(files, destination=OUTPUT):
    destination = Path(destination).resolve()
    if destination != OUTPUT.resolve():
        raise ValueError('Export must stay at build/github-ready')
    # Preflight before any mutation. Existing Git metadata is never touched.
    for name, data in files.items():
        if check_file(name, data):
            raise ValueError('Unsafe publication file: ' + name)
        target = (destination / name).resolve()
        if not target.is_relative_to(destination):
            raise ValueError('Outside export')
        if target.exists() and target.read_bytes() != data:
            raise ValueError('Existing export differs: ' + name + '; review changes manually')
    if destination.exists():
        for target in destination.rglob('*'):
            name = target.relative_to(destination).as_posix()
            if target.is_symlink():
                raise ValueError('Unexpected symlink in export')
            if target.is_file() and not name.startswith('.git/') and name not in files:
                # Local dependencies/test output may exist after validation, but
                # they must not be silently swept into a fresh publication copy.
                raise ValueError('Unexpected file in existing export: ' + name)
    for name, data in files.items():
        target = destination / name
        target.parent.mkdir(parents=True, exist_ok=True)
        if not target.exists():
            target.write_bytes(data)
    return destination


if __name__ == '__main__':
    files = publication_files()
    output = export(files)
    manifest = {name: hashlib.sha256(data).hexdigest() for name, data in files.items()}
    (ROOT / 'build/github-ready-manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print(json.dumps(dict(output=str(output), files=len(files), includes_history=False, remote_configured=False), indent=2))
