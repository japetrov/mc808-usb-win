"""Opt-in experimental PE serialization. No signing, installation or driver load.

The design remains unapproved for deployment. Explicit flags permit only an
offline research artifact with recorded INIT/NX assumptions and a comparison.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import pefile
from control_flow import discover
from nx_manifest import manifest,validate_actions
from reviewed_regions import SHA256


ROOT = Path(__file__).resolve().parents[1]
OUTPUT_ROOT = ROOT/'build/experimental'


def digest(design):
    return hashlib.sha256(json.dumps(design,sort_keys=True,separators=(',',':')).encode()).hexdigest()


def serialize_experimental(original,design,*,experimental=False,accept_init=False,accept_nx=False):
    if not (experimental and accept_init and accept_nx):
        raise ValueError('Research serialization requires explicit experimental, conditional INIT and unproven NX-use acknowledgments')
    if hashlib.sha256(original).hexdigest()!=SHA256 or design['sha256']!=SHA256:
        raise ValueError('Original identity differs')
    validate_actions(original,design['actions'],design['proposed_unsigned_file_size'])
    output = bytearray(design['proposed_unsigned_file_size'])
    covered = set()
    source_covered = set()
    for c in design['copies']:
        source,target,size = c['source_file_offset'],c['target_file_offset'],c['size']
        if c['zero_extension']<0 or source<0 or target<0 or source+size>len(original) or target+size+c['zero_extension']>len(output):
            raise ValueError('Invalid source copy span')
        raw_range = set(range(source,source+size))
        new_range = set(range(target,target+size+c['zero_extension']))
        if raw_range & source_covered or new_range & covered:
            raise ValueError('Overlapping baseline copy spans')
        source_covered.update(raw_range)
        covered.update(new_range)
        output[target:target+size] = original[source:source+size]
    if source_covered!=set(range(len(original))) or covered!=set(range(len(output))):
        raise ValueError('Baseline copy policy drops source/output bytes')
    for a in design['actions']:
        target = a['target_file_offset']
        new = bytes.fromhex(a['new_bytes'])
        expected = bytes.fromhex(a['old_bytes']) if a['source_file_offset'] is not None else b'\0'*len(new)
        if output[target:target+len(new)]!=expected:
            raise ValueError('Action baseline bytes differ from declared source/zero extension')
        output[target:target+len(new)] = new
    old = pefile.PE(data=original,fast_load=True)
    checksum_offset = old.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
    if any(a['target_file_offset']<checksum_offset+4 and checksum_offset<a['target_file_offset']+len(bytes.fromhex(a['new_bytes'])) for a in design['actions']):
        raise ValueError('Manifest unexpectedly patches deferred checksum')
    struct.pack_into('<I',output,checksum_offset,0)
    checksum = pefile.PE(data=bytes(output),fast_load=True).generate_checksum()
    struct.pack_into('<I',output,checksum_offset,checksum)
    return bytes(output),dict(kind='final_pe_checksum',file_offset=checksum_offset,
                              old_value=old.OPTIONAL_HEADER.CheckSum,new_value=checksum)


def guarded_write(path,original_path,candidate):
    target = path.resolve()
    if not target.is_relative_to(OUTPUT_ROOT.resolve()) or target.suffix.lower()!='.sys':
        raise ValueError('Candidate SYS output must stay under build/experimental')
    if target==original_path.resolve() or (target.exists() and target.samefile(original_path)):
        raise ValueError('Refusing original-file alias')
    target.parent.mkdir(parents=True,exist_ok=True)
    if target.exists():
        if target.read_bytes()!=candidate:
            raise ValueError('Existing candidate differs; choose a new filename rather than overwrite it')
        return False
    with target.open('xb') as f:
        f.write(candidate)
    if target.read_bytes()!=candidate:
        raise RuntimeError('Candidate write verification failed')
    return True


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--experimental',action='store_true')
    p.add_argument('--accept-conditional-init',action='store_true')
    p.add_argument('--accept-unproven-nx-use',action='store_true')
    p.add_argument('--output',type=Path,default=OUTPUT_ROOT/'RDWM1064.experimental.sys')
    args = p.parse_args()
    if not (args.experimental and args.accept_conditional_init and args.accept_unproven_nx_use):
        p.error('All three experimental acknowledgments are required; no deployment approval is implied')
    source = ROOT/'Files/64bit/Files/RDWM1064.SYS'
    before = source.read_bytes()
    design = manifest(before,discover(before))
    # Fresh assembly comparison is mandatory for this artifact, not a stale JSON flag.
    from verify_native_shims import build
    native = build(ROOT/'.tools/uasm-2.57/uasm64.exe')
    if not native['match'] or native['manifest_sha256']!=digest(design):
        raise ValueError('Native source verification is not bound to current manifest')
    candidate,checksum = serialize_experimental(before,design,experimental=True,accept_init=True,accept_nx=True)
    from compare_candidate import compare
    comparison = compare(before,candidate,design)
    if source.read_bytes()!=before:
        raise RuntimeError('Original changed before output; refusing emission')
    created = guarded_write(args.output,source,candidate)
    target = args.output.resolve()
    evidence = dict(artifact_kind='unsigned_experimental_research_candidate',deployment_approved=False,
        hvci_compatibility_proven=False,driver_loaded=False,signed=False,
        original_sha256=SHA256,candidate_sha256=hashlib.sha256(candidate).hexdigest(),
        candidate_size=len(candidate),manifest_sha256=digest(design),checksum=checksum,
        acknowledged_conditions=['Conditional INIT RX permission','Unproven NX use and lifetime assumptions'],
        remaining_conditions=design['blockers'],native_source_verification=native,comparison=comparison)
    target.with_suffix('.manifest.json').write_text(json.dumps(design,indent=2),encoding='utf-8')
    target.with_suffix('.verification.json').write_text(json.dumps(evidence,indent=2),encoding='utf-8')
    target.with_suffix('.RESEARCH.txt').write_text(
        'UNSIGNED EXPERIMENTAL RESEARCH CANDIDATE\nNot approved for installation or deployment.\n'
        'HVCI compatibility and full driver behavior are unproven.\n'
        'INIT RX and NX buffer-use assumptions remain conditional.\n'
        'No driver was signed, installed or loaded by these tools.\n',encoding='utf-8')
    if source.read_bytes()!=before:
        raise RuntimeError('Original changed during output')
    print(json.dumps(dict(output=str(target),created=created,candidate_sha256=evidence['candidate_sha256'],
                          size=len(candidate),comparison_passed=True,deployment_approved=False),indent=2))


if __name__=='__main__':
    main()
