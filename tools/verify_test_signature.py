"""Verify offline cryptography and exact unsigned-to-signed byte preservation.

This is NOT Windows trust, kernel signing-policy or HVCI validation.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct

import lief
import pefile
from prepare_test_package import CANDIDATE_HASH, ROOT


def preserved_payload(unsigned, signed):
    if hashlib.sha256(unsigned).hexdigest() != CANDIDATE_HASH:
        raise ValueError('Unreviewed unsigned candidate')
    old = pefile.PE(data=unsigned, fast_load=True)
    new = pefile.PE(data=signed, fast_load=True)
    directory = new.OPTIONAL_HEADER.DATA_DIRECTORY[4]
    offset, size = directory.VirtualAddress, directory.Size
    if offset != len(unsigned) or size < 8 or offset + size != len(signed):
        raise ValueError('Signature must be the sole appended data')
    length, revision, kind = struct.unpack_from('<IHH', signed, offset)
    if revision != 0x200 or kind != 2 or length < 8 or ((length + 7) & ~7) != size:
        raise ValueError('Unexpected WIN_CERTIFICATE layout')
    if any(signed[offset + length:]):
        raise ValueError('Nonzero certificate alignment padding')
    copy = bytearray(signed[:offset])
    spans = [(old.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum'), 4),
             (old.OPTIONAL_HEADER.DATA_DIRECTORY[4].get_file_offset(), 8)]
    for start, count in spans:
        copy[start:start + count] = unsigned[start:start + count]
    if bytes(copy) != unsigned:
        raise ValueError('Signing changed bytes beyond checksum/security directory')
    if new.OPTIONAL_HEADER.CheckSum != new.generate_checksum():
        raise ValueError('Signed checksum mismatch')
    return dict(appended_certificate_offset=offset, appended_certificate_size=size,
                permitted_header_spans=[dict(offset=a, size=b) for a, b in spans])


def verify(unsigned, signed, certificate):
    result = preserved_payload(unsigned, signed)
    binary = lief.PE.parse(bytes(signed))
    if binary is None or len(binary.signatures) != 1:
        raise ValueError('Expected exactly one embedded signature')
    signature = binary.signatures[0]
    if signature.digest_algorithm != lief.PE.ALGORITHMS.SHA_256:
        raise ValueError('Expected SHA256 signature digest')
    if len(signature.certificates) != 1 or len(signature.signers) != 1:
        raise ValueError('Unexpected signer/certificate count')
    if bytes(signature.certificates[0].raw) != certificate:
        raise ValueError('Embedded certificate differs from exported public certificate')
    status = binary.verify_signature()
    if status != lief.PE.Signature.VERIFICATION_FLAGS.OK:
        raise ValueError('Offline signature/content verification failed: ' + str(status))
    result.update(unsigned_sha256=hashlib.sha256(unsigned).hexdigest(),
                  signed_sha256=hashlib.sha256(signed).hexdigest(),
                  certificate_sha256=hashlib.sha256(certificate).hexdigest(),
                  offline_signature_valid=True, payload_preserved=True,
                  windows_trust_verified=False, kernel_policy_verified=False,
                  hvci_compatibility_proven=False, lief_version=lief.__version__)
    return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('signed', type=Path)
    parser.add_argument('certificate', type=Path)
    args = parser.parse_args()
    unsigned = (ROOT / 'build/experimental/RDWM1064.experimental.sys').read_bytes()
    print(json.dumps(verify(unsigned, args.signed.read_bytes(), args.certificate.read_bytes()), indent=2))
