"""Read-only AMD64 PE inventory. No binary writer or driver-loading operations."""
import argparse
import hashlib
import json
import struct
from pathlib import Path

import pefile
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
from capstone.x86 import X86_OP_MEM, X86_OP_IMM, X86_REG_RIP


def sha(data):
    return hashlib.sha256(data).hexdigest()


def fields(obj):
    return {k: v for k, v in vars(obj).items()
            if not k.startswith('_') and isinstance(v, (int, str, bytes))
            for v in [v.hex() if isinstance(v, bytes) else v]}


def analyze(path):
    data = Path(path).read_bytes()
    pe = pefile.PE(data=data, fast_load=False)
    if pe.FILE_HEADER.Machine != 0x8664 or pe.OPTIONAL_HEADER.Magic != 0x20b:
        raise ValueError('This analyzer requires AMD64 PE32+')
    base = pe.OPTIONAL_HEADER.ImageBase
    def owner(rva):
        s = pe.get_section_by_rva(rva)
        return s.Name.rstrip(b'\0').decode(errors='replace') if s else None
    sections = []
    for s in pe.sections:
        sections.append(dict(name=owner(s.VirtualAddress), headers=fields(s),
                             read=bool(s.Characteristics & 0x40000000),
                             write=bool(s.Characteristics & 0x80000000),
                             execute=bool(s.Characteristics & 0x20000000),
                             discardable=bool(s.Characteristics & 0x02000000),
                             raw_sha256=sha(s.get_data())))
    directories = [dict(index=i, name=d.name, address=d.VirtualAddress,
                        size=d.Size, address_kind='file_offset' if i == 4 else 'RVA',
                        section=None if i == 4 else owner(d.VirtualAddress))
                   for i, d in enumerate(pe.OPTIONAL_HEADER.DATA_DIRECTORY)]
    imports = []
    for attr in ('DIRECTORY_ENTRY_IMPORT', 'DIRECTORY_ENTRY_DELAY_IMPORT'):
        for dll in getattr(pe, attr, []):
            imports.append(dict(kind=attr, dll=dll.dll.decode(errors='replace'),
                                descriptor=fields(dll.struct), symbols=[dict(
                                    name=i.name.decode(errors='replace') if i.name else None,
                                    ordinal=i.ordinal, hint=i.hint, iat_rva=i.address-base)
                                    for i in dll.imports]))
    relocs = []
    for block in getattr(pe, 'DIRECTORY_ENTRY_BASERELOC', []):
        entries = []
        for e in block.entries:
            width = {10: 8, 3: 4}.get(e.type, 0)
            raw = pe.get_data(e.rva, width) if width else b''
            value = int.from_bytes(raw, 'little') if raw else None
            entries.append(dict(rva=e.rva, type=e.type, section=owner(e.rva),
                                width=width, value=value,
                                target_rva=value-base if value is not None and base <= value < base+pe.OPTIONAL_HEADER.SizeOfImage else None,
                                page_straddle=bool(width and e.rva % 4096+width > 4096)))
        relocs.append(dict(header=fields(block.struct), entries=entries))
    exceptions = []
    for e in getattr(pe, 'DIRECTORY_ENTRY_EXCEPTION', []):
        rva = e.struct.UnwindData
        head = pe.get_data(rva, 4)
        u = {}
        if len(head) == 4:
            verflags, prolog, count, frame = head
            tail = rva+4+((count+1)//2)*4
            flags = verflags >> 3
            u = dict(version=verflags & 7, flags=flags, prolog_size=prolog,
                     code_slots=count, frame_register=frame & 15, frame_offset=frame >> 4,
                     code_bytes=pe.get_data(rva+4, count*2).hex(), tail_rva=tail)
            if flags & 4:
                u['chained_runtime_function'] = list(struct.unpack('<III', pe.get_data(tail, 12)))
            elif flags & 3:
                u['handler_rva'] = struct.unpack('<I', pe.get_data(tail, 4))[0]
                u['language_specific_data_rva'] = tail+4
                u['language_specific_data_note'] = 'Handler-dependent format; not assumed to be generic RVAs.'
        exceptions.append(dict(runtime_function=fields(e.struct), unwind_rva=rva,
                               unwind=u, parsed=str(getattr(e, 'unwindinfo', ''))))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    references, gaps = [], []
    for s in pe.sections:
        if not s.Characteristics & 0x20000000:
            continue
        code = s.get_data()[:s.Misc_VirtualSize]
        pos = 0
        # Linear sweep is evidence collection, never a completeness proof.
        while pos < len(code):
            ins = next(md.disasm(code[pos:], base+s.VirtualAddress+pos, count=1), None)
            if ins is None:
                gaps.append(s.VirtualAddress+pos)
                pos += 1
                continue
            for op in ins.operands:
                target, kind = None, None
                if op.type == X86_OP_MEM and op.mem.base == X86_REG_RIP:
                    target, kind = ins.address+ins.size+op.mem.disp-base, 'rip_memory'
                elif op.type == X86_OP_IMM and base <= op.imm < base+pe.OPTIONAL_HEADER.SizeOfImage:
                    target, kind = op.imm-base, 'immediate_or_branch'
                if target is not None:
                    references.append(dict(source_rva=ins.address-base, source_section=owner(ins.address-base),
                                           instruction=ins.mnemonic+' '+ins.op_str, target_rva=target,
                                           target_section=owner(target), kind=kind,
                                           operand_access=op.access))
            pos += ins.size
    pages = {}
    for s in pe.sections:
        for p in range(s.VirtualAddress//4096, (s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData)+4095)//4096):
            pages.setdefault(p*4096, []).append(owner(s.VirtualAddress))
    report = dict(input=str(Path(path).resolve()), size=len(data), sha256=sha(data),
                  versions=dict(pefile=pefile.__version__),
                  headers=dict(dos=fields(pe.DOS_HEADER), nt=fields(pe.NT_HEADERS),
                               file=fields(pe.FILE_HEADER), optional=fields(pe.OPTIONAL_HEADER)),
                  full_pe_dump=pe.dump_info(), sections=sections, directories=directories,
                  imports=imports, relocations=relocs, exceptions=exceptions,
                  debug=[dict(header=fields(d.struct), payload=pe.get_data(d.struct.AddressOfRawData,d.struct.SizeOfData).hex()) for d in getattr(pe,'DIRECTORY_ENTRY_DEBUG',[])],
                  load_config=fields(pe.DIRECTORY_ENTRY_LOAD_CONFIG.struct) if hasattr(pe,'DIRECTORY_ENTRY_LOAD_CONFIG') else None,
                  shared_pages=[dict(rva=p,sections=s) for p,s in pages.items() if len(s)>1],
                  references=references, undecodable_rvas=gaps,
                  warnings=pe.get_warnings(), checksum=dict(stored=pe.OPTIONAL_HEADER.CheckSum, computed=pe.generate_checksum()),
                  limitations=['Linear disassembly may decode embedded data and miss indirect references.',
                               'Operand access describes the explicit operand, not callee side effects.',
                               'Runtime writes, computed pointers, pool flags and all handler-specific metadata require further review.'])
    if Path(path).read_bytes() != data:
        raise RuntimeError('Input changed during analysis')
    return report


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('input', type=Path)
    p.add_argument('--output', type=Path, required=True)
    a = p.parse_args()
    if (a.output.resolve() == a.input.resolve()
            or (a.output.exists() and a.output.samefile(a.input))
            or a.output.suffix.lower() != '.json'):
        p.error('Output must be a separate .json file')
    r = analyze(a.input)
    a.output.parent.mkdir(parents=True, exist_ok=True)
    a.output.write_text(json.dumps(r, indent=2), encoding='utf-8')
    print(json.dumps({k:r[k] for k in ('sha256','size','warnings')}, indent=2))


if __name__ == '__main__':
    main()
