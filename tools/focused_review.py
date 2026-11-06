"""Repeatable evidence extracts; no claim of complete control/data flow analysis."""
import json
import hashlib
from pathlib import Path
from capstone import Cs, CS_ARCH_X86, CS_MODE_64
import pefile


def review(path):
    if hashlib.sha256(Path(path).read_bytes()).hexdigest() != '984f00a9ffe11380e63392e7d7f6e3e5f70aa178a9764d47fc790a2170aaf084':
        raise ValueError('Focused bounds are valid only for the reviewed original SHA-256')
    p = pefile.PE(str(path))
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    base = p.OPTIONAL_HEADER.ImageBase
    def dis(start, end):
        return [dict(rva=i.address-base, text=i.mnemonic+' '+i.op_str)
                for i in md.disasm(p.get_data(start,end-start),base+start)]
    # These are manually reviewed bounds for this exact driver, not inferred functions.
    out = dict(init_code=dis(0x13088,0x130dd)+dis(0x130e4,0x13102),
               exception_handler=dis(0xfde4,0xfe01), pool_call_contexts=[])
    targets = {s.address-base:s.name.decode() for d in p.DIRECTORY_ENTRY_IMPORT
               for s in d.imports if s.name and b'AllocatePool' in s.name}
    r = json.loads(Path('reports/original-pe.json').read_text())
    for ref in r['references']:
        if ref['target_rva'] in targets and ref['instruction'].startswith(('call ', 'jmp ')):
            at = ref['source_rva']
            # Align context to a known runtime-function start where possible.
            begin = next((e.struct.BeginAddress for e in p.DIRECTORY_ENTRY_EXCEPTION
                          if e.struct.BeginAddress <= at < e.struct.EndAddress), at)
            out['pool_call_contexts'].append(dict(import_name=targets[ref['target_rva']],
                                                  call_rva=at, context=dis(begin,at+6)))
    return out


if __name__ == '__main__':
    result = review(Path('Files/64bit/Files/RDWM1064.SYS'))
    Path('reports/focused-review.json').write_text(json.dumps(result,indent=2))
    print('Pool call sites:',len(result['pool_call_contexts']))
    for c in result['pool_call_contexts']:
        print(c['import_name'],hex(c['call_rva']),c['context'][-8:])
