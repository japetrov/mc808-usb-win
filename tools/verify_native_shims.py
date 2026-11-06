"""Assemble the reviewed shim source and verify AMD64 COFF against the manifest.

Produces only a COFF object in ignored build/, never a PE/SYS or Windows load.
"""
import argparse
import hashlib
import json
from pathlib import Path
import struct
import subprocess

from control_flow import discover
from nx_manifest import manifest


ROOT = Path(__file__).resolve().parents[1]


def coff(raw):
    def unpack(fmt,offset):
        if offset<0 or offset+struct.calcsize(fmt)>len(raw):
            raise ValueError('Truncated COFF structure')
        return struct.unpack_from(fmt,raw,offset)
    machine,count,timestamp,symptr,symcount,optional,flags = unpack('<HHIIIHH',0)
    if machine!=0x8664 or optional or count>32:
        raise ValueError('Expected small AMD64 COFF object')
    strings = symptr+18*symcount
    length, = unpack('<I',strings)
    if length<4 or strings+length>len(raw):
        raise ValueError('Invalid COFF string table')
    def name(encoded):
        if encoded[:4]==b'\0'*4:
            offset = int.from_bytes(encoded[4:],'little')
            if not 4<=offset<length:
                raise ValueError('Invalid long COFF symbol name')
            end = raw.find(b'\0',strings+offset,strings+length)
            if end<0:
                raise ValueError('Unterminated COFF symbol')
            return raw[strings+offset:end].decode('ascii')
        return encoded.rstrip(b'\0').decode('ascii')
    symbols,index = {},0
    while index<symcount:
        n,value,section,typ,storage,aux = unpack('<8sIhHBB',symptr+index*18)
        if index+aux>=symcount:
            raise ValueError('COFF auxiliary symbol overruns table')
        symbols[index] = dict(name=name(n),value=value,section=section,type=typ,storage=storage)
        index += aux+1
    sections = []
    for n in range(count):
        row = unpack('<8sIIIIIIHHI',20+n*40)
        encoded,vs,va,size,ptr,relptr,lineptr,relcount,linecount,characteristics = row
        if ptr+size>len(raw) or relptr+relcount*10>len(raw) or linecount:
            raise ValueError('Invalid COFF section bounds')
        relocations = []
        for i in range(relcount):
            offset,symbol,typ = unpack('<IIH',relptr+10*i)
            if symbol not in symbols:
                raise ValueError('Relocation references auxiliary/missing symbol')
            relocations.append(dict(offset=offset,type=typ,symbol=symbols[symbol]))
        sections.append(dict(name=encoded.rstrip(b'\0').decode(),bytes=raw[ptr:ptr+size].hex(),
                             characteristics=characteristics,relocations=relocations))
    return dict(timestamp=timestamp,sections=sections,symbols=list(symbols.values()))


def verify_object(raw,design):
    parsed = coff(raw)
    code_sections = [s for s in parsed['sections'] if s['name']=='.text']
    if len(code_sections)!=1:
        raise ValueError('Expected one text section')
    text = code_sections[0]
    if any(s['bytes'] for s in parsed['sections'] if s['name']!='.text'):
        raise ValueError('Unexpected non-text object payload')
    if text['characteristics'] & 0x80000000 or not text['characteristics'] & 0x20000000:
        raise ValueError('Object text permissions are not RX')
    if len(bytes.fromhex(text['bytes']))!=32 or len(text['relocations'])!=2:
        raise ValueError('Unexpected shim code size/relocation count')
    linked = bytearray.fromhex(text['bytes'])
    base = design['shims'][0]['rva']
    externals = {'__imp_'+s['api']:s['iat_rva'] for s in design['shims']}
    seen = set()
    for r in text['relocations']:
        symbol = r['symbol']
        if r['type']!=4 or symbol['section']!=0 or symbol['value']!=0 or symbol['name'] not in externals:
            raise ValueError('Unexpected AMD64 REL32 symbol/fixup')
        offset = r['offset']
        if offset not in (11,27) or offset in seen:
            raise ValueError('Unexpected shim relocation offset')
        seen.add(offset)
        addend = struct.unpack_from('<i',linked,offset)[0]
        displacement = externals[symbol['name']]+addend-(base+offset+4)
        struct.pack_into('<i',linked,offset,displacement)
    expected = b''.join(bytes.fromhex(s['bytes']) for s in design['shims'])
    if bytes(linked)!=expected:
        raise ValueError('Native source code differs from the emulated manifest bytes')
    for name,value in [('MC808_NxExAllocatePool',0),('MC808_NxExAllocatePoolWithTag',16)]:
        matches = [s for s in parsed['symbols'] if s['name']==name]
        if len(matches)!=1 or matches[0]['section']!=1 or matches[0]['value']!=value:
            raise ValueError('Native public symbol layout differs')
    return dict(code_bytes=32,relocations=2,object_sha256=hashlib.sha256(raw).hexdigest(),
                object_text_sha256=hashlib.sha256(bytes.fromhex(text['bytes'])).hexdigest(),
                linked_text_sha256=hashlib.sha256(linked).hexdigest(),linked_bytes=bytes(linked).hex(),
                sections=[s['name'] for s in parsed['sections']],match=True)


def build(assembler, *, output=None):
    pin = json.loads((ROOT/'toolchains/uasm-2.57.json').read_text())
    if hashlib.sha256(assembler.read_bytes()).hexdigest()!=pin['executable_sha256']:
        raise ValueError('Assembler fingerprint differs from the pinned portable tool')
    source = ROOT/'asm/reconstruction/nx_pool_shims.asm'
    before = (ROOT/'Files/64bit/Files/RDWM1064.SYS').read_bytes()
    design = manifest(before,discover(before))
    output = output or ROOT/'build/native/nx_pool_shims.obj'
    output.parent.mkdir(parents=True,exist_ok=True)
    command = [str(assembler.resolve()),'-win64','-Fo',str(output),str(source)]
    result = subprocess.run(command,cwd=ROOT,check=True,capture_output=True,text=True)
    review = verify_object(output.read_bytes(),design)
    review.update(tool='UASM 2.57',assembler_sha256=pin['executable_sha256'],
                  source_sha256=hashlib.sha256(source.read_bytes()).hexdigest(),
                  original_sha256=design['sha256'],
                  manifest_sha256=hashlib.sha256(json.dumps(design,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                  assembler_output=result.stdout+result.stderr,driver_emitted=False)
    if (ROOT/'Files/64bit/Files/RDWM1064.SYS').read_bytes()!=before:
        raise RuntimeError('Original changed during native verification')
    return review


if __name__=='__main__':
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--assembler',type=Path,default=ROOT/'.tools/uasm-2.57/uasm64.exe')
    args = p.parse_args()
    result = build(args.assembler)
    (ROOT/'reports/native-shims.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps({k:result[k] for k in ('tool','code_bytes','relocations','match','linked_text_sha256')},indent=2))
