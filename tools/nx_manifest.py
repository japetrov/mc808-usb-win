"""Combine the reviewed layout/metadata with a conditional minimum NX design.

Writes a JSON manifest of proposed byte fragments; NEVER writes a PE/SYS file.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path
import struct

import capstone
import pefile
from control_flow import discover
from layout_preview import preview
from metadata_plan import Layout,plan
from reviewed_regions import SHA256
from semantic_review import review


APPEND_SIZE = 32


def shim_bytes(stub_rva,iat_rva):
    # TEST ECX,ECX; JNE +5; MOV ECX,200h; JMP [RIP+disp32]; INT3 pad.
    disp = iat_rva-(stub_rva+15)
    if not -(1<<31)<=disp<1<<31:
        raise ValueError('Shim IAT displacement overflow')
    return bytes.fromhex('85c97505b900020000ff25')+struct.pack('<i',disp)+b'\xcc'


def validate_actions(data,actions,output_size):
    occupied = set()
    for a in actions:
        new = bytes.fromhex(a['new_bytes'])
        if not new or a['target_file_offset']<0 or a['target_file_offset']+len(new)>output_size:
            raise ValueError('Action outside planned output')
        positions = set(range(a['target_file_offset'],a['target_file_offset']+len(new)))
        if occupied & positions:
            raise ValueError('Overlapping manifest actions')
        occupied.update(positions)
        if a['source_file_offset'] is not None:
            old = bytes.fromhex(a['old_bytes'])
            if data[a['source_file_offset']:a['source_file_offset']+len(old)]!=old or len(old)!=len(new):
                raise ValueError('Expected original action bytes do not match')


def manifest(data,flow):
    if hashlib.sha256(data).hexdigest()!=SHA256 or flow['sha256']!=SHA256:
        raise ValueError('NX design requires the reviewed original')
    p = pefile.PE(data=data)
    operands = preview(data,flow,text_append_size=APPEND_SIZE)
    if operands['displacement_overflows']:
        raise ValueError('Reserved-code layout has displacement overflows')
    metadata = plan(data,flow,text_append_size=APPEND_SIZE)
    layout = Layout(p,metadata['layout'])
    sem = review(data,flow)
    ins = {i['rva']:i for i in flow['instructions']}
    imports = {i.name.decode():i.address-p.OPTIONAL_HEADER.ImageBase for d in p.DIRECTORY_ENTRY_IMPORT for i in d.imports if i.name}
    text = next(r for r in layout.regions if r['name']=='.text')
    stub_start = text['new_begin']+text['append_offset']
    shims = []
    for n,name in enumerate(('ExAllocatePool','ExAllocatePoolWithTag')):
        rva = stub_start+16*n
        encoded = shim_bytes(rva,layout.rva(imports[name]))
        md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
        decoded = [dict(rva=i.address,bytes=bytes(i.bytes).hex(),mnemonic=i.mnemonic,operands=i.op_str)
                   for i in md.disasm(encoded,rva)]
        if [i['mnemonic'] for i in decoded]!=['test','jne','mov','jmp','int3']:
            raise ValueError('Unexpected shim decode')
        shims.append(dict(api=name,rva=rva,old_iat_rva=imports[name],iat_rva=layout.rva(imports[name]),
                          file_offset=text['new_raw_offset']+text['append_offset']+16*n,
                          bytes=encoded.hex(),instructions=decoded,
                          unwind_kind='leaf_tail_jump_no_stack_or_nonvolatile_changes'))
    actions,redirects,skipped = [],[],[]
    selected = []
    for a in sem['allocation_sites']:
        if a['pool'].get('value')==1:
            skipped.append(dict(source_rva=a['rva'],reason='Original PagedPool request retained.'))
            continue
        selected.append(a)
    replace_sites = set()
    for a in selected:
        at = a['rva']
        i = ins[at]
        if i['size']!=6 or not bytes.fromhex(i['bytes']).startswith(b'\xff\x15'):
            raise ValueError('Unreviewed allocation call encoding')
        if any(at<s['rva']<at+6 for s in flow['seeds']):
            raise ValueError('Known target inside rewritten call')
        f = next(e for e in p.DIRECTORY_ENTRY_EXCEPTION if e.struct.BeginAddress<=at<e.struct.EndAddress)
        if at<f.struct.BeginAddress+f.unwindinfo.SizeOfProlog:
            raise ValueError('Allocation call is inside prologue; reject replacement')
        shim = next(s for s in shims if s['api']==a['import_name'])
        new_at = layout.rva(at)
        disp = shim['rva']-(new_at+5)
        if not -(1<<31)<=disp<1<<31:
            raise ValueError('Redirect displacement overflow')
        encoded = b'\xe8'+struct.pack('<i',disp)+b'\x90'
        reason = 'Replace 6-byte indirect call with 5-byte CALL plus NOP; route through leaf NX shim without changing enclosing function size.'
        actions.append(dict(kind='nx_call_redirect',source_rva=at,source_file_offset=p.get_offset_from_rva(at),
                            target_rva=new_at,target_file_offset=layout.new_file(at),old_bytes=i['bytes'],
                            new_bytes=encoded.hex(),reason=reason,conditional=True))
        redirects.append(dict(source_rva=at,new_rva=new_at,api=a['import_name'],shim_rva=shim['rva'],
                              old_return_rva=at+6,new_return_rva=new_at+5,resume_rva=new_at+6,
                              pool_evidence=a['pool'],status='proposed_pending_buffer_use_and_permission_review'))
        replace_sites.add(at+i['displacement_offset'])
    removed = []
    for f in operands['fixups']:
        if f['site'] in replace_sites:
            if f['kind']!='rip_displacement':
                raise ValueError('Redirect would hide unrelated fixup')
            removed.append(f)
            continue
        if not f['changes']:
            continue
        signed = f['kind'] in ('rip_displacement','relative_control_transfer')
        actions.append(dict(kind=f['kind'],source_rva=f['site'],source_file_offset=p.get_offset_from_rva(f['site']),
                            target_rva=f['new_site'],target_file_offset=layout.new_file(f['site']),
                            old_bytes=p.get_data(f['site'],f['width']).hex(),
                            new_bytes=f['new_value'].to_bytes(f['width'],'little',signed=signed).hex(),
                            reason='Translate reviewed operand/pointer target under the reserved-code layout.',conditional=False))
    if len(removed)!=len(redirects):
        raise ValueError('Not every redirect supersedes exactly one IAT displacement patch')
    for f in metadata['fields']:
        if f['changes']:
            actions.append(dict(kind=f['kind'],source_rva=f['old_site_rva'],source_file_offset=f['old_file_offset'],
                                target_rva=f['new_site_rva'],target_file_offset=f['new_file_offset'],
                                old_bytes=f['old_value'].to_bytes(f['width'],'little').hex(),
                                new_bytes=f['new_value'].to_bytes(f['width'],'little').hex(),
                                reason=f['reason'],conditional=f['conditional']))
    rebuilt = metadata['relocation_rebuild']
    fragment = b''.join(struct.pack('<II',b['page_rva'],b['size'])+
                        struct.pack('<'+'H'*len(b['entries']),*b['entries']) for b in rebuilt['blocks'])
    actions.append(dict(kind='relocation_directory_rebuild',source_rva=rebuilt['old_directory_rva'],
                        source_file_offset=p.get_offset_from_rva(rebuilt['old_directory_rva']),
                        target_rva=rebuilt['new_directory_rva'],target_file_offset=layout.new_file(rebuilt['old_directory_rva']),
                        old_bytes=p.get_data(rebuilt['old_directory_rva'],len(fragment)).hex(),
                        new_bytes=fragment.hex(),reason=rebuilt['reason'],conditional=False))
    for shim in shims:
        actions.append(dict(kind='appended_nx_shim',source_rva=None,source_file_offset=None,
                            target_rva=shim['rva'],target_file_offset=shim['file_offset'],old_bytes=None,
                            new_bytes=shim['bytes'],reason='New leaf tail-call shim in appended RX text bytes; original bytes are retained.',conditional=True))
    actions.sort(key=lambda a:a['target_file_offset'])
    validate_actions(data,actions,metadata['proposed_unsigned_file_size'])
    modified = {b for a in actions for b in range(a['target_file_offset'],a['target_file_offset']+len(bytes.fromhex(a['new_bytes'])))}
    for blob in metadata['preserved_blobs']:
        start = layout.new_file(blob['old_rva'])
        if modified & set(range(start,start+blob['size'])):
            raise ValueError('Manifest changes a declared preserved metadata blob')
    copies = [dict(kind='headers',source_file_offset=0,target_file_offset=0,size=p.OPTIONAL_HEADER.SizeOfHeaders,
                   zero_extension=metadata['header_values']['SizeOfHeaders']-p.OPTIONAL_HEADER.SizeOfHeaders)]
    for s,r in zip(p.sections,layout.regions):
        copies.append(dict(kind=r['name'],source_file_offset=s.PointerToRawData,
                           target_file_offset=r['new_raw_offset'],size=s.SizeOfRawData,
                           zero_extension=r['new_raw_size']-s.SizeOfRawData))
    source_end,target_end = 0,0
    for c in copies:
        if c['source_file_offset']!=source_end or c['target_file_offset']!=target_end:
            raise ValueError('Copy policy leaves unexplained source or output gaps')
        source_end += c['size']
        target_end += c['size']+c['zero_extension']
    if source_end!=len(data) or target_end!=metadata['proposed_unsigned_file_size']:
        raise ValueError('Copy plan does not cover the full original and proposed raw layout')
    return dict(sha256=SHA256,emission_allowed=False,layout=metadata['layout'],
                header_values=metadata['header_values'],
                proposed_unsigned_file_size=metadata['proposed_unsigned_file_size'],
                copy_policy=metadata['copy_policy'],copies=copies,actions=actions,shims=shims,
                redirects=redirects,skipped_allocations=skipped,superseded_fixups=removed,
                preserved_blobs=metadata['preserved_blobs'],runtime_functions=metadata['runtime_functions'],
                deferred=metadata['deferred'],
                blockers=['INIT write removal remains conditional on the affected-write/alias review.',
                          'Buffer execution/lifetime review and nonzero dynamic pool modifiers remain unresolved.',
                          'Native assembly evidence must match this exact source and manifest.',
                          'Candidate bytes require full old/new comparison; Windows loader and HVCI tests remain manual.'],
                summary=dict(actions=len(actions),redirects=len(redirects),appended_code_bytes=APPEND_SIZE,
                             superseded_iat_fixups=len(removed),raw_file_size=metadata['proposed_unsigned_file_size'],
                             kinds=dict(Counter(a['kind'] for a in actions))))


if __name__=='__main__':
    source = Path('Files/64bit/Files/RDWM1064.SYS')
    before = source.read_bytes()
    result = manifest(before,discover(before))
    Path('reports/reconstruction-manifest.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    if source.read_bytes()!=before:
        raise RuntimeError('Original changed during manifest generation')
    print(json.dumps(result['summary'],indent=2))
