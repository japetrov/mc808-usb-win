"""Hash-bound INIT address/write evidence and unchanged object displacement map.

Absence of direct references is evidence, not a proof against indirect aliases.
"""
from collections import Counter
import hashlib
import json
from pathlib import Path

import pefile
from control_flow import discover
from frame_map import frames
from reviewed_regions import SHA256
from trace_calls import trace


OBJECT_OFFSETS = [
    (0x3a1e,0x3a19,0x3a15,0x500,0x28,1),
    (0x3e25,0x3e1d,0x3e19,0xa0c0,0x18,2),
    (0x3f90,0x3f88,0x3f84,0x570,0x28,1),
    (0x4fcd,0x4fc5,0x4fc1,0xa0c0,0x18,1),
    (0x507a,0x5072,0x506e,0xa0c0,0x18,1),
    (0x8133,0x812e,0x812a,0xa078,0x38,1),
]


def review(data,flow):
    if hashlib.sha256(data).hexdigest()!=SHA256 or flow['sha256']!=SHA256:
        raise ValueError('Permission review requires original identity')
    p = pefile.PE(data=data)
    ins = {i['rva']:i for i in flow['instructions']}
    frame_rows = frames(flow)
    object_rows = []
    for at,load_at,mul_at,offset,stride,arg in OBJECT_OFFSETS:
        lea,load,mul = ins[at],ins[load_at],ins[mul_at]
        f = next(f for f in frame_rows if f['function']['begin']<=at<f['function']['end'])
        if (lea['mnemonic']!='lea' or lea['operands'][1].get('base')!='rax'
                or lea['operands'][1].get('index')!='rcx' or lea['operands'][1].get('displacement')!=offset):
            raise ValueError('Object displacement pattern changed')
        if (load['mnemonic']!='mov' or load['operands'][0].get('register')!='rax'
                or load['operands'][1].get('base')!='rsp'):
            raise ValueError('Object base load changed')
        normalized = f['heights'][load_at]+load['operands'][1]['displacement']
        if normalized!=arg*8 or not any(h['argument']==arg and h['width']==8 for h in f['argument_home_origins']):
            raise ValueError('Object base is not the reviewed argument home')
        if mul['mnemonic']!='imul' or mul['operands'][0].get('register')!='rcx' or mul['operands'][-1].get('value')!=stride:
            raise ValueError('Object stride changed')
        if mul_at+mul['size']!=load_at or load_at+load['size']!=at:
            raise ValueError('Unexpected intervening object-base/index instructions')
        object_rows.append(dict(source=at,function=f['function']['begin'],argument_home_origin=arg,
                                base_load=load_at,scale_instruction=mul_at,offset=offset,stride=stride,
                                treatment='retain_object_layout_offset_not_an_encoded_image_RVA',
                                condition='Incoming object layout and saved argument home retain their reviewed meaning.'))
    image_base_refs = {r['source'] for r in flow['references'] if r['target']==0}
    switch_base_refs = {s['jump']-(25 if s['selector'] is not None else 17) for s in flow['reviewed_switches']}
    if image_base_refs!=switch_base_refs:
        raise ValueError('Unaccounted explicit image-base construction')
    immediate = flow['immediate_address_candidates']
    if len(immediate)!=1 or immediate[0]['source']!=0xce32 or immediate[0]['value']!=0x20019:
        raise ValueError('Unreviewed immediate in image-address numeric range')
    io_call = next(c for c in flow['indirect_transfers'] if c['source']==0xce45)
    if io_call['imported']['name']!='IoOpenDeviceRegistryKey':
        raise ValueError('Registry desired-access classification changed')
    if ins[0xce32]['operands'][0].get('register')!='r8d' or any(
            'r8' in i['registers_written'] or 'r8d' in i['registers_written']
            for i in flow['instructions'] if 0xce32<i['rva']<0xce45):
        raise ValueError('Registry access argument was overwritten')
    traced = trace(data,flow)
    counts = Counter()
    concrete = []
    executable_writes = []
    for w in traced['memory_writes']:
        origin = w['address'][0]
        kind = 'stack_relative' if origin=='stack_address' else 'image_relative' if origin=='image_rva' else 'unresolved_object_or_alias'
        counts[kind] += 1
        if origin=='image_rva':
            target = w['address'][1]
            section = p.get_section_by_rva(target)
            row = dict(**w,target_rva=target,target_section=section.Name.rstrip(b'\0').decode() if section else None)
            concrete.append(row)
            end_section = p.get_section_by_rva(target+w['operand_width']-1)
            if any(s and s.Characteristics & 0x20000000 for s in (section,end_section)):
                executable_writes.append(row)
    init = next(s for s in p.sections if s.Name.rstrip(b'\0')==b'INIT')
    begin,end = init.VirtualAddress,init.VirtualAddress+init.Misc_VirtualSize
    return dict(sha256=SHA256,init_range=dict(begin=begin,end=end),
                init_absolute_pointer_targets=[r for r in flow['absolute_pointers'] if begin<=r['target']<end],
                init_relocation_sites=[e.rva for b in p.DIRECTORY_ENTRY_BASERELOC for e in b.entries if begin<=e.rva<end],
                init_rip_data_references=[r for r in flow['references'] if begin<=r['target']<end],
                known_executable_image_writes=executable_writes,concrete_image_writes=concrete,
                explicit_memory_writes=dict(counts),object_displacements=object_rows,
                image_base_uses=[dict(source=s,treatment='reviewed_switch_base') for s in sorted(image_base_refs)],
                scalar_immediate=dict(source=0xce32,value=0x20019,treatment='registry_desired_access_not_pointer'),
                conclusion='No discovered direct INIT data address or concrete executable image write; indirect aliases remain unproven.',
                emission_allowed=False,
                limits=['Only discovered code and Capstone explicit memory-write operands are covered.',
                        'Block-local symbolic expressions do not prove the destination of unresolved object/alias stores.',
                        'Known image-relative repetition spans require additional count/range interpretation.',
                        'Incoming home origins name parameters; they do not prove global lifetime or immutability.'])


if __name__=='__main__':
    path = Path('Files/64bit/Files/RDWM1064.SYS')
    data = path.read_bytes()
    result = review(data,discover(data))
    Path('reports/permission-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    if path.read_bytes()!=data:
        raise RuntimeError('Original changed during review')
    print(json.dumps(dict(writes=result['explicit_memory_writes'],executable_writes=len(result['known_executable_image_writes']),
                         object_displacements=len(result['object_displacements']),emission_allowed=False),indent=2))
