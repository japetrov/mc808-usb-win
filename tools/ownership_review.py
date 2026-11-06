"""Hash-bound object table inventory and allocation/free-location evidence.

Location matches do not prove unique ownership, absence of aliases or NX safety.
"""
import hashlib
import json
from pathlib import Path

import pefile
from control_flow import discover, listing
from reviewed_regions import SHA256
from semantic_review import review
from trace_calls import trace


LIFETIME_LINKS = [
    (0xa2bb,0xa329,'image',0x122a0),
    (0xa5e0,0xa670,'stack',0x38),
    (0xc11e,0xc275,'stack',0x30),
    (0xc11e,0xc2ed,'stack',0x30),
    (0xc11e,0xc363,'stack',0x30),
    (0xc4ca,0xc698,'stack',0x60),
]


def inventory(data,flow):
    if hashlib.sha256(data).hexdigest()!=SHA256 or flow['sha256']!=SHA256:
        raise ValueError('Ownership evidence is hash-bound')
    p = pefile.PE(data=data)
    ins = {i['rva']:i for i in flow['instructions']}
    ordered = flow['instructions']
    pointers = {x['site']:x['target'] for x in flow['absolute_pointers'] if x['executable_target']}
    calls = {c['source']:c for c in trace(data,flow)['calls']}
    construction = []
    for i in ordered:
        ops = i['operands']
        if i['mnemonic']!='lea' or len(ops)!=2:
            continue
        target = ops[1].get('target_rva')
        if target not in pointers:
            continue
        following = ins.get(i['rva']+i['size'])
        if not following or following['mnemonic']!='mov':
            continue
        dst,src = following['operands']
        if dst['kind']=='memory' and src.get('register')==ops[0].get('register'):
            construction.append(dict(lea=i['rva'],store=following['rva'],table=target,
                                     object_address_operand=dst,
                                     classification='candidate_vtable_installation'))
    bases = sorted({x['table'] for x in construction})
    tables = []
    for base in bases:
        end = next((b for b in bases if b>base),None)
        slots = []
        at = base
        while at in pointers and (end is None or at<end):
            slots.append(dict(offset=at-base,pointer_site=at,target=pointers[at]))
            at += 8
        tables.append(dict(base=base,slots=slots,
                           extent_status='contiguous_relocated_code_pointer_prefix_not_proven_type_size'))
    semantic = review(data,flow)
    allocs = []
    for a in semantic['allocation_sites']:
        f = a['function']
        allocs.append(dict(site=a['rva'],function=f,pool=a['pool'],slice=calls[a['rva']],
                          direct_callers=[calls[c['source']] for c in a['direct_callers']],
                          same_function_free_sites=[dict(site=c['source'],slice=calls[c['source']])
                              for c in flow['indirect_transfers'] if c['imported']
                              and c['imported']['name'] in ('ExFreePool','ExFreePoolWithTag')
                              and f['begin']<=c['source']<f['end']],
                          nx_conversion_approved=False))
    free_imports = {c['source']:c['imported']['name'] for c in flow['indirect_transfers']
                    if c['imported'] and c['imported']['name'] in ('ExFreePool','ExFreePoolWithTag')}
    links = []
    for alloc,free,kind,offset in LIFETIME_LINKS:
        store = ins[alloc+ins[alloc]['size']]
        if store['mnemonic']!='mov' or store['operands'][1].get('register')!='rax':
            raise ValueError('Expected immediate allocation return store')
        dst = store['operands'][0]
        alloc_f = next(f for f in flow['runtime_functions'] if f['begin']<=alloc<f['end'])
        free_f = next(f for f in flow['runtime_functions'] if f['begin']<=free<f['end'])
        preceding = [i for i in ordered if free_f['begin']<=i['rva']<free]
        load = next(i for i in reversed(preceding) if 'rcx' in i['registers_written'])
        if free not in free_imports or load['mnemonic']!='mov' or load['operands'][0].get('register')!='rcx':
            raise ValueError('Expected free pointer load')
        src = load['operands'][1]
        if any(i['mnemonic'].startswith(('j','call','loop')) for i in preceding if load['rva']<i['rva']<free):
            raise ValueError('Free pointer load crosses a control transfer')
        if kind=='image':
            matches = dst.get('target_rva')==offset and src.get('target_rva')==offset
        else:
            matches = (alloc_f==free_f and dst.get('base')=='rsp' and src.get('base')=='rsp'
                       and dst.get('displacement')==offset and src.get('displacement')==offset)
            if any('rsp' in i['registers_written'] and i['mnemonic']!='call'
                   for i in ordered if alloc<i['rva']<=load['rva']):
                raise ValueError('Stack height changes between allocation and free evidence')
        if not matches or dst['size']!=8 or src['size']!=8:
            raise ValueError('Allocation and free do not use the reviewed location')
        links.append(dict(allocation=alloc,return_store=store['rva'],free=free,free_argument_load=load['rva'],
                          location_kind=kind,location=offset,
                          conclusion='matching_storage_location_only',
                          limitations='Aliases, intervening indirect writes, all path conditions and escape lifetimes remain unproven.'))
    f930 = next(t for t in tables if t['base']==0x105c8)
    if f930['slots'][0]['target']!=0xf930:
        raise ValueError('F930 vtable slot changed')
    candidate = calls[0xfac6]
    if candidate['stack_arguments'][0]['low32']!=('constant',0):
        raise ValueError('FAC6 fifth argument changed')
    return dict(sha256=SHA256,construction_writes=construction,candidate_tables=tables,
                allocations=allocs,location_links=links,
                conditional_allocator_path=dict(call=0xfac6,candidate_target=0xf930,
                    target_pointer_site=0x105c8,pool_type_low32=0,
                    evidence_sites=[0xe384,0xe38b,0xe3f7,0xe3fe,0xe406,0xb006,0xb027,0xaf6c,0x3fb6,0x40a8,0xfab1,0xfac6],
                    status='conditional_object_identity_not_proven',
                    condition='FA30 receiver retains the vtable installed by E3B0 on the corresponding 0x38-byte array element.'),
                original_failure_path=dict(function=0x820,allocation=0x835,compare=0x84b,
                    branch=0x84f,zeroing=0x860,
                    finding='JNE bypasses zeroing on non-NULL; NULL with positive size reaches REP STOSB with RDI=0.',
                    status='static_original_behavior_finding_not_modified'),
                limits=['Candidate table extents and object types are inferred, not original symbols.',
                        'No candidate edge is promoted to an unconditional resolved indirect call.',
                        'No ownership or NX-safety proof is made; no binary is emitted.'])


if __name__ == '__main__':
    source = Path('Files/64bit/Files/RDWM1064.SYS')
    before = source.read_bytes()
    flow = discover(before)
    result = inventory(before,flow)
    Path('reports/ownership-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    for title,ranges in [
        ('allocator_virtual_path',[(0xe3b0,0xe411),(0x3fae,0x40ad),(0xfaa0,0xfac8)]),
        ('allocation_lifetimes',[(0xa280,0xa301),(0xa310,0xa33f),(0xa590,0xa69a),(0xc090,0xc378),(0xc4a0,0xc6aa)])]:
        subset = dict(flow,instructions=[i for i in flow['instructions'] if any(a<=i['rva']<b for a,b in ranges)])
        (Path('asm/reviewed')/(title+'.asm')).write_text(
            '; See reports/OWNERSHIP_ANALYSIS.md; conditional target and storage matches are not ownership proofs.\n'+listing(subset),encoding='utf-8')
    if source.read_bytes()!=before:
        raise RuntimeError('Original changed during review')
    print('Candidate tables:',len(result['candidate_tables']),'; verified allocation/free location matches:',len(result['location_links']))
