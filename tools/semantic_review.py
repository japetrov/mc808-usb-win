"""Hash-bound handler and allocation evidence; emits analysis listings only."""
import hashlib
import json
from pathlib import Path
import struct

import pefile
from control_flow import discover, listing
from reviewed_regions import SHA256


REGIONS = [
    ('init',[(0x13088,0x130dd),(0x130e4,0x13102)]),
    ('cookie_handlers',[(0xfc30,0xfc50),(0xfd78,0xfddb),(0xfde4,0xfe01)]),
    ('allocation_helpers',[(0x820,0x889),(0x8660,0x8763),(0xf930,0xfa26)]),
]


def review(data, flow):
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise ValueError('Semantic review is bound to the reviewed original')
    p = pefile.PE(data=data)
    by_rva = {i['rva']:i for i in flow['instructions']}
    handlers = []
    for h in flow['handler_records']:
        packed = h['first_payload_u32']
        # These six original records all take the simple unaligned-frame branch.
        # The helper's optional flag-4 alignment path is not exercised by them.
        if packed & 7:
            raise ValueError('Unreviewed handler payload flags')
        offset = packed & ~7
        begin = h['function']
        prologue = [i for i in flow['instructions'] if begin <= i['rva'] < begin+80]
        cookie_stores = [i['rva'] for i in prologue if i['mnemonic']=='mov'
                         and len(i['operands'])==2
                         and i['operands'][0].get('base')=='rsp'
                         and i['operands'][0].get('displacement')==offset
                         and i['operands'][0]['access'] & 2
                         and i['operands'][1].get('register')=='rax']
        if len(cookie_stores) != 1:
            raise ValueError('Handler offset does not identify a unique cookie store')
        store = cookie_stores[0]
        prev = next(i for i in prologue if i['rva']+i['size']==store)
        load = next(i for i in prologue if i['rva']+i['size']==prev['rva'])
        if prev['mnemonic']!='xor' or prev['operands_text']!='rax, rsp' or load['operands'][1].get('target_rva')!=0x10b00:
            raise ValueError('Cookie store pattern changed')
        handlers.append(dict(**h,cookie_offset=offset,cookie_store=store,
                             payload_kind='stack_cookie_offset_not_image_RVA',
                             preserve_payload_if_frame_unchanged=True))
    sites = []
    for call in flow['indirect_transfers']:
        imp = call['imported']
        if not imp or imp['name'] not in ('ExAllocatePool','ExAllocatePoolWithTag'):
            continue
        at = call['source']
        f = next(f for f in flow['runtime_functions'] if f['begin']<=at<f['end'])
        preceding = [i for i in flow['instructions'] if f['begin']<=i['rva']<at]
        setup = next(i for i in reversed(preceding) if any(x in ('rcx','ecx','cx','cl','ch') for x in i['registers_written']))
        if setup['mnemonic']=='xor' and setup['operands_text']=='ecx, ecx':
            pool = dict(kind='constant',value=0,name='NonPagedPool')
        elif setup['mnemonic']=='mov' and setup['operands'][1].get('kind')=='immediate':
            value = setup['operands'][1]['value']
            pool = dict(kind='constant',value=value,name='PagedPool' if value==1 else 'unclassified')
        else:
            pool = dict(kind='stack_argument_requires_interprocedural_review')
        # Constant evidence is only valid with no branch/call between assignment and use.
        between = [i for i in preceding if setup['rva']<i['rva']<at]
        if pool['kind']=='constant' and any(i['mnemonic'].startswith(('j','call','loop','ret')) for i in between):
            raise ValueError('Constant assignment crosses an unanalyzed control transfer')
        callers = [dict(source=e['source'],target=e['target']) for e in flow['edges']
                   if e['kind']=='call' and e['target']==f['begin']]
        sites.append(dict(rva=at,import_name=imp['name'],function=f,setup=setup,
                          pool=pool,direct_callers=callers,
                          instruction_after_call=by_rva.get(at+by_rva[at]['size']),
                          buffer_execution_and_lifetime_proven=False))
    return dict(sha256=SHA256,handlers=handlers,allocation_sites=sorted(sites,key=lambda x:x['rva']),
                derived_argument_findings=[
                    dict(function=0x8660,call=0x8688,entry_rsp_offset=0x20,argument='fourth (R9D)',
                         evidence='push rdi and sub rsp,0x50 produce delta -0x58; load [rsp+0x78] reads homed R9D',
                         direct_caller=0xb1de,direct_caller_r9=0,
                         limitation='Other callers or external exposure are not excluded'),
                    dict(function=0xf930,call=0xf95b,entry_rsp_offset=0x28,argument='fifth (stack)',
                         evidence='push rdi and sub rsp,0x50 produce delta -0x58; load [rsp+0x80] reads entry RSP+0x28',
                         vtable_pointer_site=0x105c8,
                         limitation='Pool type at indirect callers remains unresolved')],
                note='No allocation-buffer execution, alias/lifetime, or equivalence proof is claimed.')


def main():
    source = Path('Files/64bit/Files/RDWM1064.SYS')
    data = source.read_bytes()
    flow = discover(data)
    result = review(data,flow)
    Path('reports/semantic-review.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    out = Path('asm/reviewed')
    out.mkdir(parents=True,exist_ok=True)
    for title,ranges in REGIONS:
        partial = dict(flow)
        partial['instructions'] = [i for i in flow['instructions'] if any(a<=i['rva']<b for a,b in ranges)]
        notes = {
            'init': '; Cookie state is stored in .data RVAs 10B00/10B08; no direct INIT store in these ranges.\n',
            'cookie_handlers': '; FDE4 passes handler data to FD78. First payload DWORD is a masked cookie stack offset.\n'
                               '; All six reviewed records have low three payload bits zero; preserve frame-relative payloads.\n',
            'allocation_helpers': '; 835 passes PoolType=0. 8688 obtains PoolType from homed argument 4 (R9D).\n'
                                  '; F95B obtains PoolType from entry RSP+28h, argument 5. Indirect callers unresolved.\n'
                                  '; Buffer lifetime/execution and allocation-failure behavior are not proven safe to change.\n',
        }
        text = (notes[title]+'; Reviewed original ranges: '+', '.join('%08X..%08X (exclusive)' % (a,b) for a,b in ranges)+'\n'
                '; See reports/DEEP_ANALYSIS.md for semantic notes and limitations.\n'+listing(partial))
        (out/(title+'.asm')).write_text(text,encoding='utf-8')
    if source.read_bytes()!=data:
        raise RuntimeError('Original changed during review')
    print('Reviewed %d handler records and %d allocation sites; wrote three assembly analysis listings.' %
          (len(result['handlers']),len(result['allocation_sites'])))


if __name__ == '__main__':
    main()
