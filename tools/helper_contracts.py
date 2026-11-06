"""Original-byte contracts for helper 820 and selected object paths.

Selected paths and saved argument origins carry explicit preconditions. This
module does not promote conditional object matches to resolved call edges.
"""
import hashlib
import json
from pathlib import Path

from control_flow import discover, listing
from frame_map import frames, normalize
from reviewed_regions import SHA256
from trace_calls import Slice, trace


CALLERS = {
    0xb75c:dict(location='local',offset=-0x38,size=0x88),
    0xb7ad:dict(location='object_field',offset=0x90,size=0x12),
    0xb97f:dict(location='local',offset=-0x78,size=0x88),
    0xb9cd:dict(location='local',offset=-0x88,size=0x88),
    0xbb70:dict(location='local_replacement',offset=-0x78,size=0x88),
    0xbc21:dict(location='object_field',offset=0x98,size=None),
    0xc2d6:dict(location='indexed_object_field',offset=0x50,stride=8,size=None),
    0xd6b7:dict(location='object_field',offset=0x28,size=0x80),
    0xd6ea:dict(location='object_field',offset=0x30,size=None),
    0xf62c:dict(location='local',offset=-0x38,size=0x28),
}


def selected_path(flow,frame_rows,begin,call,seed_home_origins=False):
    ins = {i['rva']:i for i in flow['instructions']}
    frame = next(r for r in frame_rows if r['function']['begin']<=begin<r['function']['end'])
    height = frame['heights'].get(begin)
    if height is None:
        raise ValueError('No unique stack height for selected path')
    state = Slice(begin,begin==frame['function']['begin'])
    # For selected interior paths, naming old saved parameters is conditional on
    # those homes retaining the prologue values. The condition is never hidden.
    assumptions = []
    if seed_home_origins:
        for h in frame['argument_home_origins']:
            state.memory[('stack_address',h['entry_offset']-height),h['width']] = ('saved_argument_origin',h['argument'])
        assumptions.append('Saved argument homes retain their original values at path entry.')
    edges = {(e['source'],e['target']) for e in flow['edges'] if e['kind'] in ('fallthrough','jump','reviewed_switch')}
    visited,branches = [],[]
    at = begin
    while at!=call:
        i = ins.get(at)
        if i is None or at>call:
            raise ValueError('Selected path is not a decoded increasing-address path')
        if i['mnemonic']=='call':
            raise ValueError('Selected path crosses an unsummarized call')
        nxt = at+i['size']
        if (at,nxt) not in edges:
            raise ValueError('Selected path lacks a fallthrough edge')
        if i['mnemonic'].startswith(('j','loop')):
            branches.append(dict(rva=at,path='fallthrough_only'))
        state.step(i)
        visited.append(at)
        at = nxt
    if ins[call]['mnemonic']!='call':
        raise ValueError('Selected path must terminate at a call')
    return dict(begin=begin,call=call,function=frame['function']['begin'],instructions=visited,
                chosen_branch_paths=branches,assumptions=assumptions,
                arguments={r:normalize(state.reg(r),height) for r in ('rcx','rdx','r8','r9')})


def analyze(data,flow):
    if hashlib.sha256(data).hexdigest()!=SHA256 or flow['sha256']!=SHA256:
        raise ValueError('Contracts require the reviewed original')
    frame_rows = frames(flow)
    if any(r['conflicts'] or r['unsupported'] for r in frame_rows):
        raise ValueError('Ambiguous stack analysis; refusing field contracts')
    calls = {c['source']:c for c in trace(data,flow)['calls']}
    discovered = {e['source'] for e in flow['edges'] if e['kind']=='call' and e['target']==0x820}
    if discovered!=set(CALLERS):
        raise ValueError('Helper caller set changed')
    rows = []
    for at,contract in sorted(CALLERS.items()):
        c = calls[at]
        f = next(r for r in frame_rows if r['function']['begin']<=at<r['function']['end'])
        height = f['heights'][c['block']]
        output = normalize(c['register_arguments']['rcx'],height)
        size = c['register_arguments']['rdx']
        if contract['location'].startswith('local') and output!=('entry_stack_address',contract['offset']):
            raise ValueError('Caller local storage changed')
        if contract['size'] is not None and size!=('constant',contract['size']):
            raise ValueError('Caller fixed size changed')
        if at==0xb7ad:
            if (output[0]!='add' or output[2]!=('constant',0x90)
                    or output[1][:3]!=('memory',8,('entry_stack_address',8))):
                raise ValueError('B7AD output field changed')
        if at in (0xd6b7,0xd6ea) and output!=('add',('argument',1),('constant',contract['offset'])):
            raise ValueError('Object-method output field changed')
        if at==0xc2d6:
            if (output[0]!='add' or output[2]!=('constant',0x50) or output[1][0]!='add'
                    or output[1][1][:3]!=('memory',8,('entry_stack_address',8))
                    or output[1][2][0]!='multiply' or output[1][2][2]!=8):
                raise ValueError('C2D6 indexed output field changed')
        rows.append(dict(call=at,function=f['function']['begin'],contract=contract,
                         local_output_expression=output,local_size_expression=size,
                         classification='local_exact' if contract['location'].startswith('local') else 'reviewed_field_schema_requires_object_identity',
                         nx_conversion_approved=False))
    # Two allocation/release method pairs can be expressed against argument 1
    # without carrying any facts across an unknown call or branch merge.
    pairs = []
    for alloc_begin,alloc_call,free_begin,free_call,offset in [
            (0xd6a0,0xd6b7,0xd700,0xd72c,0x28),
            (0xd6d0,0xd6ea,0xd750,0xd77c,0x30)]:
        allocation = selected_path(flow,frame_rows,alloc_begin,alloc_call)
        release = selected_path(flow,frame_rows,free_begin,free_call)
        expected = ('add',('argument',1),('constant',offset))
        if allocation['arguments']['rcx']!=expected:
            raise ValueError('Allocation field schema mismatch')
        actual = release['arguments']['rcx']
        if actual[:3]!=('memory',8,expected):
            raise ValueError('Release field schema mismatch')
        if calls[free_call]['imported']['name']!='ExFreePoolWithTag':
            raise ValueError('Release import changed')
        pairs.append(dict(offset=offset,allocation_path=allocation,release_path=release,
                          conclusion='matching_parameterized_field_schema',
                          preconditions=['Both methods receive the same live object as argument 1.',
                                         'No intervening alias replaces the field with another allocation.']))
    object_paths = [
        selected_path(flow,frame_rows,0xe37c,0xe38b,True),
        selected_path(flow,frame_rows,0xb001,0xb027,True),
        selected_path(flow,frame_rows,0xaf14,0xaf6c,True),
        selected_path(flow,frame_rows,0x4032,0x40a8,True),
    ]
    if object_paths[0]['arguments']['rcx']!=('add',('saved_argument_origin',1),('constant',0x118)):
        raise ValueError('Constructor receiver offset changed')
    if object_paths[1]['arguments']['rcx']!=('add',('saved_argument_origin',1),('constant',0x118)):
        raise ValueError('Initialization receiver offset changed')
    if object_paths[2]['arguments']['rcx']!=('saved_argument_origin',1):
        raise ValueError('AEE0 does not forward receiver unchanged')
    index_address = object_paths[3]['arguments']['rcx']
    if index_address[0]!='add' or index_address[1]!=('saved_argument_origin',1) or index_address[2][0]!='multiply' or index_address[2][2]!=0x38:
        raise ValueError('FA30 receiver stride changed')
    # BC21's output pointer is held in a local alias. Verify its defining
    # instruction chain rather than declaring an unknown local an object pointer.
    ins = {i['rva']:i for i in flow['instructions']}
    required = {0xbbf1:('mov','rax, qword ptr [rsp + 0xb0]'),
                0xbbf9:('add','rax, 0x98'),0xbbff:('mov','qword ptr [rsp + 0x70], rax'),
                0xbc1c:('mov','rcx, qword ptr [rsp + 0x70]')}
    for at,(m,op) in required.items():
        if (ins[at]['mnemonic'],ins[at]['operands_text'])!=(m,op):
            raise ValueError('BC21 defining alias chain changed')
    return dict(sha256=SHA256,frames=frame_rows,helper_callers=rows,field_method_pairs=pairs,
                object_identity_path_summaries=object_paths,
                object_identity_status='structural_receiver_offsets_verified_lifecycle_identity_still_conditional',
                bc21_alias_chain=list(required),
                limits=['Field names describe offsets, not recovered original C++ types.',
                        'Method schema equality is not proof of concrete object identity.',
                        'Selected paths may be infeasible; chosen branch conditions are not solved.',
                        'Saved home labels are conditional origins and do not override the conservative call slicer.',
                        'No binary is emitted and no allocation is approved for NX conversion.'])


if __name__=='__main__':
    path = Path('Files/64bit/Files/RDWM1064.SYS')
    data = path.read_bytes()
    flow = discover(data)
    result = analyze(data,flow)
    Path('reports/helper-contracts.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    ranges = [(0x890,0x8c5),(0xb740,0xb953),(0xb960,0xbef2),(0xd6a0,0xd793),(0xf610,0xf79a)]
    sub = dict(flow,instructions=[i for i in flow['instructions'] if any(a<=i['rva']<b for a,b in ranges)])
    Path('asm/reviewed/helper_820_callers.asm').write_text(
        '; See reports/HELPER_CONTRACTS.md for path preconditions and remaining alias/lifetime gates.\n'+listing(sub),encoding='utf-8')
    if path.read_bytes()!=data:
        raise RuntimeError('Original changed during analysis')
    print('Analyzed',len(result['frames']),'frames and',len(result['helper_callers']),'helper callers; verified',len(result['field_method_pairs']),'field method pairs.')
