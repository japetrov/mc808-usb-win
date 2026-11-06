"""Bounded straight-line symbolic slices of call arguments and indirect targets.

Blocks are analyzed independently: no target is proven across a join or call.
All memory facts are discarded after calls and possibly aliasing writes.
Expressions are evidence of local data flow, never a complete alias proof.
"""
import json
import hashlib
from pathlib import Path

from control_flow import discover


def const(n):
    return ('constant',n)


def unknown(reason):
    return ('unknown',reason)


def narrow(value,bits):
    if value[0]=='constant':
        return const(value[1] & ((1<<bits)-1))
    if value[0]=='low_bits' and value[1]<=bits:
        return value
    return ('low_bits',bits,value)


def add(left,right):
    if right==const(0):
        return left
    if left[0]=='constant' and right[0]=='constant':
        return const(left[1]+right[1])
    if left[0] in ('stack_address','image_rva') and right[0]=='constant':
        return (left[0],left[1]+right[1])
    return ('add',left,right)


ALIASES = {}
for full,names in [('rax','eax ax al ah'),('rbx','ebx bx bl bh'),('rcx','ecx cx cl ch'),
                   ('rdx','edx dx dl dh'),('rsi','esi si sil'),('rdi','edi di dil'),
                   ('rbp','ebp bp bpl'),('rsp','esp sp spl')]:
    ALIASES[full] = (full,64)
    for name,bits in zip(names.split(),[32,16,8,8]):
        ALIASES[name] = (full,bits)
for n in range(8,16):
    for suffix,bits in [('',64),('d',32),('w',16),('b',8)]:
        ALIASES['r'+str(n)+suffix] = ('r'+str(n),bits)


class Slice:
    def __init__(self,block,formal_entry=False):
        self.block = block
        self.registers = {r:('block_register',r) for r in {x[0] for x in ALIASES.values()}}
        if formal_entry:
            self.registers.update({r:('argument',n) for n,r in enumerate(('rcx','rdx','r8','r9'),1)})
        self.registers['rsp'] = ('stack_address',0)
        self.memory = {}
        self.epoch = 0
        self.formal_entry = formal_entry

    def reg(self,name):
        if name in ('ah','bh','ch','dh'):
            return unknown('high byte register read')
        full,bits = ALIASES.get(name,(name,64))
        value = self.registers.get(full,unknown('unsupported register '+str(name)))
        return value if bits==64 else narrow(value,bits)

    def setreg(self,name,value):
        full,bits = ALIASES.get(name,(name,64))
        # Partial 8/16-bit writes retain unknown upper bits. Do not fabricate a pointer.
        self.registers[full] = value if bits==64 else narrow(value,32) if bits==32 else unknown('partial register write')

    def address(self,op):
        if op.get('segment'):
            return unknown('segment-relative address')
        if 'target_rva' in op:
            return ('image_rva',op['target_rva'])
        base = self.reg(op['base']) if op.get('base') else const(0)
        if op.get('index'):
            index = self.reg(op['index'])
            scaled = const(index[1]*op['scale']) if index[0]=='constant' else ('multiply',index,op['scale'])
            base = add(base,scaled)
        return add(base,const(op.get('displacement',0)))

    def load(self,address,size):
        if (address,size) in self.memory:
            return self.memory[address,size]
        # Reads from unmodified entry stack arguments, before the first call.
        if (self.formal_entry and self.epoch==0 and address[0]=='stack_address'
                and address[1]>=0x28 and (address[1]-0x28)%8==0):
            arg = ('argument',5+(address[1]-0x28)//8)
            return arg if size==8 else narrow(arg,size*8)
        return ('memory',size,address,self.epoch)

    def value(self,op):
        if op['kind']=='immediate':
            return const(op['value'])
        if op['kind']=='register':
            return self.reg(op['register'])
        if op['kind']=='memory':
            return self.load(self.address(op),op['size'])
        return unknown('unsupported operand')

    def store(self,op,value):
        if op['kind']=='register':
            self.setreg(op['register'],value)
        elif op['kind']=='memory':
            address = self.address(op)
            # Forward only direct stack cells. Unknown/aliased stores invalidate
            # all cells rather than assuming disjointness from the active frame.
            if address[0]!='stack_address':
                self.memory.clear()
                self.epoch += 1
                return
            begin,end = address[1],address[1]+op['size']
            for key in list(self.memory):
                addr,width = key
                if addr[0]=='stack_address' and addr[1]<end and begin<addr[1]+width:
                    del self.memory[key]
            self.memory[address,op['size']] = narrow(value,op['size']*8) if op['size']<8 else value

    def step(self,ins):
        m,ops = ins['mnemonic'],ins['operands']
        if m=='mov' and len(ops)==2:
            self.store(ops[0],self.value(ops[1]))
            return
        if m in ('movzx','movsxd','movsx') and len(ops)==2:
            value = self.value(ops[1])
            if m=='movzx':
                value = narrow(value,ops[1]['size']*8)
            else:
                value = ('sign_extend',ops[1]['size']*8,value)
            self.store(ops[0],value)
            return
        if m=='lea':
            self.store(ops[0],self.address(ops[1]))
            return
        if m=='xor' and len(ops)==2 and ops[0].get('register') and ops[0].get('register')==ops[1].get('register'):
            self.store(ops[0],const(0))
            return
        if m in ('add','sub') and len(ops)==2:
            value = self.value(ops[1])
            if m=='sub':
                value = const(-value[1]) if value[0]=='constant' else ('negate',value)
            self.store(ops[0],add(self.value(ops[0]),value))
            return
        if m=='imul' and len(ops)==3 and ops[2].get('kind')=='immediate':
            value,factor = self.value(ops[1]),ops[2]['value']
            self.store(ops[0],const(value[1]*factor) if value[0]=='constant' else ('multiply',value,factor))
            return
        if m=='push':
            value = self.value(ops[0])
            self.registers['rsp'] = add(self.reg('rsp'),const(-8))
            self.memory[self.reg('rsp'),8] = value
            return
        if m=='pop':
            self.store(ops[0],self.load(self.reg('rsp'),8))
            self.registers['rsp'] = add(self.reg('rsp'),const(8))
            return
        # Undefined/unsupported effects must not preserve stale values.
        for name in ins['registers_written']:
            if name in ALIASES:
                self.setreg(name,unknown('unmodeled '+m+' at '+hex(ins['rva'])))
        if any(op.get('kind')=='memory' and op.get('access',0)&2 for op in ops):
            self.memory.clear()
            self.epoch += 1

    def after_call(self,at):
        for name in ('rax','rcx','rdx','r8','r9','r10','r11'):
            self.registers[name] = unknown('volatile after call '+hex(at))
        self.registers['rax'] = ('call_return',at)
        self.memory.clear()
        self.epoch += 1


def trace(data,flow):
    if hashlib.sha256(data).hexdigest()!=flow['sha256']:
        raise ValueError('Flow map does not match input bytes')
    starts = {f['begin'] for f in flow['runtime_functions']}
    leaders = starts | {s['rva'] for s in flow['seeds']}
    controls = {e['source']:e for e in flow['edges'] if e['kind'] in ('call','jump')}
    for e in flow['edges']:
        if e['kind'] in ('jump','reviewed_switch') and e['target'] is not None:
            leaders.add(e['target'])
    # Conditional fallthrough starts a distinct block. Do not merge facts from
    # the taken and non-taken paths using instruction address order.
    for i in flow['instructions']:
        if i['mnemonic'].startswith(('j','loop','ret','iret')) or i['mnemonic'] in ('int3','ud2','hlt'):
            leaders.add(i['rva']+i['size'])
    records,writes = [],[]
    state,previous = None,None
    for ins in flow['instructions']:
        at = ins['rva']
        if at in leaders or at!=previous or state is None:
            state = Slice(at,at in starts)
        for op in ins['operands']:
            if op.get('kind')=='memory' and op.get('access',0)&2:
                writes.append(dict(source=at,block=state.block,mnemonic=ins['mnemonic'],
                                   address=state.address(op),operand_width=op['size'],
                                   span_kind='RCX-dependent repetition' if ins['mnemonic'].startswith('rep ') else 'fixed_operand_width'))
        if ins['mnemonic']=='call':
            edge = controls.get(at,{})
            rsp = state.reg('rsp')
            records.append(dict(source=at,block=state.block,
                                target_expression=state.value(ins['operands'][0]),
                                direct_target=edge.get('target') if edge.get('direct') else None,
                                imported=edge.get('imported'),
                                register_arguments={name:state.reg(name) for name in ('rcx','rdx','r8','r9')},
                                stack_arguments=[dict(argument=n+5,
                                    value=state.load(add(rsp,const(0x20+8*n)),8),
                                    low32=state.load(add(rsp,const(0x20+8*n)),4)) for n in range(6)],
                                scope='straight_line_block_only'))
            state.after_call(at)
        else:
            state.step(ins)
        previous = at+ins['size']
    return dict(sha256=flow['sha256'],calls=records,memory_writes=writes,
                limits=['No facts propagate across block joins or conditional edges.',
                        'All tracked memory is invalidated after calls and possibly aliasing stores.',
                        'No automatic vtable-target or ownership proof is made from these expressions.'])


if __name__ == '__main__':
    source = Path('Files/64bit/Files/RDWM1064.SYS')
    before = source.read_bytes()
    result = trace(before,discover(before))
    Path('reports/call-slices.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    if source.read_bytes()!=before:
        raise RuntimeError('Original changed during slicing')
    print('Recorded',len(result['calls']),'call-site slices; no binary emitted.')
