"""Intraprocedural stack-height analysis; names saved arguments as origins only."""
from collections import defaultdict, deque


def stack_effect(ins):
    m,ops = ins['mnemonic'],ins['operands']
    if m=='push':
        return -8
    if m=='pop':
        return None if ops[0].get('register')=='rsp' else 8
    if m in ('add','sub') and ops and ops[0].get('register')=='rsp':
        if ops[1].get('kind')!='immediate':
            return None
        return ops[1]['value'] * (-1 if m=='sub' else 1)
    if m=='call' or m.startswith(('ret','iret')):
        return 0  # Net call/return effect within caller; no successor after RET.
    if any(r in ('rsp','esp','sp','spl') for r in ins['registers_written']):
        return None
    return 0


def frames(flow):
    instructions = {i['rva']:i for i in flow['instructions']}
    edges = defaultdict(set)
    for e in flow['edges']:
        if e['kind'] in ('fallthrough','jump','reviewed_switch') and e['target'] is not None:
            edges[e['source']].add(e['target'])
    result = []
    for f in flow['runtime_functions']:
        queue = deque([f['begin']])
        heights = {f['begin']:0}
        conflicts,unsupported = [],[]
        while queue:
            at = queue.popleft()
            ins = instructions.get(at)
            if ins is None:
                continue
            delta = stack_effect(ins)
            if delta is None:
                unsupported.append(at)
                out = None
            else:
                out = heights[at]+delta if heights[at] is not None else None
            for target in edges[at]:
                if not f['begin']<=target<f['end']:
                    continue
                if target not in heights:
                    heights[target] = out
                    queue.append(target)
                elif heights[target]!=out and heights[target] is not None:
                    conflicts.append(dict(target=target,first=heights[target],second=out))
                    heights[target] = None
                    queue.append(target)
        homes = []
        # Capture only straight prologue spills before a call/branch; these are
        # origin labels, not proof the spill remains immutable during execution.
        at = f['begin']
        modified = set()
        for _ in range(16):
            ins = instructions.get(at)
            if ins is None or at not in heights or heights[at] is None:
                break
            if ins['mnemonic'].startswith(('j','call','ret','loop')):
                break
            ops = ins['operands']
            if ins['mnemonic']=='mov' and len(ops)==2 and ops[0].get('base')=='rsp' and not ops[0].get('index'):
                args = dict(rcx=1,ecx=1,rdx=2,edx=2,r8=3,r8d=3,r9=4,r9d=4)
                n = args.get(ops[1].get('register'))
                offset = heights[at]+ops[0]['displacement']
                if n and n not in modified and offset==n*8:
                    homes.append(dict(argument=n,entry_offset=offset,width=ops[0]['size'],spill=at))
            for name in ins['registers_written']:
                n = dict(rcx=1,ecx=1,cx=1,cl=1,ch=1,rdx=2,edx=2,dx=2,dl=2,dh=2,
                         r8=3,r8d=3,r8w=3,r8b=3,r9=4,r9d=4,r9w=4,r9b=4).get(name)
                if n:
                    modified.add(n)
            at += ins['size']
        result.append(dict(function=f,heights=heights,argument_home_origins=homes,
                           conflicts=conflicts,unsupported=unsupported))
    return result


def normalize(value,block_height):
    """Translate block-relative stack expressions to entry-relative expressions."""
    if not isinstance(value,(tuple,list)):
        return value
    if value and value[0]=='stack_address':
        return ('entry_stack_address',block_height+value[1]) if block_height is not None else ('unknown','unknown block height')
    return tuple(normalize(x,block_height) for x in value)
