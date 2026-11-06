"""Read-only recursive AMD64 disassembly and typed evidence inventory.

This is a conservative discovery tool, not a complete disassembler/decompiler.
Generated assembly is an analysis listing, not buildable reconstruction source.
"""
import argparse
from collections import Counter, defaultdict, deque
import hashlib
import json
from pathlib import Path
import struct

import capstone
import pefile
from capstone.x86 import X86_OP_IMM, X86_OP_MEM, X86_OP_REG, X86_REG_RIP
from reviewed_regions import SHA256, SWITCHES, DATA_RANGES


EXPECTED = '984f00a9ffe11380e63392e7d7f6e3e5f70aa178a9764d47fc790a2170aaf084'


def discover(data):
    p = pefile.PE(data=data)
    if p.FILE_HEADER.Machine != 0x8664 or p.OPTIONAL_HEADER.Magic != 0x20b:
        raise ValueError('Requires AMD64 PE32+')
    base = p.OPTIONAL_HEADER.ImageBase
    md = capstone.Cs(capstone.CS_ARCH_X86, capstone.CS_MODE_64)
    md.detail = True
    known_original = hashlib.sha256(data).hexdigest() == SHA256
    reviewed_data = [dict(x) for x in DATA_RANGES] if known_original else []
    switches = []
    if known_original:
        for spec in SWITCHES:
            spec = dict(spec)
            selectors = p.get_data(spec['selector'],spec['count']) if spec['selector'] is not None else None
            count = max(selectors)+1 if selectors else spec['count']
            spec['target_count'] = count
            spec['targets'] = list(struct.unpack('<'+'I'*count,p.get_data(spec['table'],count*4)))
            spec['selector_bytes'] = selectors.hex() if selectors else None
            reviewed_data.append(dict(begin=spec['table'],end=spec['table']+count*4,kind='switch_target_rvas'))
            if selectors:
                reviewed_data.append(dict(begin=spec['selector'],end=spec['selector']+spec['count'],kind='switch_selectors'))
            switches.append(spec)
    def section(rva):
        return p.get_section_by_rva(rva)
    def name(rva):
        s = section(rva)
        return s.Name.rstrip(b'\0').decode() if s else None
    def executable(rva):
        s = section(rva)
        return bool(s and s.Characteristics & 0x20000000
                    and s.VirtualAddress <= rva < s.VirtualAddress+s.Misc_VirtualSize)
    def known_data(rva):
        return any(x['begin'] <= rva < x['end'] for x in reviewed_data)
    imports = {i.address-base:dict(dll=d.dll.decode(), name=i.name.decode() if i.name else None,
                                  ordinal=i.ordinal)
               for d in getattr(p,'DIRECTORY_ENTRY_IMPORT',[]) for i in d.imports}
    functions = [dict(begin=e.struct.BeginAddress, end=e.struct.EndAddress,
                      unwind=e.struct.UnwindData)
                 for e in getattr(p,'DIRECTORY_ENTRY_EXCEPTION',[])]
    seeds = defaultdict(set)
    queue = deque()
    def seed(rva, reason):
        if executable(rva) and not known_data(rva):
            if not seeds[rva]:
                queue.append(rva)
            seeds[rva].add(reason)
    seed(p.OPTIONAL_HEADER.AddressOfEntryPoint,'entry_point')
    for spec in switches:
        for target in spec['targets']:
            if not executable(target) or known_data(target):
                raise ValueError('Reviewed switch target is not executable code')
            seed(target,'reviewed_switch_target')
    handler_records = []
    for f in functions:
        seed(f['begin'],'runtime_function')
        raw = p.get_data(f['unwind'],4)
        flags = raw[0] >> 3
        tail = f['unwind']+4+((raw[2]+1)//2)*4
        if flags & 3 and not flags & 4:
            handler = struct.unpack('<I',p.get_data(tail,4))[0]
            seed(handler,'unwind_handler')
            handler_records.append(dict(function=f['begin'],unwind=f['unwind'],flags=flags,
                                        handler=handler,payload=tail+4,
                                        first_payload_u32=struct.unpack('<I',p.get_data(tail+4,4))[0]))
    absolute_pointers = []
    for b in getattr(p,'DIRECTORY_ENTRY_BASERELOC',[]):
        for e in b.entries:
            if e.type != 10:
                continue
            target = struct.unpack('<Q',p.get_data(e.rva,8))[0]-base
            absolute_pointers.append(dict(site=e.rva,target=target,
                                          target_section=name(target),executable_target=executable(target)))
            seed(target,'relocated_absolute_pointer')
    decoded, occupied, conflicts, failures = {}, {}, [], []
    edges, references, indirect = [], [], []
    while queue:
        rva = queue.popleft()
        while executable(rva) and not known_data(rva):
            if rva in decoded:
                break
            if rva in occupied:
                conflicts.append(dict(rva=rva,existing_instruction=occupied[rva],kind='target_inside_instruction'))
                break
            s = section(rva)
            count = min(15,s.VirtualAddress+s.Misc_VirtualSize-rva)
            ins = next(md.disasm(p.get_data(rva,count),base+rva,count=1),None)
            if ins is None:
                failures.append(rva)
                break
            overlap = [x for x in range(rva,rva+ins.size) if x in occupied]
            if overlap:
                conflicts.append(dict(rva=rva,existing_instruction=occupied[overlap[0]],kind='overlapping_decode'))
                break
            if any(known_data(x) for x in range(rva,rva+ins.size)):
                conflicts.append(dict(rva=rva,kind='instruction_overlaps_reviewed_data'))
                break
            ops = []
            for op in ins.operands:
                item = dict(size=op.size,access=op.access)
                if op.type == X86_OP_REG:
                    item.update(kind='register',register=ins.reg_name(op.reg))
                elif op.type == X86_OP_IMM:
                    item.update(kind='immediate',value=op.imm)
                elif op.type == X86_OP_MEM:
                    item.update(kind='memory',base=ins.reg_name(op.mem.base),
                                index=ins.reg_name(op.mem.index),scale=op.mem.scale,
                                displacement=op.mem.disp,segment=ins.reg_name(op.mem.segment))
                    if op.mem.base == X86_REG_RIP:
                        target = rva+ins.size+op.mem.disp
                        item['target_rva'] = target
                        references.append(dict(source=rva,target=target,target_section=name(target),
                                               kind='rip_memory',access=op.access,
                                               displacement_offset=ins.disp_offset,
                                               displacement_size=ins.disp_size))
                        # LEA of executable bytes may identify an otherwise unreachable callback.
                        # These seeds remain tentative: executable sections also contain data.
                        if ins.mnemonic == 'lea':
                            seed(target,'lea_executable_address_tentative')
                ops.append(item)
            regs_read, regs_write = ins.regs_access()
            decoded[rva] = dict(rva=rva,size=ins.size,bytes=bytes(ins.bytes).hex(),
                                immediate_offset=ins.imm_offset,immediate_size=ins.imm_size,
                                displacement_offset=ins.disp_offset,displacement_size=ins.disp_size,
                                mnemonic=ins.mnemonic,operands_text=ins.op_str,operands=ops,
                                registers_read=[ins.reg_name(x) for x in regs_read],
                                registers_written=[ins.reg_name(x) for x in regs_write],
                                section=name(rva))
            for byte in range(rva,rva+ins.size):
                occupied[byte] = rva
            call = ins.group(capstone.CS_GRP_CALL)
            jump = ins.group(capstone.CS_GRP_JUMP) or ins.mnemonic.startswith('loop')
            stop = ins.group(capstone.CS_GRP_RET) or ins.group(capstone.CS_GRP_IRET) or ins.mnemonic in ('int3','ud2','hlt')
            if call or jump:
                kind = 'call' if call else 'jump'
                target = None
                if ins.operands and ins.operands[0].type == X86_OP_IMM:
                    target = ins.operands[0].imm-base
                    edges.append(dict(source=rva,target=target,kind=kind,direct=True))
                    seed(target,'direct_'+kind)
                else:
                    op = ops[0] if ops else {}
                    imported = imports.get(op.get('target_rva'))
                    entry = dict(source=rva,kind=kind,operand=op,imported=imported)
                    indirect.append(entry)
                    edges.append(dict(source=rva,target=None,kind=kind,direct=False,
                                      iat_rva=op.get('target_rva'),imported=imported))
                if jump and ins.mnemonic == 'jmp':
                    break
            if stop:
                break
            nxt = rva+ins.size
            edges.append(dict(source=rva,target=nxt,kind='fallthrough',direct=True))
            rva = nxt
    # Verify manually supplied switch facts against the decoded dispatch sequence.
    # The original sequence materializes ImageBase with LEA, loads u32 RVAs, then
    # adds ImageBase and jumps. These indexed table displacements have no DIR64.
    for spec in switches:
        at = spec['jump']
        if at not in decoded or decoded[at]['mnemonic'] != 'jmp' or decoded[at]['operands_text'] != 'rax':
            raise ValueError('Reviewed switch does not terminate in jmp rax')
        add = decoded.get(at-3)
        load = decoded.get(at-10)
        if not add or add['mnemonic'] != 'add' or add['operands_text'] != 'rax, rcx':
            raise ValueError('Unexpected switch base addition')
        if not load or load['mnemonic'] != 'mov' or load['operands'][1].get('displacement') != spec['table']:
            raise ValueError('Unexpected switch target table load')
        mem = load['operands'][1]
        if (load['operands'][0].get('register') != 'eax' or mem.get('base') != 'rcx'
                or mem.get('index') != 'rax' or mem.get('scale') != 4 or mem['size'] != 4):
            raise ValueError('Unexpected switch target indexing')
        lea = decoded.get(at-17 if spec['selector'] is None else at-25)
        if (not lea or lea['mnemonic'] != 'lea' or lea['operands'][0].get('register') != 'rcx'
                or lea['operands'][1].get('target_rva') != 0):
            raise ValueError('Switch base is not the image base')
        if spec['selector'] is not None:
            selector = decoded.get(at-18)
            if (not selector or selector['mnemonic']!='movzx'
                    or selector['operands'][0].get('register')!='eax'):
                raise ValueError('Unexpected compact switch selector load')
            mem = selector['operands'][1]
            if (mem.get('base')!='rcx' or mem.get('index')!='rax' or mem.get('scale')!=1
                    or mem.get('displacement')!=spec['selector'] or mem['size']!=1):
                raise ValueError('Unexpected compact switch selector indexing')
        guards = sorted((i for i in decoded.values() if at-90<=i['rva']<lea['rva'] and i['mnemonic']=='cmp'),key=lambda i:i['rva'])
        cmp = guards[-1] if guards else None
        branch = decoded.get(cmp['rva']+cmp['size']) if cmp else None
        if (not cmp or cmp['operands'][1].get('value')!=spec['count']-1
                or not branch or branch['mnemonic']!='ja'):
            raise ValueError('Unexpected unsigned switch bound')
        spec['range_check_rva'] = cmp['rva']
        spec['default_target'] = branch['operands'][0]['value']-base
        spec['validated_dispatch'] = True
        for target in sorted(set(spec['targets'])):
            edges.append(dict(source=at,target=target,kind='reviewed_switch',direct=False))
    unknown = []
    for s in p.sections:
        if not s.Characteristics & 0x20000000:
            continue
        end = s.VirtualAddress+s.Misc_VirtualSize
        at = s.VirtualAddress
        while at < end:
            if at in occupied or known_data(at):
                at += 1
                continue
            begin = at
            while at < end and at not in occupied and not known_data(at):
                at += 1
            block = p.get_data(begin,at-begin)
            # This is a byte description, never an automatic code/data classification.
            unknown.append(dict(begin=begin,end=at,size=at-begin,section=name(begin),
                                all_zero=all(x == 0 for x in block),
                                only_zero_or_int3=all(x in (0,0xcc) for x in block),
                                preview_hex=block[:32].hex()))
    result = dict(sha256=hashlib.sha256(data).hexdigest(),image_base=base,
                  versions=dict(capstone=capstone.__version__,pefile=pefile.__version__),
                  runtime_functions=functions,handler_records=handler_records,
                  absolute_pointers=absolute_pointers,
                  reviewed_data_ranges=reviewed_data,reviewed_switches=switches,
                  seeds=[dict(rva=k,reasons=sorted(v)) for k,v in sorted(seeds.items())],
                  instructions=[decoded[k] for k in sorted(decoded)],edges=edges,
                  references=references,indirect_transfers=indirect,
                  immediate_address_candidates=[dict(source=i['rva'],value=o['value'],kind='untyped_integer')
                      for i in decoded.values() if not i['mnemonic'].startswith(('j','call','loop'))
                      for o in i['operands'] if o.get('kind')=='immediate'
                      and base<=o['value']<base+p.OPTIONAL_HEADER.SizeOfImage],
                  indexed_displacement_candidates=[dict(source=i['rva'],operand=o,kind='untyped_displacement')
                      for i in decoded.values() for o in i['operands'] if o.get('kind')=='memory'
                      and o.get('index') and 0x380<=o['displacement']<p.OPTIONAL_HEADER.SizeOfImage],
                  conflicts=conflicts,decode_failures=sorted(set(failures)),
                  unclassified_executable_ranges=unknown,
                  limitations=['Seeds are evidence, not proven function boundaries.',
                               'Unresolved indirect transfers can hide code and references.',
                               'Unclassified executable bytes can include data, padding or code.',
                               'No complete alias analysis, allocation lifetime proof, or equivalence proof is performed.'])
    result['summary'] = dict(instructions=len(decoded),decoded_bytes=len(occupied),
                             seeds=len(seeds),conflicts=len(conflicts),decode_failures=len(set(failures)),
                             unclassified_bytes=sum(x['size'] for x in unknown),
                             reviewed_data_bytes=sum(executable(at) for x in reviewed_data for at in range(x['begin'],x['end'])),
                             resolved_switches=len(switches),
                             indirect_transfers=len(indirect),
                             nonimport_indirect_transfers=sum(not x['imported'] for x in indirect),
                             unresolved_nonimport_indirect_transfers=sum(not x['imported'] and x['source'] not in {s['jump'] for s in switches} for x in indirect),
                             imported_transfers=dict(Counter(x['imported']['name'] for x in indirect if x['imported'])))
    return result


def listing(report):
    lines = ['; ANALYSIS LISTING ONLY - not buildable source',
             '; Input SHA256: '+report['sha256'],
             '; Left column uses original RVAs; absolute branch operands use preferred VAs.',
             '; Names are inferred, not original symbols.',
             '; Bytes omitted by recursive discovery remain UNCLASSIFIED.', '']
    seeds = {x['rva']:x['reasons'] for x in report['seeds']}
    imports = {x['source']:x['imported'] for x in report['indirect_transfers'] if x['imported']}
    previous = None
    for ins in report['instructions']:
        at = ins['rva']
        if at != previous:
            lines.append('; -- discontinuity / unclassified bytes --')
        if at in seeds:
            lines.append('loc_%08X: ; %s' % (at,', '.join(seeds[at])))
        annotation = ''
        if at in imports:
            annotation = ' ; '+imports[at]['dll']+'!'+str(imports[at]['name'])
        lines.append(('; RVA %08X  %-30s  %s %s%s' %
                     (at,ins['bytes'],ins['mnemonic'],ins['operands_text'],annotation)).rstrip())
        previous = at+ins['size']
    return '\n'.join(lines)+'\n'


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('input',type=Path)
    parser.add_argument('--output',type=Path,default=Path('reports/control-flow.json'))
    parser.add_argument('--listing',type=Path,default=Path('asm/generated/original-recursive.asm'))
    args = parser.parse_args()
    outputs = (args.output,args.listing)
    if args.output.suffix.lower() != '.json' or args.listing.suffix.lower() != '.asm':
        parser.error('Expected .json report and .asm listing')
    for out in outputs:
        if out.resolve() == args.input.resolve() or (out.exists() and out.samefile(args.input)):
            parser.error('Refusing to overwrite input')
    before = args.input.read_bytes()
    result = discover(before)
    for out,text in ((args.output,json.dumps(result,indent=2)),(args.listing,listing(result))):
        out.parent.mkdir(parents=True,exist_ok=True)
        out.write_text(text,encoding='utf-8')
    if args.input.read_bytes() != before:
        raise RuntimeError('Input changed during analysis')
    print(json.dumps(result['summary'],indent=2))


if __name__ == '__main__':
    main()
