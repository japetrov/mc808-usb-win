"""Non-emitting layout/fixup preview. Always reports unresolved emission gates."""
import hashlib
import json
from pathlib import Path

import pefile
from control_flow import discover
from reviewed_regions import SHA256


def align(value, alignment):
    return (value+alignment-1)//alignment*alignment


def preview(data, flow, *, text_append_size=0):
    if hashlib.sha256(data).hexdigest()!=SHA256 or flow['sha256']!=SHA256:
        raise ValueError('Preview requires the reviewed original')
    p = pefile.PE(data=data)
    if not isinstance(text_append_size,int) or not 0<=text_append_size<=0x10000:
        raise ValueError('Invalid code append reservation')
    regions = []
    virtual, raw = 0x1000, align(p.OPTIONAL_HEADER.SizeOfHeaders,0x200)
    for s in p.sections:
        size = max(s.Misc_VirtualSize,s.SizeOfRawData)
        appended = text_append_size if s.Name.rstrip(b'\0')==b'.text' else 0
        new_virtual_size = max(s.Misc_VirtualSize,align(size,16)+appended) if appended else s.Misc_VirtualSize
        new_raw_size = align(max(s.SizeOfRawData,new_virtual_size),0x200)
        regions.append(dict(name=s.Name.rstrip(b'\0').decode(),old_begin=s.VirtualAddress,
                            old_extent=size,old_virtual_size=s.Misc_VirtualSize,
                            new_virtual_size=new_virtual_size,
                            new_begin=virtual,new_raw_offset=raw,
                            new_raw_size=new_raw_size,
                            append_offset=align(size,16) if appended else None,
                            append_size=appended,
                            original_flags=s.Characteristics,
                            proposed_flags=s.Characteristics & ~0x80000000 if s.Name.startswith(b'INIT') else s.Characteristics,
                            flags_condition='INIT write removal requires completed alias/write audit' if s.Name.startswith(b'INIT') else None))
        virtual = align(virtual+max(new_virtual_size,new_raw_size),0x1000)
        raw += new_raw_size
    def mapped(rva):
        if 0<=rva<p.OPTIONAL_HEADER.SizeOfHeaders:
            return rva
        for r in regions:
            if r['old_begin']<=rva<r['old_begin']+r['old_extent']:
                return r['new_begin']+rva-r['old_begin']
        raise ValueError('Unmapped original RVA '+hex(rva))
    fixups = []
    def fix(kind,site,old_target,new_target,width=4,old_value=None,new_value=None,**extra):
        row = dict(kind=kind,site=site,new_site=mapped(site),old_target=old_target,
                   new_target=new_target,width=width,**extra)
        if old_value is not None:
            row.update(old_value=old_value,new_value=new_value,changes=old_value!=new_value)
        fixups.append(row)
    instructions = {i['rva']:i for i in flow['instructions']}
    overflows = []
    for ref in flow['references']:
        ins = instructions[ref['source']]
        target = mapped(ref['target'])
        disp = target-(mapped(ins['rva'])+ins['size'])
        width = ref['displacement_size']
        if not -(1<<(width*8-1))<=disp<(1<<(width*8-1)):
            overflows.append(dict(source=ins['rva'],kind='rip_memory',value=disp,width=width))
        fix('rip_displacement',ins['rva']+ref['displacement_offset'],ref['target'],target,
            width,ref['target']-(ins['rva']+ins['size']),disp)
    for e in flow['edges']:
        if e['kind'] not in ('call','jump') or not e['direct']:
            continue
        ins = instructions[e['source']]
        target = mapped(e['target'])
        disp = target-(mapped(ins['rva'])+ins['size'])
        width = ins['immediate_size']
        if width not in (1,4) or not -(1<<(width*8-1))<=disp<(1<<(width*8-1)):
            overflows.append(dict(source=ins['rva'],kind='branch',value=disp,width=width))
        fix('relative_control_transfer',ins['rva']+ins['immediate_offset'],e['target'],target,width,
            e['target']-(ins['rva']+ins['size']),disp)
    for ptr in flow['absolute_pointers']:
        fix('dir64_value',ptr['site'],ptr['target'],mapped(ptr['target']),8,
            p.OPTIONAL_HEADER.ImageBase+ptr['target'],p.OPTIONAL_HEADER.ImageBase+mapped(ptr['target']))
    for switch in flow['reviewed_switches']:
        for n,target in enumerate(switch['targets']):
            fix('switch_target_rva',switch['table']+4*n,target,mapped(target),4,target,mapped(target))
        # The dispatch uses ImageBase + displacement. These displacement fields
        # are not RIP references and are not covered by base relocations.
        for ins in flow['instructions']:
            for op in ins['operands']:
                if (op.get('kind')=='memory' and op.get('base')=='rcx' and op.get('index')=='rax'
                        and op.get('displacement') in (switch['table'],switch['selector'])
                        and switch['jump']-30<=ins['rva']<switch['jump']):
                    old = op['displacement']
                    fix('imagebase_indexed_displacement',ins['rva']+ins['displacement_offset'],old,mapped(old),
                        ins['displacement_size'],old,mapped(old))
    mapped_functions = []
    for f in flow['runtime_functions']:
        r = next(r for r in regions if r['old_begin']<=f['begin']<r['old_begin']+r['old_extent'])
        if not f['begin']<f['end']<=r['old_begin']+r['old_virtual_size']:
            raise ValueError('Function crosses an unsupported original region boundary')
        mapped_functions.append(dict(old=f,new=dict(begin=mapped(f['begin']),
            end=r['new_begin']+f['end']-r['old_begin'],unwind=mapped(f['unwind']))))
    return dict(sha256=SHA256,emission_allowed=False,regions=regions,
                proposed_section_alignment=0x1000,proposed_file_alignment=0x200,
                proposed_size_of_image=virtual,fixups=fixups,displacement_overflows=overflows,
                mapped_runtime_functions=mapped_functions,
                summary=dict(fixups=len(fixups),changed_fixups=sum(f.get('changes',False) for f in fixups),
                             overflow_count=len(overflows)),
                blockers=['Allocation lifetime/execution audit and NX transformations incomplete.',
                          'Indirect call targets and aliases are not fully resolved.',
                          'INIT permission change remains conditional on write/alias review.',
                          'Import/resource/debug/directory rewrites and full unwind emission are not implemented.',
                          'Unclassified bytes and typed data/reference audit need completion.',
                          'This preview is not a complete modification manifest or proof of equivalence.'])


if __name__ == '__main__':
    data = Path('Files/64bit/Files/RDWM1064.SYS').read_bytes()
    result = preview(data,discover(data))
    Path('reports/layout-preview.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    print(json.dumps(dict(emission_allowed=result['emission_allowed'],**result['summary']),indent=2))
