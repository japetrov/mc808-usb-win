"""Typed, non-emitting PE metadata reconstruction plan for the reviewed original.

Outputs JSON only. It neither serializes a candidate PE nor approves emission.
"""
from collections import Counter, defaultdict
import hashlib
import json
from pathlib import Path
import struct

import pefile
from control_flow import discover
from frame_map import frames
from layout_preview import preview, align
from reviewed_regions import SHA256
from semantic_review import review


class Layout:
    def __init__(self,pe,regions):
        self.pe,self.regions = pe,regions

    def owner(self,rva):
        for r in self.regions:
            if r['old_begin']<=rva<r['old_begin']+r['old_extent']:
                return r
        raise ValueError('Unmapped RVA '+hex(rva))

    def rva(self,rva):
        if 0<=rva<self.pe.OPTIONAL_HEADER.SizeOfHeaders:
            return rva
        r = self.owner(rva)
        return r['new_begin']+rva-r['old_begin']

    def end(self,end,begin):
        r = self.owner(begin)
        if not begin<end<=r['old_begin']+r['old_virtual_size']:
            raise ValueError('Range crosses a virtual region boundary')
        return r['new_begin']+end-r['old_begin']

    def file_to_rva(self,offset):
        if 0<=offset<self.pe.OPTIONAL_HEADER.SizeOfHeaders:
            return offset
        for s in self.pe.sections:
            if s.PointerToRawData<=offset<s.PointerToRawData+s.SizeOfRawData:
                return s.VirtualAddress+offset-s.PointerToRawData
        raise ValueError('Unmapped original file offset '+hex(offset))

    def new_file(self,rva):
        if 0<=rva<self.pe.OPTIONAL_HEADER.SizeOfHeaders:
            return rva
        r = self.owner(rva)
        s = self.pe.get_section_by_rva(rva)
        if rva-r['old_begin']>=s.SizeOfRawData:
            raise ValueError('No original raw backing for RVA')
        return r['new_raw_offset']+rva-r['old_begin']


def decode_unwind(head,codes):
    """Decode version-1 x64 slot arrays without treating extension slots as ops."""
    if len(head)!=4 or head[0]&7!=1:
        raise ValueError('Only version-1 x64 unwind is reviewed')
    count = head[2]
    if len(codes)!=count*2:
        raise ValueError('Truncated unwind codes')
    operations,slot,previous,stack = [],0,256,0
    names = {0:'PUSH_NONVOL',1:'ALLOC_LARGE',2:'ALLOC_SMALL',3:'SET_FPREG',
             4:'SAVE_NONVOL',5:'SAVE_NONVOL_FAR',8:'SAVE_XMM128',9:'SAVE_XMM128_FAR',10:'PUSH_MACHFRAME'}
    while slot<count:
        offset,packed = codes[slot*2:slot*2+2]
        op,info = packed & 15,packed >> 4
        if op not in names or offset>head[1] or offset>previous:
            raise ValueError('Unsupported or malformed unwind operation')
        previous = offset
        slots = 1
        row = dict(slot=slot,code_offset=offset,opcode=op,operation=names[op],info=info)
        def extension(n):
            if slot+1+n>count:
                raise ValueError('Truncated unwind extension')
            return int.from_bytes(codes[(slot+1)*2:(slot+1+n)*2],'little')
        if op==0:
            row['register'] = info
            stack += 8
        elif op==1:
            if info==0:
                row['allocation_size'],slots = extension(1)*8,2
            elif info==1:
                row['allocation_size'],slots = extension(2),3
            else:
                raise ValueError('Invalid ALLOC_LARGE OpInfo')
            stack += row['allocation_size']
        elif op==2:
            row['allocation_size'] = info*8+8
            stack += row['allocation_size']
        elif op==3:
            if info or head[3]&15==0:
                raise ValueError('Invalid frame register operation')
        elif op in (4,8):
            row['stack_offset'],slots = extension(1)*(8 if op==4 else 16),2
        elif op in (5,9):
            row['stack_offset'],slots = extension(2),3
        elif op==10:
            if info>1:
                raise ValueError('Invalid machine-frame operation')
            row['machine_frame_size'] = 40+8*info
            stack += row['machine_frame_size']
        row['slots'] = slots
        operations.append(row)
        slot += slots
    return dict(version=1,flags=head[0]>>3,prolog_size=head[1],code_slots=count,
                frame_register=head[3]&15,frame_offset=(head[3]>>4)*16,
                stack_size=stack,operations=operations)


def regroup_relocations(sites):
    """Semantic relocation records only; no PE bytes are emitted."""
    groups = defaultdict(list)
    if len(set(sites))!=len(sites):
        raise ValueError('Duplicate relocation sites')
    for site in sorted(sites):
        if site<0 or site>0xffffffff:
            raise ValueError('Invalid relocation site')
        groups[site & ~0xfff].append((10<<12)|(site & 0xfff))
    blocks = []
    for page,entries in sorted(groups.items()):
        padding = [0] if len(entries)%2 else []
        blocks.append(dict(page_rva=page,size=8+2*(len(entries)+len(padding)),
                           dir64_count=len(entries),entries=entries+padding,padding_entries=len(padding)))
    return blocks


def plan(data,flow, *, text_append_size=0):
    if hashlib.sha256(data).hexdigest()!=SHA256 or flow['sha256']!=SHA256:
        raise ValueError('Metadata plan requires the reviewed original')
    p = pefile.PE(data=data)
    if p.get_overlay_data_start_offset() is not None or p.FILE_HEADER.PointerToSymbolTable or p.FILE_HEADER.NumberOfSymbols:
        raise ValueError('Unreviewed overlay or COFF symbol data')
    if any(s.PointerToRelocations or s.NumberOfRelocations or s.PointerToLinenumbers or s.NumberOfLinenumbers for s in p.sections):
        raise ValueError('Unreviewed section auxiliary records')
    base_plan = preview(data,flow,text_append_size=text_append_size)
    layout = Layout(p,base_plan['regions'])
    fields,blobs,import_rows,resources,unwinds = [],{},[],[],{}
    used = set()
    def read(rva,size):
        offset = p.get_offset_from_rva(rva)
        raw = data[offset:offset+size]
        if len(raw)!=size:
            raise ValueError('Truncated input metadata')
        return raw
    def scalar(kind,site,width,value,reason,conditional=False):
        raw = read(site,width)
        old = int.from_bytes(raw,'little')
        if not 0<=value<1<<(8*width):
            raise ValueError('Metadata value does not fit field')
        addresses = set(range(site,site+width))
        if used & addresses:
            raise ValueError('Duplicate/overlapping typed metadata field')
        used.update(addresses)
        fields.append(dict(kind=kind,old_site_rva=site,new_site_rva=layout.rva(site),
                           old_file_offset=p.get_offset_from_rva(site),new_file_offset=layout.new_file(site),
                           width=width,old_value=old,new_value=value,changes=old!=value,
                           reason=reason,conditional=conditional))
    def struct_field(obj,name,width,value,kind,reason,conditional=False):
        site = layout.file_to_rva(obj.get_field_absolute_offset(name))
        scalar(kind,site,width,value,reason,conditional)
    def rva_field(obj,name,kind,reason):
        value = getattr(obj,name)
        struct_field(obj,name,4,layout.rva(value) if value else 0,kind,reason)
    def preserve(kind,rva,size):
        raw = read(rva,size)
        key = (rva,size)
        if key not in blobs:
            blobs[key] = dict(old_rva=rva,new_rva=layout.rva(rva),size=size,
                              sha256=hashlib.sha256(raw).hexdigest(),roles=[])
        if kind not in blobs[key]['roles']:
            blobs[key]['roles'].append(kind)
    def string(kind,rva,prefix=0):
        raw = p.get_string_at_rva(rva+prefix,max_length=4096)
        if read(rva+prefix+len(raw),1)!=b'\0':
            raise ValueError('Unterminated metadata string')
        preserve(kind,rva,prefix+len(raw)+1)
        return raw.decode('ascii')

    # Rebuild the relocation directory from translated relocation sites, retaining
    # absolute pointer VALUE patches in the separate instruction/layout preview.
    sites = [layout.rva(e.rva) for b in p.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type==10]
    if any(e.type not in (0,10) for b in p.DIRECTORY_ENTRY_BASERELOC for e in b.entries):
        raise ValueError('Unsupported original relocation type')
    relocation_blocks = regroup_relocations(sites)
    relocation_size = sum(b['size'] for b in relocation_blocks)
    reloc_dir = p.OPTIONAL_HEADER.DATA_DIRECTORY[5]
    reloc_section = p.get_section_by_rva(reloc_dir.VirtualAddress)
    if relocation_size>reloc_section.Misc_VirtualSize:
        raise ValueError('Relocation rebuild exceeds retained virtual capacity')
    if any(read(reloc_dir.VirtualAddress+reloc_dir.Size,reloc_section.Misc_VirtualSize-reloc_dir.Size)):
        raise ValueError('Relocation tail contains unexplained nonzero data')

    # Address and size are independently typed for every directory slot.
    allowed = {1,2,3,5,6,12}
    for index,d in enumerate(p.OPTIONAL_HEADER.DATA_DIRECTORY):
        if (d.VirtualAddress or d.Size) and index not in allowed:
            raise ValueError('Unreviewed nonempty directory '+str(index))
        struct_field(d,'VirtualAddress',4,layout.rva(d.VirtualAddress) if d.VirtualAddress else 0,
                     'directory_file_offset' if index==4 else 'directory_rva',
                     'Certificate slot is a file offset; absent in this original.' if index==4 else 'Translate directory root; retain absent roots as zero.')
        struct_field(d,'Size',4,relocation_size if index==5 else d.Size,'directory_size',
                     'Use semantic relocation block size.' if index==5 else 'Retain payload length.')

    # Unbound import descriptors and the independent INT/IAT arrays.
    for dll in p.DIRECTORY_ENTRY_IMPORT:
        d = dll.struct
        if not d.OriginalFirstThunk or d.TimeDateStamp or d.ForwarderChain:
            raise ValueError('Only reviewed unbound imports are supported')
        for name in ('OriginalFirstThunk','Name','FirstThunk'):
            rva_field(d,name,'import_descriptor_rva','Translate import descriptor RVA.')
        dll_name = string('import_dll_name',d.Name)
        symbols = []
        for n in range(len(dll.imports)):
            oft,iat = d.OriginalFirstThunk+8*n,d.FirstThunk+8*n
            value = int.from_bytes(read(oft,8),'little')
            if value==0 or int.from_bytes(read(iat,8),'little')!=value:
                raise ValueError('Unexpected bound/short import thunk array')
            if value & (1<<63):
                if value & ~((1<<63)|0xffff):
                    raise ValueError('Invalid ordinal import encoding')
                new,symbol = value,dict(ordinal=value & 0xffff)
            else:
                new = layout.rva(value)
                symbol = dict(name=string('hint_name',value,2),hint=int.from_bytes(read(value,2),'little'))
            scalar('import_lookup_thunk',oft,8,new,'Map hint/name RVA; preserve ordinal flag and ordinal.')
            scalar('import_address_thunk',iat,8,new,'Map original unbound IAT hint/name RVA; loader later resolves it.')
            symbols.append(dict(**symbol,old_lookup_rva=oft,new_lookup_rva=layout.rva(oft),
                                old_iat_rva=iat,new_iat_rva=layout.rva(iat)))
        for start in (d.OriginalFirstThunk,d.FirstThunk):
            end = start+8*len(dll.imports)
            if any(read(end,8)):
                raise ValueError('Missing null import thunk')
            preserve('null_thunk',end,8)
        import_rows.append(dict(dll=dll_name,symbols=symbols))
    terminator = p.OPTIONAL_HEADER.DATA_DIRECTORY[1].VirtualAddress+20*len(import_rows)
    if any(read(terminator,20)):
        raise ValueError('Missing import descriptor terminator')
    preserve('null_import_descriptor',terminator,20)

    # Resource tree links are root-relative, while leaf data addresses are RVAs.
    root = p.OPTIONAL_HEADER.DATA_DIRECTORY[2].VirtualAddress
    def walk_resource(directory,path=()):
        preserve('resource_directory_header',layout.file_to_rva(directory.struct.get_file_offset()),16)
        for entry in directory.entries:
            label = str(entry.name) if entry.name else entry.id
            node = path+(label,)
            preserve('resource_root_relative_link',layout.file_to_rva(entry.struct.get_file_offset()),8)
            if entry.name:
                offset = entry.struct.Name & 0x7fffffff
                length = int.from_bytes(read(root+offset,2),'little')
                preserve('resource_utf16_name',root+offset,2+length*2)
            if hasattr(entry,'directory'):
                walk_resource(entry.directory,node)
            else:
                leaf = entry.data.struct
                rva_field(leaf,'OffsetToData','resource_payload_rva','Translate leaf payload RVA; tree-relative links stay unchanged.')
                preserve('resource_leaf_scalars',layout.file_to_rva(leaf.get_file_offset())+4,12)
                preserve('resource_payload',leaf.OffsetToData,leaf.Size)
                resources.append(dict(path=list(node),old_payload_rva=leaf.OffsetToData,
                                      new_payload_rva=layout.rva(leaf.OffsetToData),size=leaf.Size))
    walk_resource(p.DIRECTORY_ENTRY_RESOURCE)

    # Debug file pointer and RVA deliberately have different translation rules.
    debug_rows = []
    for item in p.DIRECTORY_ENTRY_DEBUG:
        d = item.struct
        if d.Type!=2 or read(d.AddressOfRawData,4)!=b'RSDS':
            raise ValueError('Unreviewed debug record format')
        if layout.file_to_rva(d.PointerToRawData)!=d.AddressOfRawData:
            raise ValueError('Debug raw pointer and RVA identify different payloads')
        rva_field(d,'AddressOfRawData','debug_payload_rva','Translate mapped CodeView payload address.')
        struct_field(d,'PointerToRawData',4,layout.new_file(d.AddressOfRawData),'debug_payload_file_offset',
                     'Translate raw file pointer independently from RVA.')
        preserve('debug_header_scalars',layout.file_to_rva(d.get_file_offset()),20)
        preserve('codeview_rsds_payload',d.AddressOfRawData,d.SizeOfData)
        debug_rows.append(dict(old_rva=d.AddressOfRawData,new_rva=layout.rva(d.AddressOfRawData),
                               old_file_offset=d.PointerToRawData,new_file_offset=layout.new_file(d.AddressOfRawData),size=d.SizeOfData))

    # Decode each unique unwind record once, preserving shared records and frame
    # offsets while translating all true RVA-bearing fields.
    semantic = review(data,flow)
    known_payloads = {h['payload']:h['cookie_offset'] for h in semantic['handlers']}
    function_rows = []
    frame_rows = {f['function']['begin']:f for f in frames(flow)}
    for e in p.DIRECTORY_ENTRY_EXCEPTION:
        f = e.struct
        if f.UnwindData & 3:
            raise ValueError('Unreviewed runtime-function unwind encoding')
        for name,value in [('BeginAddress',layout.rva(f.BeginAddress)),
                           ('EndAddress',layout.end(f.EndAddress,f.BeginAddress)),
                           ('UnwindData',layout.rva(f.UnwindData))]:
            struct_field(f,name,4,value,'runtime_function_rva','Translate function boundary/unwind RVA; EndAddress is exclusive.')
        if f.UnwindData not in unwinds:
            head = read(f.UnwindData,4)
            record = decode_unwind(head,read(f.UnwindData+4,head[2]*2))
            size = 4+align(head[2],2)*2
            tail = f.UnwindData+size
            preserve('unwind_header_codes_and_alignment',f.UnwindData,size)
            flags = record['flags']
            if flags not in (0,3):
                raise ValueError('Unreviewed handler/chain flags; refuse generic metadata rewriting')
            if flags:
                handler = int.from_bytes(read(tail,4),'little')
                payload = tail+4
                if handler!=0xfde4 or payload not in known_payloads:
                    raise ValueError('Unknown handler-specific payload')
                scalar('unwind_handler_rva',tail,4,layout.rva(handler),'Translate handler RVA, not its frame-relative cookie payload.')
                preserve('gs_cookie_stack_offset',payload,4)
                record.update(handler_rva=handler,new_handler_rva=layout.rva(handler),payload_rva=payload,
                              cookie_offset=known_payloads[payload])
            unwinds[f.UnwindData] = dict(old_rva=f.UnwindData,new_rva=layout.rva(f.UnwindData),**record)
        record = unwinds[f.UnwindData]
        prolog_end = f.BeginAddress+record['prolog_size']
        height = frame_rows[f.BeginAddress]['heights'].get(prolog_end)
        if height is None or -height!=record['stack_size']:
            raise ValueError('Unwind stack allocation disagrees with decoded prologue at '+hex(f.BeginAddress))
        function_rows.append(dict(old_begin=f.BeginAddress,new_begin=layout.rva(f.BeginAddress),
                                  old_end=f.EndAddress,new_end=layout.end(f.EndAddress,f.BeginAddress),
                                  old_unwind=f.UnwindData,new_unwind=layout.rva(f.UnwindData),
                                  prologue_stack_bytes=-height))
    if [f['new_begin'] for f in function_rows]!=sorted(f['new_begin'] for f in function_rows):
        raise ValueError('Runtime function table would not remain sorted')

    # Header/layout-dependent scalars; unrelated flags and source identity stay
    # unchanged. INIT's permission field is explicitly conditional, not approved.
    oh = p.OPTIONAL_HEADER
    header_values = dict(SectionAlignment=0x1000,FileAlignment=0x200,
        SizeOfHeaders=align(oh.SizeOfHeaders,0x200),SizeOfImage=base_plan['proposed_size_of_image'],
        AddressOfEntryPoint=layout.rva(oh.AddressOfEntryPoint),BaseOfCode=layout.rva(oh.BaseOfCode),
        SizeOfCode=sum(r['new_raw_size'] for r,s in zip(layout.regions,p.sections) if s.Characteristics & 0x20),
        SizeOfInitializedData=sum(r['new_raw_size'] for r,s in zip(layout.regions,p.sections) if s.Characteristics & 0x40),
        SizeOfUninitializedData=sum(s.Misc_VirtualSize for s in p.sections if s.Characteristics & 0x80))
    for name,value in header_values.items():
        struct_field(oh,name,4,value,'optional_header_layout','Recompute from proposed aligned section layout.')
    for r,s in zip(layout.regions,p.sections):
        if r['new_virtual_size']!=s.Misc_VirtualSize:
            struct_field(s,'Misc_VirtualSize',4,r['new_virtual_size'],'section_virtual_size',
                         'Include appended code while preserving all original virtual bytes.')
        for name,value in dict(VirtualAddress=r['new_begin'],PointerToRawData=r['new_raw_offset'],
                               SizeOfRawData=r['new_raw_size']).items():
            struct_field(s,name,4,value,'section_header_layout','Translate section location or round raw size to file alignment.')
        struct_field(s,'Characteristics',4,r['proposed_flags'],'section_permissions',
                     'Conditional INIT RX proposal; complete permission review required.' if r['flags_condition'] else 'Retain original residency and access flags.',
                     bool(r['flags_condition']))
    # Check metadata field locations against the prior operand/pointer inventory.
    operand_sites = {at for f in base_plan['fixups'] for at in range(f['site'],f['site']+f['width'])}
    if used & operand_sites:
        raise ValueError('Metadata patches overlap prior operand/pointer patches')
    file_size = max(r['new_raw_offset']+r['new_raw_size'] for r in layout.regions)
    return dict(sha256=SHA256,emission_allowed=False,layout=base_plan['regions'],
                copy_policy='Future writer must preserve all original header/raw bytes except declared field patches and relocation-directory rebuild; zero only newly introduced padding.',
                header_values=header_values,proposed_unsigned_file_size=file_size,
                fields=fields,preserved_blobs=list(blobs.values()),imports=import_rows,
                resources=resources,debug=debug_rows,runtime_functions=function_rows,
                unwind_records=[unwinds[k] for k in sorted(unwinds)],
                relocation_rebuild=dict(old_directory_rva=reloc_dir.VirtualAddress,
                    new_directory_rva=layout.rva(reloc_dir.VirtualAddress),old_size=reloc_dir.Size,new_size=relocation_size,
                    virtual_capacity=reloc_section.Misc_VirtualSize,blocks=relocation_blocks,
                    reason='Relocation sites cross different 4-KiB pages after section movement; regroup and add ABSOLUTE padding as needed.'),
                deferred=[dict(kind='checksum',original=oh.CheckSum,reason='Compute only over the final serialized candidate.'),
                          dict(kind='padding',reason='Writer must zero newly introduced header/raw padding deterministically.'),
                          dict(kind='signatures',reason='Any rebuilt package needs a new accepted signing/catalog route.')],
                blockers=['INIT permission change remains conditional.',
                          'NX allocation transformations and remaining affected-reference/alias review are incomplete.',
                          'No writer, new wrapper code/unwind records or candidate comparison exists yet.',
                          'Complete metadata planning is not driver equivalence or HVCI certification.'],
                summary=dict(typed_fields=len(fields),changed_fields=sum(x['changes'] for x in fields),
                    preserved_blobs=len(blobs),import_symbols=sum(len(d['symbols']) for d in import_rows),
                    runtime_functions=len(function_rows),unique_unwind_records=len(unwinds),
                    relocation_blocks=len(relocation_blocks),relocation_directory_size=relocation_size,
                    unwind_operations=dict(Counter(op['operation'] for r in unwinds.values() for op in r['operations']))))


if __name__=='__main__':
    source = Path('Files/64bit/Files/RDWM1064.SYS')
    before = source.read_bytes()
    result = plan(before,discover(before))
    Path('reports/metadata-plan.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    if source.read_bytes()!=before:
        raise RuntimeError('Original changed during metadata planning')
    print(json.dumps(result['summary'],indent=2))
