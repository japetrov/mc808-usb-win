"""Original/candidate byte, instruction, metadata and dual-parser comparisons.

Successful static comparison is not a Windows loader or HVCI certification.
"""
import hashlib
import json
from pathlib import Path

import capstone
from capstone.x86 import X86_OP_REG,X86_OP_IMM,X86_OP_MEM,X86_REG_RIP
import lief
import pefile
from control_flow import discover
from metadata_plan import Layout,decode_unwind
from nx_manifest import manifest
from reviewed_regions import SHA256


def require(condition,message):
    if not condition:
        raise ValueError(message)


def imports(pe):
    return [(d.dll.decode(),[(i.name.decode() if i.name else None,i.ordinal,i.hint) for i in d.imports])
            for d in pe.DIRECTORY_ENTRY_IMPORT]


def resources(pe):
    result = []
    def walk(d,path=()):
        for e in d.entries:
            at = path+(str(e.name) if e.name else e.id,)
            if hasattr(e,'directory'):
                walk(e.directory,at)
            else:
                s = e.data.struct
                result.append((at,s.Size,s.CodePage,pe.get_data(s.OffsetToData,s.Size)))
    walk(pe.DIRECTORY_ENTRY_RESOURCE)
    return result


def compare(original,candidate,design):
    require(hashlib.sha256(original).hexdigest()==SHA256 and design['sha256']==SHA256,'Original hash mismatch')
    require(len(candidate)==design['proposed_unsigned_file_size'],'Candidate file size differs')
    old,new = pefile.PE(data=original),pefile.PE(data=candidate)
    layout = Layout(old,design['layout'])
    checksum_offset = old.OPTIONAL_HEADER.get_field_absolute_offset('CheckSum')
    allowed = set(range(checksum_offset,checksum_offset+4))
    for a in design['actions']:
        value = bytes.fromhex(a['new_bytes'])
        start = a['target_file_offset']
        require(candidate[start:start+len(value)]==value,'Manifest action mismatch at '+hex(start))
        require(not allowed & set(range(start,start+len(value))),'Overlapping candidate action')
        allowed.update(range(start,start+len(value)))
    # Verify every copied original byte and every zero extension independently of
    # the writer's buffer construction; require exact coverage of the whole file.
    checked = set()
    for c in design['copies']:
        start,size = c['target_file_offset'],c['size']
        for i in range(size+c['zero_extension']):
            target = start+i
            require(target not in checked,'Overlapping comparison baseline')
            checked.add(target)
            if target not in allowed:
                expected = original[c['source_file_offset']+i] if i<size else 0
                require(candidate[target]==expected,'Unexplained candidate byte at '+hex(target))
    require(len(checked)==len(candidate),'Candidate has uncovered bytes')
    require(new.OPTIONAL_HEADER.CheckSum==new.generate_checksum(),'Invalid final PE checksum')
    require(new.FILE_HEADER.Machine==0x8664 and new.OPTIONAL_HEADER.Magic==0x20b,'Architecture changed')
    for name,value in design['header_values'].items():
        require(getattr(new.OPTIONAL_HEADER,name)==value,'Header mismatch '+name)
    require(new.OPTIONAL_HEADER.ImageBase==old.OPTIONAL_HEADER.ImageBase,'Preferred base changed')
    require(new.OPTIONAL_HEADER.DllCharacteristics==old.OPTIONAL_HEADER.DllCharacteristics,'Unexplained DLL flags')
    require(new.FILE_HEADER.NumberOfSections==len(design['layout']),'Section count mismatch')
    pages = {}
    for s,r in zip(new.sections,design['layout']):
        require(s.Name.rstrip(b'\0').decode()==r['name'],'Section name changed')
        require(s.VirtualAddress==r['new_begin'] and s.PointerToRawData==r['new_raw_offset'],'Section address mismatch')
        require(s.Misc_VirtualSize==r['new_virtual_size'] and s.SizeOfRawData==r['new_raw_size'],'Section size mismatch')
        require(s.Characteristics==r['proposed_flags'],'Section permission mismatch')
        require(s.VirtualAddress%0x1000==0 and s.PointerToRawData%0x200==0 and s.SizeOfRawData%0x200==0,'Bad section alignment')
        require(not (s.Characteristics & 0x20000000 and s.Characteristics & 0x80000000),'Writable/executable section')
        require(s.PointerToRawData+s.SizeOfRawData<=len(candidate),'Section outside file')
        for page in range(s.VirtualAddress//4096,(s.VirtualAddress+max(s.Misc_VirtualSize,s.SizeOfRawData)+4095)//4096):
            require(page not in pages,'Sections share a mapped page')
            pages[page] = r['name']
    require(imports(old)==imports(new),'Import identity changed')
    require(resources(old)==resources(new),'Resource payload/identity changed')
    for index,(a,b) in enumerate(zip(old.OPTIONAL_HEADER.DATA_DIRECTORY,new.OPTIONAL_HEADER.DATA_DIRECTORY)):
        require(b.VirtualAddress==(layout.rva(a.VirtualAddress) if a.VirtualAddress else 0),'Directory root mismatch')
        require(b.Size==(0x1b8 if index==5 else a.Size),'Directory size mismatch')
    for b in design['preserved_blobs']:
        require(hashlib.sha256(new.get_data(b['new_rva'],b['size'])).hexdigest()==b['sha256'],'Preserved metadata differs')
    for a,b in zip(old.DIRECTORY_ENTRY_DEBUG,new.DIRECTORY_ENTRY_DEBUG):
        require(b.struct.AddressOfRawData==layout.rva(a.struct.AddressOfRawData),'Debug RVA differs')
        require(b.struct.PointerToRawData==layout.new_file(a.struct.AddressOfRawData),'Debug file pointer differs')
        require(candidate[b.struct.PointerToRawData:b.struct.PointerToRawData+b.struct.SizeOfData]==old.get_data(a.struct.AddressOfRawData,a.struct.SizeOfData),'Debug bytes differ')
    relocation_sites = sorted(e.rva for b in new.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type==10)
    expected_sites = sorted(layout.rva(e.rva) for b in old.DIRECTORY_ENTRY_BASERELOC for e in b.entries if e.type==10)
    require(relocation_sites==expected_sites,'Relocation sites differ')
    require(all(e.type in (0,10) for b in new.DIRECTORY_ENTRY_BASERELOC for e in b.entries),'Unexpected relocation type')
    for b in old.DIRECTORY_ENTRY_BASERELOC:
        for e in b.entries:
            if e.type!=10:
                continue
            old_value = int.from_bytes(old.get_data(e.rva,8),'little')
            new_value = int.from_bytes(new.get_data(layout.rva(e.rva),8),'little')
            require(new_value==old.OPTIONAL_HEADER.ImageBase+layout.rva(old_value-old.OPTIONAL_HEADER.ImageBase),'Relocation pointer identity changed')
    require(len(new.DIRECTORY_ENTRY_EXCEPTION)==len(old.DIRECTORY_ENTRY_EXCEPTION),'Runtime function count changed')
    for a,b in zip(old.DIRECTORY_ENTRY_EXCEPTION,new.DIRECTORY_ENTRY_EXCEPTION):
        a,b = a.struct,b.struct
        require((b.BeginAddress,b.EndAddress,b.UnwindData)==(layout.rva(a.BeginAddress),layout.end(a.EndAddress,a.BeginAddress),layout.rva(a.UnwindData)),'Runtime-function metadata differs')
        head = old.get_data(a.UnwindData,4)
        size = 4+((head[2]+1)//2)*4
        require(new.get_data(b.UnwindData,size)==old.get_data(a.UnwindData,size),'Unwind codes/frame changed')
        decoded = decode_unwind(head,old.get_data(a.UnwindData+4,head[2]*2))
        if decoded['flags']:
            tail_old,tail_new = a.UnwindData+size,b.UnwindData+size
            require(int.from_bytes(new.get_data(tail_new,4),'little')==layout.rva(int.from_bytes(old.get_data(tail_old,4),'little')),'Unwind handler differs')
            require(new.get_data(tail_new+4,4)==old.get_data(tail_old+4,4),'Handler cookie payload changed')
    # Decode actual candidate instructions and compare all original operands.
    flow = discover(original)
    md = capstone.Cs(capstone.CS_ARCH_X86,capstone.CS_MODE_64)
    md.detail = True
    redirects = {r['source_rva']:r for r in design['redirects']}
    switch_sites = {a['source_rva'] for a in design['actions'] if a['kind']=='imagebase_indexed_displacement'}
    compared = 0
    for row in flow['instructions']:
        rva = row['rva']
        mapped = layout.rva(rva)
        o = next(md.disasm(old.get_data(rva,row['size']),old.OPTIONAL_HEADER.ImageBase+rva,count=1))
        n = next(md.disasm(new.get_data(mapped,row['size']),new.OPTIONAL_HEADER.ImageBase+mapped,count=1),None)
        require(n is not None,'Candidate instruction fails decoding')
        if rva in redirects:
            require(n.mnemonic=='call' and n.size==5 and n.operands[0].imm-new.OPTIONAL_HEADER.ImageBase==redirects[rva]['shim_rva'],'Call redirect differs')
            require(new.get_data(mapped+5,1)==b'\x90','Call continuation NOP missing')
            continue
        require(o.id==n.id and o.size==n.size and len(o.operands)==len(n.operands),'Instruction identity/size differs at '+hex(rva))
        branch = o.group(capstone.CS_GRP_CALL) or o.group(capstone.CS_GRP_JUMP) or o.mnemonic.startswith('loop')
        for a,b in zip(o.operands,n.operands):
            require(a.type==b.type and a.size==b.size,'Operand shape changed')
            if a.type==X86_OP_REG:
                require(a.reg==b.reg,'Register operand changed')
            elif a.type==X86_OP_IMM:
                expected = old.OPTIONAL_HEADER.ImageBase+layout.rva(a.imm-old.OPTIONAL_HEADER.ImageBase) if branch else a.imm
                require(b.imm==expected,'Immediate/branch target changed')
            elif a.type==X86_OP_MEM:
                require((a.mem.base,a.mem.index,a.mem.scale,a.mem.segment)==(b.mem.base,b.mem.index,b.mem.scale,b.mem.segment),'Memory address shape changed')
                if a.mem.base==X86_REG_RIP:
                    target = o.address+o.size+a.mem.disp-old.OPTIONAL_HEADER.ImageBase
                    require(n.address+n.size+b.mem.disp-new.OPTIONAL_HEADER.ImageBase==layout.rva(target),'RIP target differs')
                elif rva+o.disp_offset in switch_sites:
                    require(b.mem.disp==layout.rva(a.mem.disp),'Indexed switch displacement differs')
                else:
                    require(a.mem.disp==b.mem.disp,'Object/stack displacement changed')
        compared += 1
    for s in design['shims']:
        require(new.get_data(s['rva'],16)==bytes.fromhex(s['bytes']),'Candidate shim bytes differ from native/emulated design')
    # Independent parser checks: no use of LIEF's writer/reconstruction functions.
    config = lief.PE.ParserConfig()
    config.parse_exceptions = True
    other = lief.PE.parse(candidate,config)
    require(other is not None,'Independent LIEF parse failed')
    require(len(other.sections)==len(new.sections),'Independent section count differs')
    for a,b in zip(other.sections,new.sections):
        require((a.name,a.virtual_address,a.pointerto_raw_data,a.sizeof_raw_data,a.virtual_size,int(a.characteristics))==
                (b.Name.rstrip(b'\0').decode(),b.VirtualAddress,b.PointerToRawData,b.SizeOfRawData,b.Misc_VirtualSize,b.Characteristics),'Independent section interpretation differs')
    independent_imports = [(d.name,[(i.name if not i.is_ordinal else None,i.ordinal if i.is_ordinal else None) for i in d.entries]) for d in other.imports]
    expected_imports = [(d.dll.decode(),[(i.name.decode() if i.name else None,i.ordinal) for i in d.imports]) for d in new.DIRECTORY_ENTRY_IMPORT]
    require(independent_imports==expected_imports,'Independent import interpretation differs')
    require(other.optional_header.addressof_entrypoint==new.OPTIONAL_HEADER.AddressOfEntryPoint,'Independent entry point differs')
    require(other.optional_header.sizeof_image==new.OPTIONAL_HEADER.SizeOfImage,'Independent image size differs')
    independent_exceptions = [(e.rva_start,e.rva_end,e.unwind_rva) for e in other.exceptions]
    expected_exceptions = [(e.struct.BeginAddress,e.struct.EndAddress,e.struct.UnwindData) for e in new.DIRECTORY_ENTRY_EXCEPTION]
    require(independent_exceptions==expected_exceptions,'Independent exception interpretation differs')
    independent_relocations = sorted(e.address for b in other.relocations for e in b.entries if int(e.type)==10)
    require(independent_relocations==relocation_sites,'Independent relocation interpretation differs')
    require(other.optional_header.checksum==new.OPTIONAL_HEADER.CheckSum,'Independent checksum field differs')
    require(new.get_overlay_data_start_offset() is None,'Unexpected candidate overlay')
    require(not new.get_warnings(),'Candidate PE parser reports warnings: '+str(new.get_warnings()))
    return dict(passed=True,candidate_sha256=hashlib.sha256(candidate).hexdigest(),
                byte_coverage=len(candidate),preserved_instructions_compared=compared,
                intentional_call_redirects=len(redirects),import_symbols=56,relocation_sites=len(relocation_sites),
                runtime_functions=281,unique_unwind_records=len({e.struct.UnwindData for e in new.DIRECTORY_ENTRY_EXCEPTION}),
                pefile_version=pefile.__version__,lief_version=lief.__version__,checksum=new.OPTIONAL_HEADER.CheckSum,
                parser_warnings=new.get_warnings(),windows_loader_tested=False,hvci_compatibility_proven=False)


if __name__=='__main__':
    original = Path('Files/64bit/Files/RDWM1064.SYS').read_bytes()
    candidate = Path('build/experimental/RDWM1064.experimental.sys').read_bytes()
    result = compare(original,candidate,manifest(original,discover(original)))
    print(json.dumps(result,indent=2))
