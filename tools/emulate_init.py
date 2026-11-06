"""Exercise the original and planned INIT code fragments on emulator RX pages.

DriverEntry's target body is replaced by a MOV EAX,0 / RET mock. No PE image is
serialized and no Windows loader, kernel API or real driver entry is invoked.
"""
import hashlib
import json
from pathlib import Path
import struct

from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE,UC_HOOK_MEM_WRITE
from unicorn import UC_PROT_READ,UC_PROT_WRITE,UC_PROT_EXEC,UC_TLB_VIRTUAL
from unicorn import x86_const as x
from control_flow import discover
from nx_manifest import manifest
from reviewed_regions import SHA256


DEFAULT_COOKIE = 0x2b992ddfa232
MASK64 = (1<<64)-1


def run_init(data,design,*,rebuilt=False,image_base=0x10000,cookie=0,tick=0):
    if hashlib.sha256(data).hexdigest()!=SHA256 or design['sha256']!=SHA256:
        raise ValueError('INIT fragment review requires original identity')
    old_start,end = 0x13080,0x13104
    fragment = bytearray(data[old_start:end])  # This original has raw offsets == RVAs.
    init_rva,cookie_rva,target = old_start,0x10b00,0xe7a0
    if rebuilt:
        regions = {r['name']:r for r in design['layout']}
        init_rva = regions['INIT']['new_begin']
        cookie_rva = regions['.data']['new_begin']+0x10b00-regions['.data']['old_begin']
        target = regions['.text']['new_begin']+0xe7a0-regions['.text']['old_begin']
        for a in design['actions']:
            source = a['source_rva']
            if source is not None and old_start<=source<end:
                old,new = bytes.fromhex(a['old_bytes']),bytes.fromhex(a['new_bytes'])
                offset = source-old_start
                if offset+len(old)>len(fragment) or fragment[offset:offset+len(old)]!=old:
                    raise ValueError('INIT expected bytes do not match')
                if a['target_rva']!=init_rva+offset:
                    raise ValueError('INIT translation is not contiguous')
                fragment[offset:offset+len(new)] = new
    uc = Uc(UC_ARCH_X86,UC_MODE_64)
    uc.ctl_set_tlb_mode(UC_TLB_VIRTUAL)
    code,cell,driver = image_base+init_rva,image_base+cookie_rva,image_base+target
    caller,stack,shared = image_base+0x30000,0x800000,0xfffff78000000000
    for address in (code & ~0xfff,cell & ~0xfff,driver & ~0xfff,caller):
        uc.mem_map(address,0x1000)
    uc.mem_map(stack,0x4000,UC_PROT_READ|UC_PROT_WRITE)
    uc.mem_map(shared,0x1000)
    uc.mem_write(code,bytes(fragment))
    uc.mem_write(cell,struct.pack('<QQ',cookie,0))
    tick_value = cell if tick=='force_fallback' else tick
    uc.mem_write(shared+0x320,struct.pack('<Q',tick_value))
    uc.mem_write(driver,b'\xb8\x00\x00\x00\x00\xc3')
    wrapper = code+0x64
    uc.mem_write(caller,b'\xe8'+struct.pack('<i',wrapper-(caller+5))+b'\x90')
    for address in (code & ~0xfff,driver & ~0xfff,caller):
        uc.mem_protect(address,0x1000,UC_PROT_READ|UC_PROT_EXEC)
    uc.mem_protect(shared,0x1000,UC_PROT_READ)
    uc.mem_protect(cell & ~0xfff,0x1000,UC_PROT_READ|UC_PROT_WRITE)
    initial_rsp = stack+0x1000
    uc.reg_write(x.UC_X86_REG_RSP,initial_rsp)
    uc.reg_write(x.UC_X86_REG_RCX,0x44440000)
    uc.reg_write(x.UC_X86_REG_RDX,0x55550000)
    uc.reg_write(x.UC_X86_REG_EFLAGS,2)
    entries,writes = [],[]
    def code_hook(machine,address,size,_):
        if address==driver:
            entries.append((machine.reg_read(x.UC_X86_REG_RCX),machine.reg_read(x.UC_X86_REG_RDX)))
    def write_hook(machine,access,address,size,value,_):
        if not stack<=address<stack+0x4000:
            writes.append(dict(address=address,size=size))
    uc.hook_add(UC_HOOK_CODE,code_hook)
    uc.hook_add(UC_HOOK_MEM_WRITE,write_hook)
    uc.emu_start(caller,caller+6,timeout=1000000,count=100)
    current,complement = struct.unpack('<QQ',uc.mem_read(cell,16))
    if entries!=[(0x44440000,0x55550000)] or uc.reg_read(x.UC_X86_REG_RSP)!=initial_rsp:
        raise ValueError('INIT wrapper did not preserve entry arguments/stack')
    if any(w['address'] not in (cell,cell+8) or w['size']!=8 for w in writes):
        raise ValueError('INIT wrote outside the two reviewed data cells')
    expected = cookie
    if cookie in (0,DEFAULT_COOKIE):
        expected = (tick_value ^ cell) & ((1<<48)-1)
        expected = expected or DEFAULT_COOKIE
    if current!=expected or complement!=(current ^ MASK64):
        raise ValueError('Cookie initialization relationship changed')
    return dict(rebuilt=rebuilt,image_base=image_base,initial_cookie=cookie,tick=tick,
                cookie=current,complement=complement,nonstack_writes=writes,init_page_rx=True,
                mock_driver_entry_calls=len(entries),final_status=uc.reg_read(x.UC_X86_REG_RAX))


def verify(data,design):
    results = []
    for rebuilt in (False,True):
        for base in (0x10000,0xfffff80000000000):
            for cookie in (0,DEFAULT_COOKIE,0x123456789abc):
                for tick in (0,0x1234abcd,0xffffffffffffffff,'force_fallback'):
                    results.append(run_init(data,design,rebuilt=rebuilt,image_base=base,cookie=cookie,tick=tick))
    return dict(original_sha256=SHA256,
                manifest_sha256=hashlib.sha256(json.dumps(design,sort_keys=True,separators=(',',':')).encode()).hexdigest(),
                cases=len(results),driver_loaded=False,results=results,
                conclusion='Reviewed INIT paths ran on emulator RX pages and wrote only cookie cells; indirect alias/loader behavior is not proven.')


if __name__=='__main__':
    path = Path('Files/64bit/Files/RDWM1064.SYS')
    data = path.read_bytes()
    design = manifest(data,discover(data))
    result = verify(data,design)
    Path('reports/init-emulation.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    if path.read_bytes()!=data:
        raise RuntimeError('Original changed during INIT emulation')
    print(json.dumps({k:result[k] for k in ('cases','driver_loaded','conclusion')},indent=2))
