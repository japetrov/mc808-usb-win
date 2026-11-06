"""Isolated Unicorn tests of call/shim fragments and a fake MOV/RET allocator.

No complete driver image, Windows kernel API or driver loading is involved.
"""
import json
import hashlib
from pathlib import Path
import struct

import unicorn
from unicorn import Uc,UC_ARCH_X86,UC_MODE_64,UC_HOOK_CODE
from unicorn import x86_const as x
from control_flow import discover
from nx_manifest import manifest


REGISTERS = {name:getattr(x,'UC_X86_REG_'+name.upper()) for name in
             ('rax','rbx','rcx','rdx','rsi','rdi','rbp','rsp','r8','r9','r10','r11','r12','r13','r14','r15')}


def run_fragment(call_rva,call_bytes,iat_rva,rcx,*,shim=None,image_base=0x10000,allocation_result=0):
    uc = Uc(UC_ARCH_X86,UC_MODE_64)
    # Direct virtual translation avoids the default physical-address-width mask
    # when testing canonical high kernel VAs. This is emulator configuration,
    # not guest/host page-table or Windows security configuration.
    uc.ctl_set_tlb_mode(unicorn.UC_TLB_VIRTUAL)
    uc.mem_map(image_base,0x20000)
    stack_base,api = 0x800000,0x500000
    uc.mem_map(stack_base,0x4000)
    uc.mem_map(api,0x1000)
    uc.mem_write(image_base+call_rva,call_bytes)
    uc.mem_write(image_base+iat_rva,struct.pack('<Q',api))
    if shim:
        uc.mem_write(image_base+shim['rva'],bytes.fromhex(shim['bytes']))
    # The API is a mock returning a selected pointer/NULL. This is the only
    # code at its address and does not invoke any host Windows functionality.
    uc.mem_write(api,b'\x48\xb8'+struct.pack('<Q',allocation_result)+b'\xc3')
    initial = {name:(0x1000000000000000+n*0x10101) for n,name in enumerate(REGISTERS)}
    initial.update(rcx=rcx,rdx=0x1234,r8=0x72436350,rsp=stack_base+0x1000)
    for name,value in initial.items():
        uc.reg_write(REGISTERS[name],value)
    uc.reg_write(x.UC_X86_REG_EFLAGS,2)
    stack_args = struct.pack('<QQQ',0x1122334455667788,0x8877665544332211,0x13579bdf2468ace0)
    uc.mem_write(initial['rsp']+0x20,stack_args)
    entries = []
    def hook(machine,address,size,_):
        if address==api:
            rsp = machine.reg_read(x.UC_X86_REG_RSP)
            entries.append(dict(registers={name:machine.reg_read(reg) for name,reg in REGISTERS.items()},
                                return_address=struct.unpack('<Q',machine.mem_read(rsp,8))[0],
                                stack_arguments=bytes(machine.mem_read(rsp+0x28,len(stack_args))).hex()))
    uc.hook_add(UC_HOOK_CODE,hook)
    uc.emu_start(image_base+call_rva,image_base+call_rva+6,timeout=1000000,count=32)
    if len(entries)!=1 or uc.reg_read(x.UC_X86_REG_RIP)!=image_base+call_rva+6:
        raise ValueError('Fragment did not return exactly once to the expected continuation')
    final = {name:uc.reg_read(reg) for name,reg in REGISTERS.items()}
    return dict(initial=initial,api_entry=entries[0],final=final,
                final_stack_arguments=bytes(uc.mem_read(initial['rsp']+0x20,len(stack_args))).hex())


def compare_redirect(design,redirect,pool,*,image_base=0x10000,allocation_result=0):
    action = next(a for a in design['actions'] if a['kind']=='nx_call_redirect' and a['source_rva']==redirect['source_rva'])
    shim = next(s for s in design['shims'] if s['rva']==redirect['shim_rva'])
    old = run_fragment(redirect['source_rva'],bytes.fromhex(action['old_bytes']),shim['old_iat_rva'],pool,
                       image_base=image_base,allocation_result=allocation_result)
    new = run_fragment(redirect['new_rva'],bytes.fromhex(action['new_bytes']),shim['iat_rva'],pool,
                       shim=shim,image_base=image_base,allocation_result=allocation_result)
    expected = 0x200 if pool & 0xffffffff==0 else pool
    if new['api_entry']['registers']['rcx']!=expected:
        raise ValueError('Unexpected PoolType conversion')
    for name in REGISTERS:
        if name!='rcx' and new['api_entry']['registers'][name]!=old['api_entry']['registers'][name]:
            raise ValueError('Shim changed API-entry register '+name)
        if name!='rcx' and new['final'][name]!=old['final'][name]:
            raise ValueError('Shim changed return register '+name)
    if new['final']['rsp']!=new['initial']['rsp'] or new['final']['rax']!=allocation_result:
        raise ValueError('Stack or allocation return value changed')
    if old['api_entry']['return_address']!=image_base+redirect['source_rva']+6:
        raise ValueError('Original CALL return address mismatch')
    if new['api_entry']['return_address']!=image_base+redirect['new_rva']+5:
        raise ValueError('Redirect CALL return address mismatch')
    if old['api_entry']['stack_arguments']!=new['api_entry']['stack_arguments'] or old['final_stack_arguments']!=new['final_stack_arguments']:
        raise ValueError('Stack arguments changed')
    return dict(pool=pool,expected_pool=expected,image_base=image_base,allocation_result=allocation_result)


def verify(design):
    values = [0,1,2,4,16,32,0x200,0x204,0x220,0x100,0x20000000,0xffffffff,
              0xaaaaaaaa00000000,0xaaaaaaaa00000001]
    count = 0
    for redirect in design['redirects']:
        for base in (0x10000,0x180000000,0xfffff80000000000):
            for value in values:
                for returned in (0,0x123456780):
                    compare_redirect(design,redirect,value,image_base=base,allocation_result=returned)
                    count += 1
    digest = hashlib.sha256(json.dumps(design,sort_keys=True,separators=(',',':')).encode()).hexdigest()
    return dict(engine='Unicorn '+unicorn.__version__,original_sha256=design['sha256'],manifest_sha256=digest,comparisons=count,
                redirects=len(design['redirects']),pool_inputs=len(values),load_bases=3,return_cases=2,
                driver_loaded=False,
                scope='Only original CALL fragments, proposed CALL/NOP/shim fragments, fake IAT pointers and a mock MOV/RET allocator are emulated.')


if __name__=='__main__':
    source = Path('Files/64bit/Files/RDWM1064.SYS')
    before = source.read_bytes()
    design = manifest(before,discover(before))
    result = verify(design)
    Path('reports/nx-emulation.json').write_text(json.dumps(result,indent=2),encoding='utf-8')
    if source.read_bytes()!=before:
        raise RuntimeError('Original changed during fragment emulation')
    print(json.dumps(result,indent=2))
