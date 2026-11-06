import hashlib
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from control_flow import discover
from trace_calls import Slice, trace, const


def reg(name,size=8):
    return dict(kind='register',register=name,size=size,access=3)


def mem(offset,size=8,base='rsp'):
    return dict(kind='memory',base=base,index=None,displacement=offset,size=size,access=3)


def imm(value):
    return dict(kind='immediate',value=value,size=4,access=1)


def instruction(mnemonic,*ops,at=0,writes=()):
    return dict(rva=at,mnemonic=mnemonic,operands=list(ops),registers_written=list(writes),size=1)


class SliceSafetyTests(unittest.TestCase):
    def test_call_invalidates_local_memory_and_volatile_registers(self):
        s = Slice(0)
        s.step(instruction('mov',reg('ecx',4),imm(7)))
        s.step(instruction('mov',mem(0x20,4),imm(9)))
        s.after_call(10)
        self.assertNotEqual(s.reg('ecx'),const(7))
        self.assertNotEqual(s.load(('stack_address',0x20),4),const(9))

    def test_overlapping_store_invalidates_wider_value(self):
        s = Slice(0)
        s.step(instruction('mov',mem(0x20),imm(0x1234)))
        s.step(instruction('mov',mem(0x22,1),imm(0xff)))
        self.assertNotEqual(s.load(('stack_address',0x20),8),const(0x1234))

    def test_unknown_aliasing_store_invalidates_stack_fact(self):
        s = Slice(0)
        s.step(instruction('mov',mem(0x20,4),imm(7)))
        s.step(instruction('mov',mem(0,4,base='rax'),imm(5)))
        self.assertNotEqual(s.load(('stack_address',0x20),4),const(7))

    def test_fifth_argument_survives_known_prologue_adjustment(self):
        s = Slice(0,formal_entry=True)
        s.step(instruction('push',reg('rdi')))
        s.step(instruction('sub',reg('rsp'),imm(0x50)))
        s.step(instruction('mov',reg('ecx',4),mem(0x80,4)))
        self.assertEqual(s.reg('ecx'),('low_bits',32,('argument',5)))

    def test_partial_register_write_does_not_invent_upper_bits(self):
        s = Slice(0)
        s.step(instruction('mov',reg('rax'),imm(0x12345678)))
        s.step(instruction('mov',reg('al',1),imm(7)))
        self.assertEqual(s.reg('rax')[0],'unknown')
        self.assertEqual(s.reg('ah')[0],'unknown')

    def test_join_does_not_select_last_address_order_assignment(self):
        # Two paths provide different ECX values. The join is independently
        # analyzed and must not claim the value from whichever path is last.
        data = b'synthetic slice test'
        inst = [instruction('mov',reg('ecx',4),imm(7),at=0),
                instruction('jne',imm(4),at=1),
                instruction('mov',reg('ecx',4),imm(9),at=2),
                instruction('jmp',imm(4),at=3),
                instruction('call',reg('rax'),at=4)]
        flow = dict(sha256=hashlib.sha256(data).hexdigest(),instructions=inst,
                    runtime_functions=[dict(begin=0,end=5)],seeds=[dict(rva=0)],
                    edges=[dict(source=1,target=4,kind='jump',direct=True),
                           dict(source=3,target=4,kind='jump',direct=True),
                           dict(source=4,target=None,kind='call',direct=False)])
        value = trace(data,flow)['calls'][0]['register_arguments']['rcx']
        self.assertNotIn(value,(const(7),const(9)))


class DriverSliceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.data = (Path(__file__).resolve().parents[1]/'Files/64bit/Files/RDWM1064.SYS').read_bytes()
        cls.flow = discover(cls.data)
        cls.result = trace(cls.data,cls.flow)
        cls.calls = {c['source']:c for c in cls.result['calls']}

    def test_all_discovered_calls_receive_exactly_one_slice(self):
        expected = {i['rva'] for i in self.flow['instructions'] if i['mnemonic']=='call'}
        self.assertEqual(set(self.calls),expected)
        self.assertEqual(len(self.calls),len(self.result['calls']))

    def test_stack_derived_pool_types_are_distinct_arguments(self):
        self.assertEqual(self.calls[0x8688]['register_arguments']['rcx'],('low_bits',32,('argument',4)))
        self.assertEqual(self.calls[0xf95b]['register_arguments']['rcx'],('low_bits',32,('argument',5)))

    def test_candidate_virtual_allocator_call_has_zero_fifth_low32(self):
        c = self.calls[0xfac6]
        self.assertEqual(c['stack_arguments'][0]['low32'],const(0))
        self.assertIsNone(c['direct_target'])
        # Deliberately do not claim the call is resolved to F930.
        self.assertEqual(c['target_expression'][0],'memory')

    def test_mismatched_flow_map_is_rejected(self):
        with self.assertRaises(ValueError):
            trace(self.data+b'changed',self.flow)


if __name__=='__main__':
    unittest.main()
