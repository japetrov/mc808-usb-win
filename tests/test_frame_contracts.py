from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from control_flow import discover
from frame_map import frames, normalize, stack_effect
from helper_contracts import analyze
from trace_calls import Slice, const


def inst(at,m,ops=(),writes=()):
    return dict(rva=at,size=1,mnemonic=m,operands=list(ops),registers_written=list(writes))


class FrameSafetyTests(unittest.TestCase):
    def test_conflicting_stack_heights_become_unknown(self):
        flow = dict(instructions=[inst(0,'jne'),inst(1,'push'),inst(2,'jmp'),inst(3,'jmp'),inst(4,'ret')],
                    edges=[dict(source=s,target=t,kind=k) for s,t,k in
                           [(0,1,'fallthrough'),(0,3,'jump'),(1,2,'fallthrough'),(2,4,'jump'),(3,4,'jump')]],
                    runtime_functions=[dict(begin=0,end=5)])
        row = frames(flow)[0]
        self.assertTrue(row['conflicts'])
        self.assertIsNone(row['heights'][4])

    def test_unmodeled_stack_reassignment_is_not_treated_as_zero_effect(self):
        i = inst(0,'mov',[dict(kind='register',register='rsp'),dict(kind='register',register='rax')],['rsp'])
        self.assertIsNone(stack_effect(i))

    def test_overwritten_parameter_is_not_named_original_argument(self):
        flow = dict(instructions=[inst(0,'mov',[dict(kind='register',register='rcx'),dict(kind='immediate',value=7)],['rcx']),
                                 inst(1,'mov',[dict(kind='memory',base='rsp',displacement=8,size=8),dict(kind='register',register='rcx')])],
                    edges=[dict(source=0,target=1,kind='fallthrough')],runtime_functions=[dict(begin=0,end=2)])
        self.assertFalse(frames(flow)[0]['argument_home_origins'])

    def test_normalization_distinguishes_block_and_function_stack_offsets(self):
        self.assertEqual(normalize(('stack_address',0x20),-0x58),('entry_stack_address',-0x38))
        self.assertEqual(normalize(('stack_address',0x20),None)[0],'unknown')

    def test_imul_model_observes_register_width(self):
        s = Slice(0)
        s.registers['rax'] = const(0x80000000)
        i = inst(0,'imul',[dict(kind='register',register='eax',size=4),
                           dict(kind='register',register='eax',size=4),dict(kind='immediate',value=2)])
        s.step(i)
        self.assertEqual(s.reg('rax'),const(0))


class ContractTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.path = Path(__file__).resolve().parents[1]/'Files/64bit/Files/RDWM1064.SYS'
        cls.data = cls.path.read_bytes()
        cls.flow = discover(cls.data)
        cls.result = analyze(cls.data,cls.flow)

    def test_all_runtime_frames_and_all_ten_helper_callers_are_accounted_for(self):
        self.assertEqual(len(self.result['frames']),281)
        self.assertFalse(any(f['conflicts'] or f['unsupported'] for f in self.result['frames']))
        callers = {e['source'] for e in self.flow['edges'] if e['kind']=='call' and e['target']==0x820}
        self.assertEqual({r['call'] for r in self.result['helper_callers']},callers)

    def test_reused_local_slot_is_not_misrepresented_as_one_allocation(self):
        rows = {r['call']:r for r in self.result['helper_callers']}
        self.assertEqual(rows[0xb97f]['contract']['offset'],rows[0xbb70]['contract']['offset'])
        self.assertEqual(rows[0xbb70]['contract']['location'],'local_replacement')
        self.assertNotEqual(rows[0xb97f]['call'],rows[0xbb70]['call'])

    def test_method_pairs_have_explicit_identity_preconditions(self):
        pairs = self.result['field_method_pairs']
        self.assertEqual({p['offset'] for p in pairs},{0x28,0x30})
        self.assertTrue(all(p['preconditions'] for p in pairs))
        self.assertTrue(all(p['release_path']['chosen_branch_paths'] for p in pairs))

    def test_object_identity_path_remains_conditional(self):
        self.assertIn('conditional',self.result['object_identity_status'])
        self.assertTrue(all(p['assumptions'] for p in self.result['object_identity_path_summaries']))
        self.assertTrue(all(not c['nx_conversion_approved'] for c in self.result['helper_callers']))

    def test_original_is_unchanged(self):
        self.assertEqual(self.path.read_bytes(),self.data)


if __name__=='__main__':
    unittest.main()
