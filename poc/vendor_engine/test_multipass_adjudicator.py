import dataclasses
import unittest
from security_source import parse_security_source
from source_parse import SourceEvent,ValueSpan,assert_source_accounting
from multipass_contract import CandidateEvidence,candidate_from_event
try:
    from multipass_adjudicator import adjudicate_candidates,merge_source_events,parse_security_multipass
except ModuleNotFoundError:
    adjudicate_candidates=merge_source_events=parse_security_multipass=None


def ev(parser,tier,qualified=True):
    return CandidateEvidence(parser_id=parser,profile_id=None,grammar_id=parser,evidence_tier=tier,
        independently_qualified=qualified,source_revision='test',confidence_evidence=('test',))

class MultiPassAdjudicatorTests(unittest.TestCase):
    def test_non_target_security_json_is_base_identical(self):
        self.assertIsNotNone(parse_security_multipass)
        raw='{"action":"BLOCK","headers":[{"name":"x","value":"a=b"}]}'
        self.assertEqual(dataclasses.asdict(parse_security_source(raw)),dataclasses.asdict(parse_security_multipass(raw)))

    def test_cef_standard_candidate_wins_verified_boundary_conflict(self):
        raw='CEF:0|V|IPS|1|1|name|5|msg="quoted value"   act=deny'
        base=parse_security_source(raw);final=parse_security_multipass(raw)
        self.assertNotEqual(base.vendor_fields,final.vendor_fields)
        self.assertEqual('"quoted value"  ',final.vendor_fields['cef_extension']['msg'])
        self.assertIn('CEF_STANDARD',final.syntax)

    def test_leef_xhh_candidate_wins_unsupported_base(self):
        raw='LEEF:2.0|V|IPS|1|1|x7C|src=192.0.2.1|act=deny'
        base=parse_security_source(raw);final=parse_security_multipass(raw)
        self.assertNotEqual('SOURCE_PARSED',base.status)
        self.assertEqual('SOURCE_PARSED',final.status)
        self.assertEqual('deny',final.vendor_fields['leef_extension']['act'])

    def test_equal_evidence_overlap_conflict_stays_ambiguous(self):
        raw='abcdef'
        a=SourceEvent(raw,syntax='A',vendor_fields={'x':'bc'},value_spans=[ValueSpan('x',1,3,('x',))],covered=[(1,3)],unparsed=[(0,1),(3,6)],primitive_fields=1)
        b=SourceEvent(raw,syntax='B',vendor_fields={'y':'bcd'},value_spans=[ValueSpan('y',1,4,('y',))],covered=[(1,4)],unparsed=[(0,1),(4,6)],primitive_fields=1)
        decision=adjudicate_candidates((candidate_from_event(a,ev('a','QUALIFIED_STANDARD')),candidate_from_event(b,ev('b','QUALIFIED_STANDARD'))))
        self.assertTrue(decision.ambiguous);self.assertGreater(decision.conflict_count,0);self.assertEqual((),decision.accepted_parser_ids)

    def test_higher_independent_evidence_resolves_overlap(self):
        raw='abcdef'
        a=SourceEvent(raw,syntax='A',vendor_fields={'x':'bc'},value_spans=[ValueSpan('x',1,3,('x',))],covered=[(1,3)],unparsed=[(0,1),(3,6)],primitive_fields=1)
        b=SourceEvent(raw,syntax='B',vendor_fields={'y':'bcd'},value_spans=[ValueSpan('y',1,4,('y',))],covered=[(1,4)],unparsed=[(0,1),(4,6)],primitive_fields=1)
        decision=adjudicate_candidates((candidate_from_event(a,ev('a','QUALIFIED_BASE')),candidate_from_event(b,ev('b','QUALIFIED_STANDARD'))))
        self.assertFalse(decision.ambiguous);self.assertEqual(('b',),decision.accepted_parser_ids);self.assertEqual(('a',),decision.rejected_parser_ids)

    def test_nonoverlap_compatible_results_merge_without_unioning_conflicts(self):
        raw='a=1 b=2'
        a=SourceEvent(raw,syntax='A',vendor_fields={'a':'1'},value_spans=[ValueSpan('a',2,3,('a',))],covered=[(0,3)],unparsed=[(3,7)],primitive_fields=1)
        b=SourceEvent(raw,syntax='B',vendor_fields={'b':'2'},value_spans=[ValueSpan('b',6,7,('b',))],covered=[(4,7)],unparsed=[(0,4)],primitive_fields=1)
        final=merge_source_events(raw,{'a':a,'b':b},('a','b'))
        self.assertEqual({'a':'1','b':'2'},final.vendor_fields);self.assertEqual(2,len(final.value_spans));assert_source_accounting(final)

    def test_merge_rejects_incompatible_tree_ownership(self):
        raw='abcdef'
        a=SourceEvent(raw,syntax='A',vendor_fields={'obj':{'a':'bc'}},value_spans=[ValueSpan('obj.a',1,3,('obj','a'))],covered=[(1,3)],unparsed=[(0,1),(3,6)],primitive_fields=1)
        b=SourceEvent(raw,syntax='B',vendor_fields={'obj':'bcd'},value_spans=[ValueSpan('obj',1,4,('obj',))],covered=[(1,4)],unparsed=[(0,1),(4,6)],primitive_fields=1)
        with self.assertRaises(ValueError):merge_source_events(raw,{'a':a,'b':b},('a','b'))

if __name__=='__main__':unittest.main()
