import unittest
from security_source import parse_security_source
from source_parse import assert_source_accounting
try:
    from multipass_contract import CandidateEvidence,candidate_from_event
except ModuleNotFoundError:
    CandidateEvidence=candidate_from_event=None

class MultiPassContractTests(unittest.TestCase):
    def evidence(self,parser_id='security.base'):
        return CandidateEvidence(parser_id=parser_id,profile_id='pr16',grammar_id='security-source-v1',
            evidence_tier='QUALIFIED_BASE',independently_qualified=True,
            source_revision='9d3f1ff57f53aba8268b2ad216eecc67421dfa2a',
            confidence_evidence=('commercial-27968-exact','framing-6048-exact'))

    def test_current_event_is_represented_losslessly(self):
        self.assertIsNotNone(candidate_from_event)
        raw='{"a.b":1,"a":{"b":2},"items":["Zoë",null],"empty":[]}'
        event=parse_security_source(raw);assert_source_accounting(event)
        candidate=candidate_from_event(event,self.evidence())
        self.assertEqual(event.raw_sha256,candidate.raw_sha256)
        self.assertEqual(event.syntax,candidate.syntax)
        self.assertEqual(event.status,candidate.completeness)
        self.assertEqual(event.vendor_fields,candidate.field_tree)
        self.assertEqual(event.issues,list(candidate.issues))
        self.assertEqual([(s.path,s.source_segments,s.start_byte,s.end_byte) for s in event.value_spans],
                         [(s.display_path,s.source_segments,s.start_byte,s.end_byte) for s in candidate.occurrences])
        self.assertEqual(event.source_bytes,candidate.source_bytes)
        self.assertFalse(candidate.normalization_attempted)

    def test_repeated_native_occurrences_keep_order_values_types_and_spans(self):
        raw='CEF:0|V|P|1|42|Alert|5|tag=a tag=b msg="literal quote"'
        event=parse_security_source(raw);assert_source_accounting(event)
        candidate=candidate_from_event(event,self.evidence())
        tags=[x for x in candidate.occurrences if x.display_path=='cef_extension.tag']
        self.assertEqual([0,1],[x.occurrence for x in tags])
        self.assertEqual(['a','b'],[x.value for x in tags])
        self.assertEqual(['str','str'],[x.value_type for x in tags])
        self.assertLess(tags[0].start_byte,tags[1].start_byte)

    def test_covered_and_residual_regions_are_exact_utf8_bytes(self):
        raw='NOTICE prefix user=Zoë action=allow trailing prose'
        event=parse_security_source(raw);assert_source_accounting(event)
        candidate=candidate_from_event(event,self.evidence())
        data=raw.encode('utf8')
        for region in candidate.covered_regions+candidate.residual_regions:
            self.assertGreaterEqual(region.start_byte,0);self.assertLessEqual(region.end_byte,len(data))
            self.assertLess(region.start_byte,region.end_byte)
        self.assertGreater(len(candidate.residual_regions),0)

    def test_malformed_rfc5424_sd_never_exposes_orphan_candidate_spans(self):
        raw=(
            '<14>1 2026-10-15T00:00:00Z host RT_FLOW 1 MSG '
            '[junos@2636.1 reason=unset source-address="10.0.0.1"]'
        )
        event=parse_security_source(raw);assert_source_accounting(event)
        self.assertEqual('PARTIAL',event.status)
        self.assertEqual('SYSLOG_RFC5424_HEADER_PRESERVED',event.syntax)
        self.assertIn('RFC5424_SD_VALUE_NOT_QUOTED',event.issues)
        candidate=candidate_from_event(event,self.evidence())
        self.assertEqual('PARTIAL',candidate.completeness)
        self.assertEqual(
            {
                'pri','version','timestamp','hostname',
                'appname','procid','msgid',
            },
            set(candidate.field_tree['syslog']),
        )
        self.assertEqual(7,len(candidate.occurrences))

    def test_evidence_is_explicit_not_an_unbounded_score(self):
        with self.assertRaises(ValueError):
            CandidateEvidence(parser_id='',profile_id=None,grammar_id=None,evidence_tier='QUALIFIED_BASE',
                              independently_qualified=False,source_revision=None,confidence_evidence=())
        with self.assertRaises(ValueError):
            CandidateEvidence(parser_id='x',profile_id=None,grammar_id=None,evidence_tier='MAGIC_CONFIDENCE',
                              independently_qualified=False,source_revision=None,confidence_evidence=())

if __name__=='__main__': unittest.main()
