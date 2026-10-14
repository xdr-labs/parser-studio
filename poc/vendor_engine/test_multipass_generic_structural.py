"""Integration acceptance for Generic Structural as a Multi-Pass candidate."""
import unittest

from generic_structural_poc import parse_generic_structural
from multipass_adjudicator import _qualified_generic_event,parse_security_once
from multipass_contract import CandidateEvidence,candidate_from_event
from source_parse import assert_source_accounting


class MultiPassGenericStructuralTests(unittest.TestCase):
    def test_wide_positional_csv_is_structurally_complete_without_semantics(self):
        raw=','.join(str(index) for index in range(20))
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertIn('GENERIC_POSITIONAL_CSV',event.syntax)
        self.assertEqual(20,len(event.value_spans))

    def test_unseen_mixed_network_shape_uses_generic_candidate(self):
        raw=(
            '1677007712 ipflow 10.0.1.1 flow '
            'src=192.168.1.10 dst=10.10.1.5 protocol=TCP '
            'sport=23456 dport=80 translated_src_ip=203.0.113.5 '
            'translated_port=54321'
        )
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertIn('GENERIC_STRUCTURAL+MIXED',event.syntax)
        self.assertEqual('192.168.1.10',event.vendor_fields['generic']['kv']['src'])
        self.assertEqual('flow',event.vendor_fields['generic']['tokens'][3])

    def test_existing_complete_json_is_not_reinterpreted(self):
        raw='{"event":{"id":7,"ok":true},"name":"sample"}'
        event=parse_security_once(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual('JSON',event.syntax)
        self.assertEqual(
            {'event':{'id':7,'ok':True},'name':'sample'},
            event.vendor_fields,
        )

    def test_generic_candidate_contract_handles_lists_and_repeated_kv(self):
        raw=(
            '<134>1 2026-10-15T00:00:00Z ise app 1 MSG - '
            'Authentication succeeded, Field One=value one, '
            'Field Two=value two, Step=11001, Step=11017, '
            'Result=passed'
        )
        event=parse_generic_structural(raw);assert_source_accounting(event)
        self.assertEqual('SOURCE_PARSED',event.status)
        evidence=CandidateEvidence(
            parser_id='generic.structural',
            profile_id='generic-structural',
            grammar_id='generic-structural-v2',
            evidence_tier='QUALIFIED_STRUCTURAL',
            independently_qualified=True,
            source_revision='GENERIC_STRUCTURAL_EXPANDED_POC_20261015',
            confidence_evidence=('948-frozen','708-postfreeze'),
        )
        candidate=candidate_from_event(
            _qualified_generic_event(event),evidence,
        )
        self.assertEqual(len(event.value_spans),len(candidate.occurrences))
        steps=[
            occurrence.value for occurrence in candidate.occurrences
            if occurrence.display_path=='generic.kv.Step'
        ]
        self.assertEqual(['11001','11017'],steps)


if __name__=='__main__':
    unittest.main()
