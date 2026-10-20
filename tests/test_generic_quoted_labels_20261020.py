"""Generic bracket-label recovery; synthetic data, no vendor semantic oracle."""
import copy
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runtime/multipass"))
from generic_partial_atoms import augment_incomplete_atoms
from generic_partial_labels import augment_incomplete_labels
from multipass_adjudicator import parse_security_multipass
from multipass_preview_api import preview,preview_batch
from source_parse import SourceEvent,ValueSpan,_close,assert_source_accounting


def incomplete(raw):
    return _close(SourceEvent(raw,issues=['NO_SUPPORTED_GRAMMAR']))


class GenericQuotedLabels(unittest.TestCase):
    def test_quoted_labels_add_source_values_without_losing_network_atom(self):
        raw=('Gateway policy denied access from 192.0.2.3:443 '
             '[id "942100"] [msg "Request blocked by a rule"]')
        before=augment_incomplete_atoms(incomplete(raw))
        snapshot=copy.deepcopy(before)
        after=augment_incomplete_labels(before)
        assert_source_accounting(after)
        self.assertEqual(before,snapshot)
        self.assertEqual(after.raw,raw)
        self.assertEqual(after.raw_sha256,before.raw_sha256)
        self.assertEqual(after.status,'PARTIAL')
        self.assertEqual(after.vendor_fields['generic_atoms'],
                         before.vendor_fields['generic_atoms'])
        self.assertTrue(set(before.value_spans)<=set(after.value_spans))
        self.assertEqual(after.vendor_fields['generic_labels'],{
            'id':['942100'],'msg':['Request blocked by a rule'],
        })
        self.assertGreater(after.residual_bytes,0)
        self.assertFalse(after.native_verified)
        self.assertFalse(after.target_verified)

    def test_utf8_and_escaped_quotes_keep_exact_lexical_spans(self):
        raw='알림 [user "김민수 🔐"] [note "say \\"hello\\" and continue"]'
        # The values are source lexemes, including the original escapes.
        result=augment_incomplete_labels(incomplete(raw))
        assert_source_accounting(result)
        self.assertEqual(result.vendor_fields['generic_labels'],{
            'user':['김민수 🔐'],'note':['say \\"hello\\" and continue'],
        })
        for span in result.value_spans:
            _,key,index=span.source_segments
            value=result.vendor_fields['generic_labels'][key][index]
            self.assertEqual(raw.encode('utf8')[span.start_byte:span.end_byte],
                             value.encode('utf8'))

    def test_repeated_labels_keep_occurrence_order_and_are_idempotent(self):
        raw='Policy checked [tag "one"] [tag "two"] [tag "three"]'
        result=augment_incomplete_labels(incomplete(raw))
        self.assertEqual(result.vendor_fields['generic_labels'],
                         {'tag':['one','two','three']})
        self.assertEqual([span.source_segments for span in result.value_spans],
                         [('generic_labels','tag',i) for i in range(3)])
        self.assertEqual(augment_incomplete_labels(result),result)

    def test_existing_label_tree_and_spans_survive_additional_recovery(self):
        raw='Policy checked [tag: one] [tag: two] [msg "blocked"]'
        a=raw.index('one'); b=a+3
        original=_close(SourceEvent(
            raw,syntax='UNKNOWN+GENERIC_LABELS',
            vendor_fields={'generic_labels':{'tag':['one']}},
            value_spans=[ValueSpan('generic_labels.tag.0',a,b,
                                  ('generic_labels','tag',0))],
            covered=[(a,b)],primitive_fields=1,
            issues=['NO_SUPPORTED_GRAMMAR'],
        ))
        result=augment_incomplete_labels(original)
        assert_source_accounting(result)
        self.assertEqual(result.vendor_fields['generic_labels'],
                         {'tag':['one','two'],'msg':['blocked']})
        self.assertTrue(set(original.value_spans)<=set(result.value_spans))
        self.assertEqual(original.vendor_fields['generic_labels'],{'tag':['one']})

    def test_empty_quoted_values_keep_distinct_occurrences_without_reentry_duplicates(self):
        raw='Alert [tag ""] [tag "next"] [tag ""]'
        result=augment_incomplete_labels(incomplete(raw))
        assert_source_accounting(result)
        self.assertEqual(result.vendor_fields['generic_labels'],
                         {'tag':['','next','']})
        self.assertEqual(len(result.value_spans),3)
        self.assertEqual(len({(s.start_byte,s.end_byte) for s in result.value_spans}),3)
        self.assertEqual(augment_incomplete_labels(result),result)

    def test_quoted_brackets_inside_a_value_are_not_new_fields(self):
        raw='Alert [msg "example [id \\"42\\"] remains text"]'
        result=augment_incomplete_labels(incomplete(raw))
        self.assertEqual(result.vendor_fields['generic_labels'],
                         {'msg':['example [id \\"42\\"] remains text']})

    def test_invalid_or_unbounded_labels_are_not_recovered(self):
        cases=[
            '[id "not closed]',
            '[id "closed" trailing]',
            '[id "value"',
            '[id "first\nsecond"]',
            '[id "'+('x'*257)+'"]',
            '['+('k'*65)+' "value"]',
            '[id unquoted]',
            '[https "example.test"]',
        ]
        for raw in cases:
            with self.subTest(raw=raw[:70]):
                before=incomplete(raw)
                self.assertEqual(augment_incomplete_labels(before),before)

    def test_known_complete_structures_are_not_reinterpreted(self):
        raw='{"message":"[id \\\"42\\\"]"}'
        result=parse_security_multipass(raw)
        self.assertEqual(result.status,'SOURCE_PARSED')
        self.assertNotIn('generic_labels',result.vendor_fields)

    def test_multipass_and_public_preview_keep_partial_status_and_all_atoms(self):
        raw=('[Mon Oct 19 04:12:20.001 2026] [client 192.0.2.3] '
             'Gateway: Access denied with code 403 (phase 2). '
             '[id "942100"] [msg "Request blocked by policy"]')
        result=parse_security_multipass(raw)
        assert_source_accounting(result)
        self.assertEqual(result.status,'PARTIAL')
        self.assertEqual(result.vendor_fields['generic_labels']['id'],['942100'])
        self.assertEqual(result.vendor_fields['generic_labels']['msg'],
                         ['Request blocked by policy'])
        self.assertIn('192.0.2.3',result.vendor_fields['generic_atoms']['network'])
        public=preview(raw)
        self.assertEqual(public['status'],'PARTIAL')
        self.assertEqual(public['sourceSha256'],result.raw_sha256)
        self.assertEqual(public['fields']['generic_labels'],
                         result.vendor_fields['generic_labels'])
        self.assertGreater(len(public['residuals']),0)
        self.assertFalse(public['nativeVerified'])
        self.assertFalse(public['targetVerified'])
        batch=preview_batch(raw)
        self.assertEqual(batch['events'][0]['preview']['status'],'PARTIAL')


if __name__=='__main__':
    unittest.main()
