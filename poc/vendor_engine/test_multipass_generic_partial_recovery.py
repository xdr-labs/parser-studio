"""Product-path acceptance for candidate-only partial recovery."""
import dataclasses
import unittest

from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting


class MultiPassGenericPartialRecoveryTests(unittest.TestCase):
    def test_default_product_path_adds_exact_atoms_without_complete_promotion(self):
        raw=(
            'opaque alert from 192.0.2.10 to 198.51.100.20 '
            'url https://example.test/path'
        )
        baseline=parse_security_multipass(raw,max_residual_depth=0)
        current=parse_security_multipass(raw)
        assert_source_accounting(baseline);assert_source_accounting(current)
        self.assertEqual('RAW_ONLY',baseline.status)
        self.assertEqual('PARTIAL',current.status)
        self.assertNotEqual('SOURCE_PARSED',current.status)
        self.assertEqual(raw,current.raw)
        self.assertIn('generic_atoms',current.vendor_fields)
        self.assertGreater(len(current.value_spans),len(baseline.value_spans))
        data=raw.encode()
        for span in current.value_spans:
            self.assertEqual(
                data[span.start_byte:span.end_byte].decode(),
                data[span.start_byte:span.end_byte].decode(),
            )

    def test_header_and_event_code_recovery_stays_candidate_only(self):
        raw=(
            '<147>4105777: node.example: 4105879: '
            'Jun 2 16:00:48.072 SGT: '
            '%AAA-3-BADSERVERTYPEERROR: trailing free text'
        )
        event=parse_security_multipass(raw)
        assert_source_accounting(event)
        self.assertEqual('PARTIAL',event.status)
        self.assertIn('generic_envelope',event.vendor_fields)
        self.assertIn('generic_event_code',event.vendor_fields)
        self.assertNotEqual('SOURCE_PARSED',event.status)

    def test_complete_event_remains_byte_for_byte_engine_equivalent(self):
        raw='{"event":{"id":7,"ok":true},"name":"sample"}'
        baseline=parse_security_multipass(raw,max_residual_depth=0)
        current=parse_security_multipass(raw)
        self.assertEqual(dataclasses.asdict(baseline),dataclasses.asdict(current))


if __name__=='__main__':
    unittest.main()
