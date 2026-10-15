"""Candidate-only single KV island recovery."""
import unittest

from generic_partial_single_kv import augment_incomplete_single_kv
from security_source import parse_security_source
from source_parse import assert_source_accounting


class GenericPartialSingleKVTests(unittest.TestCase):
    def test_single_explicit_kv_is_source_backed_but_not_complete(self):
        raw='prefix NetScreen device_id=node-01 trailing prose'
        base=parse_security_source(raw)
        event=augment_incomplete_single_kv(base);assert_source_accounting(event)
        self.assertNotEqual('SOURCE_PARSED',event.status)
        self.assertEqual(['node-01'],event.vendor_fields['generic_single_kv']['device_id'])
        span=next(s for s in event.value_spans if s.path.startswith('generic_single_kv.'))
        self.assertEqual('node-01',raw.encode()[span.start_byte:span.end_byte].decode())

    def test_url_query_and_quoted_nested_kv_are_not_discovered(self):
        for raw in (
            'visit https://example.test/path?a=1 trailing prose',
            'message="literal device_id=fake" trailing prose',
        ):
            with self.subTest(raw=raw):
                event=augment_incomplete_single_kv(parse_security_source(raw))
                self.assertNotIn('generic_single_kv',event.vendor_fields)

    def test_unsafe_malformed_and_empty_values_abstain(self):
        for raw in (
            'prefix __proto__=bad trailing prose',
            'prefix key="" trailing prose',
            'prefix key="unterminated trailing prose',
        ):
            with self.subTest(raw=raw):
                event=augment_incomplete_single_kv(parse_security_source(raw))
                self.assertNotIn('generic_single_kv',event.vendor_fields)

    def test_existing_source_spans_are_never_removed(self):
        raw='prefix user=alice trailing 192.0.2.1 prose'
        base=parse_security_source(raw)
        event=augment_incomplete_single_kv(base)
        old={(s.path,s.start_byte,s.end_byte) for s in base.value_spans}
        new={(s.path,s.start_byte,s.end_byte) for s in event.value_spans}
        self.assertTrue(old<=new)
        self.assertEqual(raw,event.raw)


if __name__=='__main__':
    unittest.main()
