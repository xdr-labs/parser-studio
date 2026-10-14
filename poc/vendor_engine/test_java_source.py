"""Bounded Java logging envelopes are source fields, not body correctness."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_parse import parse_source,assert_source_accounting


class JavaSourceTests(unittest.TestCase):
    def test_short_date_logger_and_source_body(self):
        raw='26/11/14 10:11:12 INFO Worker: user=alice action=allow'
        out=parse_source(raw)
        self.assertEqual("SOURCE_PARSED",out.status)
        self.assertEqual({"date":"26/11/14","time":"10:11:12","level":"INFO","logger":"Worker"},out.vendor_fields["java"])
        self.assertEqual({"user":"alice","action":"allow"},out.vendor_fields["body"])
        assert_source_accounting(out)

    def test_iso_date_thread_and_logger(self):
        raw='2026-11-14 10:11:12,123 INFO [worker-7] example.Task: started operation'
        out=parse_source(raw)
        self.assertEqual("worker-7",out.vendor_fields["java"]["thread"])
        self.assertEqual("example.Task",out.vendor_fields["java"]["logger"])
        self.assertEqual("PARTIAL",out.status)
        self.assertIn('started operation',''.join(raw[a:b] for a,b in out.unparsed))
        assert_source_accounting(out)

    def test_context_and_optional_node_identifier(self):
        for myid in ("","[myid:3] - "):
            raw=f'2026-11-14 10:11:12,123 {myid}WARN  [worker-Ž:Server@42] - operation started'
            out=parse_source(raw)
            self.assertEqual("worker-Ž:Server@42",out.vendor_fields["java"]["context"])
            self.assertEqual("PARTIAL",out.status)
            span=next(x for x in out.value_spans if x.path=="java.context")
            self.assertEqual("worker-Ž:Server@42",raw.encode()[span.start_byte:span.end_byte].decode())
            self.assertEqual(raw,out.raw)
            assert_source_accounting(out)

    def test_invalid_date_or_missing_delimiter_does_not_admit_header(self):
        for raw in (
            '2026-02-30 10:11:12,123 INFO Worker: user=alice action=allow',
            '26/13/14 10:11:12 INFO Worker: user=alice action=allow',
            '26/11/14 25:11:12 INFO Worker: user=alice action=allow',
            '26/11/14 10:11:12 INFO Worker user=alice action=allow',
            '26/11/14 10:11:12 invented Worker: user=alice action=allow',
        ):
            with self.subTest(raw=raw):
                out=parse_source(raw)
                self.assertNotIn("java",out.vendor_fields)
                self.assertEqual(raw,out.raw)
                assert_source_accounting(out)

    def test_recognized_header_does_not_qualify_drain_or_dictionary(self):
        out=parse_source('26/11/14 10:11:12 INFO Worker: opaque prose without fields')
        self.assertEqual("PARTIAL",out.status)
        self.assertEqual(4,out.primitive_fields)
        self.assertGreater(out.residual_bytes,0)
        self.assertFalse(out.normalization_attempted)
        self.assertFalse(out.native_verified)
        self.assertFalse(out.target_verified)


class JavaContextBoundaryTests(unittest.TestCase):
    def test_dash_envelope_and_atomic_source_context(self):
        raw='2026-11-14 10:11:12,123 - INFO  [worker-7:example.Server@42] - user=alice action=allow'
        event=parse_source(raw)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual({'date':'2026-11-14','time':'10:11:12,123','level':'INFO',
            'context':'worker-7:example.Server@42','thread':'worker-7',
            'logger':'example.Server','line_number':'42'},event.vendor_fields['java'])
        self.assertEqual({'user':'alice','action':'allow'},event.vendor_fields['body'])
        assert_source_accounting(event)

    def test_multicolon_context_preserved_without_ambiguous_atoms(self):
        for separator in (' ', ' - '):
            raw='2026-11-14 10:11:12,123'+separator+'ERROR [listener:[::1]:2181:Example$Worker@7] - plain text'
            event=parse_source(raw)
            self.assertEqual('listener:[::1]:2181:Example$Worker@7',event.vendor_fields['java']['context'])
            self.assertNotIn('thread',event.vendor_fields['java'])
            self.assertNotIn('logger',event.vendor_fields['java'])
            self.assertEqual('7',event.vendor_fields['java']['line_number'])
            self.assertEqual('PARTIAL',event.status)
            assert_source_accounting(event)

    def test_unicode_atomic_fields_have_original_utf8_spans(self):
        raw='2026-11-14 10:11:12,123 - WARN  [worker-Ž:Example@0042] - unchanged message'
        event=parse_source(raw)
        self.assertEqual('worker-Ž',event.vendor_fields['java']['thread'])
        self.assertEqual('0042',event.vendor_fields['java']['line_number'])
        for span in event.value_spans:
            if span.path.startswith('java.'):
                self.assertEqual(event.vendor_fields['java'][span.path[5:]],raw.encode()[span.start_byte:span.end_byte].decode())

    def test_opaque_context_is_preserved_without_fabricated_atoms(self):
        for context in ('unclassified context','worker:Example@not-a-number','worker:Example@1234567890'):
            raw='2026-11-14 10:11:12,123 - WARN  ['+context+'] - opaque message'
            event=parse_source(raw)
            self.assertEqual(context,event.vendor_fields['java']['context'])
            self.assertNotIn('thread',event.vendor_fields['java'])
            self.assertNotIn('line_number',event.vendor_fields['java'])
            self.assertEqual('PARTIAL',event.status)
            self.assertEqual(raw,event.raw)

    def test_dash_does_not_admit_unqualified_plain_logger_layout(self):
        for body in ('Worker: user=alice action=allow','[thread] Worker: user=alice action=allow'):
            raw='2026-11-14 10:11:12,123 - INFO '+body
            self.assertNotIn('java',parse_source(raw).vendor_fields)

    def test_context_scan_is_bounded_and_requires_balanced_brackets(self):
        from java_source import extract_java_envelope
        for context in ('x'*514,'['*9+'x'+']'*9,'worker[missing:Example@7'):
            raw='2026-11-14 10:11:12,123 - INFO ['+context+'] - plain text'
            self.assertIsNone(extract_java_envelope(raw))
            self.assertEqual(raw,parse_source(raw).raw)


if __name__=="__main__":unittest.main()
