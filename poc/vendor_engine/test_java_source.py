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


if __name__=="__main__":unittest.main()
