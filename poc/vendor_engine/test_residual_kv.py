"""Verify bounded key/value island extraction never certifies full free text."""
from pathlib import Path
import sys
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from residual_kv import recover_kv_islands
from source_parse import parse_source,assert_source_accounting


class ResidualKeyValueTests(unittest.TestCase):
    def test_two_embedded_fields_recovered_with_original_names(self):
        raw="ALARM: login failed for user=alice src_ip=192.0.2.42 from edge"
        value=recover_kv_islands(raw)
        self.assertEqual({"user":"alice","src_ip":"192.0.2.42"},value.values)
        self.assertEqual(2,value.field_count)
        parsed=parse_source(raw)
        self.assertEqual("PARTIAL",parsed.status)
        self.assertEqual("alice",parsed.vendor_fields["embedded_kv"]["user"])
        self.assertGreater(parsed.residual_bytes,0)
        self.assertFalse(parsed.normalization_attempted)
        assert_source_accounting(parsed)
        for span in parsed.value_spans:
            expected=parsed.vendor_fields["embedded_kv"][span.path.split(".")[-1]]
            self.assertEqual(expected,raw.encode("utf8")[span.start_byte:span.end_byte].decode("utf8"))

    def test_quoted_unicode_and_escape_are_source_backed(self):
        raw='NOTICE account="한😀 user" action="suspend \\"later\\"" trailing prose'
        parsed=parse_source(raw)
        self.assertEqual("PARTIAL",parsed.status)
        self.assertEqual("한😀 user",parsed.vendor_fields["embedded_kv"]["account"])
        self.assertEqual('suspend "later"',parsed.vendor_fields["embedded_kv"]["action"])
        self.assertEqual(2,parsed.primitive_fields)
        assert_source_accounting(parsed)
        target=next(x for x in parsed.value_spans if x.path=="embedded_kv.account")
        self.assertEqual("한😀 user",raw.encode("utf8")[target.start_byte:target.end_byte].decode("utf8"))

    def test_duplicate_vendor_key_is_preserved_as_multiple_occurrences(self):
        result=recover_kv_islands("context key=first key=second another=third")
        self.assertEqual(["first","second"],result.values["key"])
        self.assertIn("ISLAND_DUPLICATE_VENDOR_FIELD",result.issues)
        self.assertEqual(3,result.field_count)

    def test_single_key_not_enough_for_trusting_free_text(self):
        for raw in ["login for user=bob failed","query=https://evil.test/search?q=secret"]:
            item=recover_kv_islands(raw)
            self.assertFalse(item.values)
            self.assertEqual(0,item.field_count)

    def test_url_query_parameters_not_mislabeled_as_source_fields(self):
        raw="request=https://host/path?user=alice&key=bad status=403"
        recovered=recover_kv_islands(raw)
        self.assertEqual({
            "request":"https://host/path?user=alice&key=bad",
            "status":"403",
        },recovered.values)
        self.assertNotIn("user",recovered.values)
        self.assertNotIn("key",recovered.values)
        parsed=parse_source(raw)
        # Entire record is in fact a valid standalone two-field KV event.
        self.assertEqual("SOURCE_PARSED",parsed.status)
        self.assertEqual(0,parsed.residual_bytes)
        self.assertEqual(recovered.values,parsed.vendor_fields)
        assert_source_accounting(parsed)

    def test_unsafe_keys_and_unclosed_quote_do_not_leak(self):
        raw='text __proto__=foo real=ok action=deny msg="unterminated'
        item=recover_kv_islands(raw)
        self.assertEqual({"real":"ok","action":"deny"},item.values)
        self.assertNotIn("__proto__",item.values)
        self.assertNotIn("msg",item.values)
        parsed=parse_source(raw)
        self.assertEqual("PARTIAL",parsed.status)
        self.assertGreater(parsed.residual_bytes,0)
        assert_source_accounting(parsed)


if __name__=="__main__":
    unittest.main()
