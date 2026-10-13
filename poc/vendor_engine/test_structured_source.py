"""Synthetic adversarial CEF/LEEF and Syslog framing extraction fixtures."""
import sys
from pathlib import Path
import unittest

sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_parse import parse_source,assert_source_accounting


class StructuredSourceTests(unittest.TestCase):
    def check(self,raw,syntax="CEF"):
        result=parse_source(raw)
        self.assertEqual(syntax,result.syntax)
        self.assertEqual(raw,result.raw)
        assert_source_accounting(result)
        self.assertFalse(result.normalization_attempted)
        return result

    def test_cef_named_header_unquoted_long_value_and_unknown_extension(self):
        raw=(r"CEF:0|Sec\|ure|Firewall|1.0|42|Denied \| access|5|"
             r"src=192.0.2.10 dst=198.51.100.3 "
             r"msg=User denied accessing restricted file act=blocked "
             r"custom_vendor_field=works")
        event=self.check(raw)
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual("Sec|ure",event.vendor_fields["cef_header"]["vendor"])
        self.assertEqual("Denied | access",event.vendor_fields["cef_header"]["name"])
        ext=event.vendor_fields["cef_extension"]
        self.assertEqual("192.0.2.10",ext["src"])
        self.assertEqual("User denied accessing restricted file",ext["msg"])
        self.assertEqual("blocked",ext["act"])
        self.assertEqual("works",ext["custom_vendor_field"])
        self.assertEqual(12,event.primitive_fields)
        self.assertEqual(event.primitive_fields,len(event.value_spans))
        self.assertEqual(0,event.residual_bytes)

    def test_cef_escapes_empty_value_and_typed_none_not_inferred(self):
        raw=(r'CEF:0|V|P|1.0|1|Some Event|4|'
             r'msg="hello \= world" empty= note="한😀 data"')
        event=self.check(raw)
        self.assertEqual("SOURCE_PARSED",event.status)
        ext=event.vendor_fields["cef_extension"]
        self.assertEqual("hello = world",ext["msg"])
        self.assertEqual("",ext["empty"])
        self.assertEqual("한😀 data",ext["note"])
        self.assertFalse(event.normalization_attempted)
        utf8=raw.encode("utf8")
        value_span=next(s for s in event.value_spans if s.path=="cef_extension.note")
        self.assertEqual("한😀 data",utf8[value_span.start_byte:value_span.end_byte].decode("utf8"))

    def test_cef_duplicate_field_is_preserved_not_overwritten(self):
        event=self.check("CEF:0|A|B|1|4|X|5|tag=first tag=second")
        self.assertEqual("PARTIAL",event.status)
        self.assertEqual(["first","second"],event.vendor_fields["cef_extension"]["tag"])
        self.assertIn("DUPLICATE_SOURCE_FIELD",event.issues)
        self.assertEqual(0,event.residual_bytes)

    def test_malformed_cef_header_never_claims_parsed(self):
        event=self.check("CEF:0|few|header")
        self.assertEqual("RAW_ONLY",event.status)
        self.assertEqual({},event.vendor_fields)
        self.assertEqual(event.source_bytes,event.residual_bytes)

    def test_leef_version_one_tab_delimiter_and_unknown_fields(self):
        raw="LEEF:1.0|IBM|QRadar|1.0|id002|src=192.0.2.2\tdst=198.51.100.2\tcustom_field=123"
        event=self.check(raw,"LEEF")
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual("id002",event.vendor_fields["leef_header"]["event_id"])
        self.assertEqual("123",event.vendor_fields["leef_extension"]["custom_field"])
        self.assertEqual(8,event.primitive_fields)
        self.assertEqual(0,event.residual_bytes)

    def test_leef_version_two_custom_hex_separator(self):
        raw="LEEF:2.0|IBM|App|2.0|001|0x5E|src=192.0.2.1^query=a=b^empty="
        event=self.check(raw,"LEEF")
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual("a=b",event.vendor_fields["leef_extension"]["query"])
        self.assertEqual("",event.vendor_fields["leef_extension"]["empty"])
        self.assertEqual("0x5E",event.vendor_fields["leef_header"]["delimiter"])
        self.assertEqual(0,event.residual_bytes)

    def test_malformed_leef_separator_cannot_fake_success(self):
        raw="LEEF:2.0|IBM|App|2.0|001|0x00|src=192.0.2.1"
        event=self.check(raw,"LEEF")
        self.assertEqual("RAW_ONLY",event.status)
        self.assertTrue(event.issues)

    def test_syslog_3164_wrapped_cef_and_quoted_kv(self):
        raw="<134>Oct 14 11:12:13 host firewall[23]: CEF:0|V|P|1|7|event|5|src=192.0.2.5 x=10"
        event=self.check(raw,"SYSLOG_RFC3164+CEF")
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual("firewall[23]",event.vendor_fields["syslog"]["tag"])
        self.assertEqual("192.0.2.5",event.vendor_fields["body"]["cef_extension"]["src"])
        self.assertEqual(0,event.residual_bytes)
        self.assertTrue(any(s.path=="body.cef_extension.src" for s in event.value_spans))

        kv="<134>Oct 14 11:12:13 host app: type=event vendorField=\"two words\""
        event=self.check(kv,"SYSLOG_RFC3164+KV")
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual("two words",event.vendor_fields["body"]["vendorField"])

    def test_syslog_with_unknown_body_remains_partial_preserving_raw(self):
        raw="<134>Oct 14 11:12:13 host app: unknown nonsense"
        event=self.check(raw,"SYSLOG_RFC3164+UNKNOWN")
        self.assertEqual("PARTIAL",event.status)
        self.assertEqual("host",event.vendor_fields["syslog"]["host"])
        self.assertEqual({},event.vendor_fields["body"])
        self.assertGreater(event.residual_bytes,0)

    def test_malformed_structured_record_does_not_consume_wrong_body(self):
        for raw in ("CEF:1|A|B|1|2|Name|5|msg=\"unterminated",
                    "LEEF:1.0|A|B|1|2|bad-extension-token"):
            event=parse_source(raw)
            self.assertNotEqual("SOURCE_PARSED",event.status)
            self.assertTrue(event.issues)
            assert_source_accounting(event)


    def test_rfc5424_kv_body_preserves_structured_data_and_vendor_fields(self):
        raw=('<134>1 2026-10-14T11:12:13Z host app 123 ABC '
             '[tenant@12345 username="한😀" event="risk"] '
             'customField="two words" src=192.0.2.1')
        event=self.check(raw,"SYSLOG_RFC5424+KV")
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual("한😀",event.vendor_fields["syslog"][
            "structured_data"]["tenant@12345"]["username"])
        self.assertEqual("two words",event.vendor_fields["body"]["customField"])
        raw_bytes=raw.encode("utf8")
        span=next(s for s in event.value_spans if s.path==
                  "syslog.structured_data.tenant@12345.username")
        self.assertEqual("한😀",raw_bytes[span.start_byte:span.end_byte].decode("utf8"))
        self.assertEqual(0,event.residual_bytes)

    def test_rfc5424_json_body_and_without_body(self):
        raw=('<165>1 2026-10-14T11:12:13.123+09:00 node app 1 - - '
             '{"newVendorField":{"nested":true},"counter":9}')
        event=self.check(raw,"SYSLOG_RFC5424+JSON")
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertTrue(event.vendor_fields["body"]["newVendorField"]["nested"])
        self.assertFalse(event.normalization_attempted)
        absent='<165>1 - node app 1 - -'
        header=self.check(absent,"SYSLOG_RFC5424")
        self.assertEqual("SOURCE_PARSED",header.status)
        self.assertEqual("-",header.vendor_fields["syslog"]["structured_data_raw"])
        self.assertEqual(0,header.residual_bytes)

    def test_rfc5424_wrapped_cef_and_multiple_escaped_sd_identifiers(self):
        raw=('<165>1 2026-10-14T11:12:13Z host app 2 MSG '
             '[id@1 flag="good' + chr(92) + ']to' + chr(92) + '"go"][id@2 another="value"] '
             'CEF:0|Vendor|Product|3|sig|name|5|app=custom')
        event=self.check(raw,"SYSLOG_RFC5424+CEF")
        self.assertEqual("SOURCE_PARSED",event.status)
        self.assertEqual('good]to"go',event.vendor_fields["syslog"][
            "structured_data"]["id@1"]["flag"])
        self.assertEqual("custom",event.vendor_fields["body"]["cef_extension"]["app"])

    def test_rfc5424_invalid_header_or_sd_fails_closed(self):
        bad=[
            '<165>2 2026-10-14T11:12:13Z host app 1 MSG - a=1',
            '<165>1 2026-10-14T11:12:13 host app 1 MSG - a=1',
            '<165>1 2026-10-14T11:12:13Z host app 1 MSG [sd a="v" a="w"]',
            '<165>1 2026-10-14T11:12:13Z host app 1 MSG [sd a="v"',
        ]
        for raw in bad:
            event=parse_source(raw)
            self.assertNotEqual("SOURCE_PARSED",event.status)
            self.assertTrue(event.issues)
            assert_source_accounting(event)


if __name__=="__main__":
    unittest.main()
