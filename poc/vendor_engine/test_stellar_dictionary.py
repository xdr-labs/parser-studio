from copy import deepcopy
import unittest

from multipass_adjudicator import parse_security_multipass
from stellar_dictionary import (
    DICTIONARY_REVISION,CEF_DICTIONARY_URL,STELLAR_DICTIONARY_URL,
    normalize_stellar_dictionary,
)


class StellarDictionaryNormalizationTests(unittest.TestCase):
    def test_direct_cef_maps_only_documented_extension_roles_and_preserves_unknown(self):
        raw=(
            "CEF:0|Synthetic|FW|1|42|Blocked|8|"
            "src=192.0.2.10 dst=198.51.100.20 spt=12345 dpt=443 "
            "act=deny cs1=vendor-only"
        )
        event=parse_security_multipass(raw)
        before=deepcopy(event.vendor_fields)
        normalized=normalize_stellar_dictionary(event)
        self.assertEqual(event.vendor_fields,before)
        self.assertFalse(event.normalization_attempted)
        self.assertEqual(normalized.dictionary_revision,DICTIONARY_REVISION)
        self.assertEqual(normalized.normalized_fields,{
            "srcip":"192.0.2.10","dstip":"198.51.100.20",
            "srcport":12345,"dstport":443,"action":"deny",
        })
        by_target={item.dictionary_field:item for item in normalized.mappings}
        self.assertEqual(set(by_target),{"srcip","dstip","srcport","dstport","action"})
        self.assertTrue(all(item.evidence_url==CEF_DICTIONARY_URL for item in by_target.values()))
        unknown=[ref for ref in normalized.unmapped_occurrences if ref.path=="cef_extension.cs1"]
        self.assertEqual(len(unknown),1)
        self.assertEqual(normalized.source_fields["cef_extension"]["cs1"],"vendor-only")
        for item in normalized.mappings:
            value=raw.encode("utf8")[item.source.start_byte:item.source.end_byte].decode("utf8")
            if item.dictionary_type=="integer":
                self.assertEqual(int(value),item.normalized_value)
            else:
                self.assertEqual(value,item.normalized_value)

    def test_wrapped_cef_maps_body_aliases_without_losing_envelope_or_unknown(self):
        raw=(
            "<165>1 2026-10-14T10:00:00Z edge fw 123 ID42 - "
            "CEF:0|Synthetic|FW|1|42|Blocked|8|src=203.0.113.8 dpt=8443 act=allow cs1=x"
        )
        event=parse_security_multipass(raw)
        normalized=normalize_stellar_dictionary(event)
        self.assertEqual(normalized.normalized_fields,{
            "srcip":"203.0.113.8","dstport":8443,"action":"allow",
        })
        self.assertIn("syslog",normalized.source_fields)
        self.assertEqual(normalized.source_fields["body"]["cef_extension"]["cs1"],"x")
        self.assertTrue(any(ref.path=="body.cef_extension.cs1"
                            for ref in normalized.unmapped_occurrences))

    def test_generic_src_alias_outside_cef_is_not_semantically_guessed(self):
        raw="src=192.0.2.10 dst=198.51.100.20 act=deny"
        event=parse_security_multipass(raw)
        normalized=normalize_stellar_dictionary(event)
        self.assertEqual(normalized.normalized_fields,{})
        self.assertEqual(len(normalized.mappings),0)
        self.assertEqual({ref.path for ref in normalized.unmapped_occurrences},
                         {"src","dst","act"})

    def test_exact_dictionary_names_are_typed_without_rewriting_source_values(self):
        raw=(
            "srcip=192.0.2.10 dstip=198.51.100.20 "
            "srcport=12345 dstport=443 proto=6 proto_name=TCP "
            "action=allow severity=70 username=alice url=https://example.test hostname=edge01"
        )
        event=parse_security_multipass(raw)
        normalized=normalize_stellar_dictionary(event)
        self.assertEqual(normalized.normalized_fields,{
            "srcip":"192.0.2.10","dstip":"198.51.100.20",
            "srcport":12345,"dstport":443,"proto":6,"proto_name":"TCP",
            "action":"allow","severity":70,"username":"alice",
            "url":"https://example.test","hostname":"edge01",
        })
        self.assertTrue(all(item.evidence_url==STELLAR_DICTIONARY_URL
                            for item in normalized.mappings))
        self.assertEqual(normalized.unmapped_occurrences,())

    def test_invalid_dictionary_type_abstains_and_preserves_original_vendor_field(self):
        for raw,target in (
            ("srcip=not-an-ip action=allow","srcip"),
            ("dstport=70000 action=allow","dstport"),
            ("severity=101 action=allow","severity"),
            ("proto=999 action=allow","proto"),
        ):
            with self.subTest(raw=raw):
                event=parse_security_multipass(raw)
                normalized=normalize_stellar_dictionary(event)
                self.assertNotIn(target,normalized.normalized_fields)
                self.assertIn("DICTIONARY_TYPE_REJECTED:"+target,normalized.issues)
                self.assertIn(target,event.vendor_fields)
                self.assertTrue(any(ref.path==target for ref in normalized.unmapped_occurrences))

    def test_duplicate_cef_alias_never_silently_overwrites_one_dictionary_target(self):
        raw=(
            "CEF:0|Synthetic|FW|1|42|Blocked|8|"
            "src=192.0.2.10 src=192.0.2.11 act=deny"
        )
        event=parse_security_multipass(raw)
        normalized=normalize_stellar_dictionary(event)
        self.assertNotIn("srcip",normalized.normalized_fields)
        self.assertEqual(event.vendor_fields["cef_extension"]["src"],
                         ["192.0.2.10","192.0.2.11"])
        self.assertIn("DICTIONARY_TARGET_AMBIGUOUS:srcip",normalized.issues)
        self.assertEqual(sum(ref.path=="cef_extension.src"
                             for ref in normalized.unmapped_occurrences),2)
        self.assertEqual(normalized.normalized_fields["action"],"deny")

    def test_public_report_is_value_free_and_source_parser_remains_separate(self):
        raw="srcip=192.0.2.10 action=deny custom_key=PRIVATE_VALUE"
        event=parse_security_multipass(raw)
        source_report=event.report()
        normalized=normalize_stellar_dictionary(event)
        report=normalized.report()
        self.assertFalse(source_report["normalization_attempted"])
        self.assertTrue(report["normalization_attempted"])
        self.assertFalse(report["native_verified"])
        self.assertFalse(report["target_verified"])
        self.assertNotIn("192.0.2.10",str(report))
        self.assertNotIn("PRIVATE_VALUE",str(report))
        self.assertEqual(normalized.source_fields["custom_key"],"PRIVATE_VALUE")


if __name__=="__main__":
    unittest.main()
