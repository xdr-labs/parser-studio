"""Keep source interpretation separate from the reviewed compiler subset."""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/"runtime/multipass"))
from multipass_adjudicator import parse_security_multipass
from multipass_preview_api import preview
from source_parse import assert_source_accounting


class LeefInterpretationReview(unittest.TestCase):
    def test_implicit_tab_retains_source_values_without_inventing_delimiter(self):
        raw=('LEEF:2.0|Acme|Agent|1.0|alert|\tusrName=김민수 🔐'
             '\tsrc=192.0.2.6\taction=blocked')
        result=parse_security_multipass(raw)
        assert_source_accounting(result)
        self.assertEqual(result.status,'SOURCE_PARSED')
        self.assertEqual(result.syntax,'LEEF_2_IMPLICIT_TAB')
        self.assertNotIn('delimiter',result.vendor_fields['leef_header'])
        self.assertEqual(result.vendor_fields['leef_extension'],{
            'usrName':'김민수 🔐','src':'192.0.2.6','action':'blocked',
        })
        self.assertEqual(result.raw,raw)
        for span in result.value_spans:
            namespace,key=span.path.split('.')
            value=result.vendor_fields[namespace][key]
            self.assertEqual(raw.encode('utf8')[span.start_byte:span.end_byte],
                             value.encode('utf8'))
        self.assertFalse(result.native_verified)
        self.assertFalse(result.target_verified)

    def test_explicit_tab_copy_preserves_values_under_the_reviewed_source_form(self):
        extension='usrName=김민수 🔐\tsrc=192.0.2.6\taction=blocked'
        implicit='LEEF:2.0|Acme|Agent|1.0|alert|\t'+extension
        explicit='LEEF:2.0|Acme|Agent|1.0|alert|0x09|'+extension
        before=preview(implicit);after=preview(explicit)
        self.assertEqual(before['status'],'SOURCE_PARSED')
        self.assertEqual(after['status'],'SOURCE_PARSED')
        self.assertEqual(before['fields']['leef_extension'],
                         after['fields']['leef_extension'])
        self.assertNotEqual(before['sourceSha256'],after['sourceSha256'])
        self.assertEqual(after['fields']['leef_header']['delimiter'],'0x09')
        self.assertFalse(after['nativeVerified'])
        self.assertFalse(after['targetVerified'])

    def test_incomplete_header_and_unsupported_delimiters_are_not_promoted(self):
        for raw in [
            'LEEF:2.0|Acme|Agent',
            'LEEF:2.0|Acme|Agent|1.0|alert|=|src=192.0.2.6',
            'LEEF:2.0|Acme|Agent|1.0|alert|xZZ|src=192.0.2.6',
        ]:
            with self.subTest(raw=raw):
                result=parse_security_multipass(raw)
                assert_source_accounting(result)
                self.assertNotEqual(result.status,'SOURCE_PARSED')
                self.assertEqual(result.raw,raw)
                self.assertFalse(result.native_verified)
                self.assertFalse(result.target_verified)


if __name__=='__main__':
    unittest.main()
