import unittest
from security_asa import parse_asa_message
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

class CiscoAsaConservativeTests(unittest.TestCase):
    def test_exact_source_message_identity_and_partial_body(self):
        raw='Oct 10 2018 12:34:56 localhost CiscoASA[999]: %ASA-4-113029: Group VPN_USERS User example'
        event=parse_security_multipass(raw)
        self.assertEqual({'product':'ASA','severity':'4','message_id':'113029'},event.vendor_fields['asa'])
        self.assertEqual('PARTIAL',event.status)
        for span in event.value_spans:
            key=span.source_segments[-1]
            self.assertEqual(event.vendor_fields['asa'][key],raw.encode()[span.start_byte:span.end_byte].decode())
        assert_source_accounting(event)

    def test_no_inference_from_json_or_ambiguous_multiple_ids(self):
        self.assertEqual('JSON',parse_security_multipass('{"msg":"%ASA-4-113029: text"}').syntax)
        self.assertIsNone(parse_asa_message('%ASA-4-113029: first %FTD-6-302013: second'))
        self.assertIsNone(parse_asa_message('%ASA-4-113029: first\n%FTD-6-302013: second'))

if __name__=='__main__':unittest.main()
