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

    def test_connection_id_only_when_explicit_and_exact(self):
        raw='%FTD-6-302013: Built inbound TCP connection 123456789 for outside:192.0.2.10/443'
        event=parse_security_multipass(raw)
        self.assertEqual('123456789',event.vendor_fields['asa']['connection_id'])
        self.assertEqual('PARTIAL',event.status)
        span=next(x for x in event.value_spans if x.source_segments==('asa','connection_id'))
        self.assertEqual('123456789',raw.encode()[span.start_byte:span.end_byte].decode())
        self.assertNotIn('connection_id',parse_asa_message('%FTD-6-302020: Built inbound ICMP connection for faddr 192.0.2.1/0').vendor_fields['asa'])
        assert_source_accounting(event)

    def test_deny_protocol_full_known_message_is_source_parsed_with_exact_spans(self):
        raw='%ASA-4-106023: Deny udp src outside:192.0.2.1/53 dst inside:198.51.100.1/53'
        event=parse_security_multipass(raw)
        self.assertEqual('Deny',event.vendor_fields['asa']['action'])
        self.assertEqual('udp',event.vendor_fields['asa']['protocol'])
        self.assertEqual('192.0.2.1',event.vendor_fields['asa']['src_ip'])
        self.assertEqual('198.51.100.1',event.vendor_fields['asa']['dst_ip'])
        self.assertEqual('SOURCE_PARSED',event.status)
        for span in event.value_spans:
            self.assertEqual(event.vendor_fields['asa'][span.source_segments[-1]],raw.encode()[span.start_byte:span.end_byte].decode())
        assert_source_accounting(event)

    def test_wrapped_full_connection_merges_syslog_envelope_and_cisco_body(self):
        raw=('May  5 17:51:17 dev01: %FTD-6-302013: Built inbound TCP connection 111111111 '
             'for net:10.10.10.10/53500 (81.2.69.144/53500) to '
             'fw111:192.168.2.2/53500 (81.2.69.144/53500)')
        event=parse_security_multipass(raw)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual('111111111',event.vendor_fields['asa']['connection_id'])
        self.assertEqual('10.10.10.10',event.vendor_fields['asa']['src_ip'])
        self.assertEqual('192.168.2.2',event.vendor_fields['asa']['dst_ip'])
        self.assertIn('syslog',event.vendor_fields)
        self.assertEqual([],event.unparsed)
        assert_source_accounting(event)

    def test_no_inference_from_json_or_ambiguous_multiple_ids(self):
        self.assertEqual('JSON',parse_security_multipass('{"msg":"%ASA-4-113029: text"}').syntax)
        self.assertIsNone(parse_asa_message('%ASA-4-113029: first %FTD-6-302013: second'))
        self.assertIsNone(parse_asa_message('%ASA-4-113029: first\n%FTD-6-302013: second'))

    def test_asa_message_id_beats_incidental_unlabeled_csv_commas(self):
        raw=('Apr 17 2020 14:00:31 edge-asa : %ASA-4-106023: Deny icmp '
             'src Inside:192.0.2.10 dst Outside:198.51.100.20 '
             '(type 11, code 0) by access-group "inside_acl" [0x0, 0x0]')
        event=parse_security_multipass(raw)
        self.assertEqual('CISCO_ASA_FTD_MESSAGE_ID',event.syntax)
        self.assertEqual('PARTIAL',event.status)
        self.assertEqual('ASA',event.vendor_fields['asa']['product'])
        self.assertEqual('106023',event.vendor_fields['asa']['message_id'])
        self.assertEqual('Deny',event.vendor_fields['asa']['action'])
        self.assertNotIn('column_0',event.vendor_fields)
        self.assertIn('ASA_MESSAGE_BODY_UNPARSED',event.issues)

if __name__=='__main__':unittest.main()
