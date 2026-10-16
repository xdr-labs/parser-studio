import unittest
from security_source import parse_security_source
from source_parse import assert_source_accounting

PAN='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end,2561,2026/10/15 00:03:20,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/15 00:03:21,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/15 00:02:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy'

class PanOsTrafficPromotionTests(unittest.TestCase):
    def test_common_rfc3164_wrapped_traffic_log_gets_named_fields(self):
        event=parse_security_source(PAN)
        self.assertEqual('SOURCE_PARSED',event.status)
        self.assertEqual('SECURITY_SYSLOG_ENVELOPE+PANOS_TRAFFIC_CSV',event.syntax)
        self.assertEqual('14',event.vendor_fields['syslog']['pri'])
        fields=event.vendor_fields['body']['fields']
        self.assertEqual('TRAFFIC',fields['type'])
        self.assertEqual('10.10.20.15',fields['src'])
        self.assertEqual('8.8.8.8',fields['dst'])
        self.assertEqual('51234',fields['sport'])
        self.assertEqual('443',fields['dport'])
        self.assertEqual('tcp',fields['protocol'])
        self.assertEqual('allow',fields['action'])
        self.assertEqual('from-policy',fields['action_source'])
        self.assertEqual([],event.unparsed)
        assert_source_accounting(event)

    def test_similar_wide_csv_does_not_receive_panos_meaning_without_full_shape(self):
        raw=PAN.replace(',TRAFFIC,',',THREAT,',1)
        event=parse_security_source(raw)
        self.assertNotIn('PANOS_TRAFFIC_CSV',event.syntax)
        self.assertIn('column_3',event.vendor_fields['body'])
        assert_source_accounting(event)

if __name__=='__main__':unittest.main()
