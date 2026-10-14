import unittest
from security_sonicwall import parse_sonicwall_host_kv
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

class SonicWallSourceTests(unittest.TestCase):
    def test_ipv4_host_and_quoted_kv_exact_spans(self):
        raw='10.0.0.1 id=firewall sn=123 time="2022-02-22 18:24:30 UTC" msg="Connection Opened" src=10.0.0.3:52379:X0'
        e=parse_security_multipass(raw)
        self.assertEqual('SOURCE_PARSED',e.status)
        self.assertEqual('10.0.0.1',e.vendor_fields['sonicwall']['host'])
        self.assertEqual('Connection Opened',e.vendor_fields['body']['msg'])
        self.assertEqual('10.0.0.3:52379:X0',e.vendor_fields['body']['src'])
        for span in e.value_spans:
            value=e.vendor_fields
            for segment in span.source_segments:value=value[segment]
            self.assertEqual(value,raw.encode()[span.start_byte:span.end_byte].decode())
        assert_source_accounting(e)

    def test_invalid_host_and_non_sonicwall_are_not_promoted(self):
        self.assertIsNone(parse_sonicwall_host_kv('999.0.0.1 id=firewall sn=123'))
        self.assertIsNone(parse_sonicwall_host_kv('10.0.0.1 id=other sn=123'))

if __name__=='__main__':unittest.main()
