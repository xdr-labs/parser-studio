"""Exactly-at-limit CEF/LEEF source data must not be falsely incomplete."""
from pathlib import Path
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from security_source import parse_security_source
from source_parse import assert_source_accounting


class SecurityExtensionLimitTests(unittest.TestCase):
    def test_cef_exact_extension_limit_and_trailing_space(self):
        for suffix in ('','  \t'):
            body='CEF:0|Example|IPS|1|100|Detection|7|'+' '.join(f'k{i}=v{i}' for i in range(1024))+suffix
            event=parse_security_source(body)
            self.assertEqual('SOURCE_PARSED',event.status)
            self.assertEqual(1024,len(event.vendor_fields['cef_extension']))
            self.assertEqual(0,event.residual_bytes)
            self.assertEqual('v1023',event.vendor_fields['cef_extension']['k1023'])
            assert_source_accounting(event)

    def test_leef_exact_extension_limit_with_terminal_delimiter(self):
        for suffix in ('','\t','\t\t'):
            body='LEEF:2.0|Example|IPS|1|100|0x09|'+'\t'.join(f'k{i}=v{i}' for i in range(1024))+suffix
            event=parse_security_source(body)
            self.assertEqual('SOURCE_PARSED',event.status)
            self.assertEqual(1024,len(event.vendor_fields['leef_extension']))
            self.assertEqual(0,event.residual_bytes)
            assert_source_accounting(event)

    def test_over_limit_never_drops_or_certifies_unparsed_values(self):
        for header,separator,key in (('CEF:0|Example|IPS|1|100|Detection|7|',' ','cef_extension'),('LEEF:2.0|Example|IPS|1|100|0x09|','\t','leef_extension')):
            raw=header+separator.join(f'k{i}=v{i}' for i in range(1025))
            event=parse_security_source(raw)
            self.assertEqual('PARTIAL',event.status)
            self.assertEqual(1024,len(event.vendor_fields[key]))
            self.assertNotIn('k1024',event.vendor_fields[key])
            self.assertIn('k1024=v1024',''.join(raw[a:b] for a,b in event.unparsed))
            self.assertEqual(raw,event.raw)
            assert_source_accounting(event)


if __name__=='__main__':unittest.main()
