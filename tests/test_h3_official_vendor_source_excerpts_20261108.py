"""H3 publisher-attributed, deliberately truncated vendor source holdouts.

Do not mistake these short quoted excerpts for whole manufacturer log records,
customer data, a vendor-wide benchmark or Stellar Cyber mapping qualification.
The expected literal UTF-8 byte positions are independently authored.
"""
from __future__ import annotations

import hashlib
import pathlib
import sys
import unittest

ROOT=pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime'/'multipass'))
from multipass_preview_api import preview,preview_batch

# A contiguous 16-field prefix of Fortinet's officially published 2017 traffic
# example. The omitted fields, including later action, are NOT tested.
# https://docs.fortinet.com/document/fortigate/7.4.2/fortios-log-message-reference/357866/log-message-fields
FORTINET_EXCERPT=(
 'date=2017-11-15 time=11:44:16 logid="0000000013" type="traffic"'
 ' subtype="forward" level="notice" vd="vdom1" eventtime=1510775056'
 ' srcip=10.1.100.155 srcname="pc1" srcport=40772 srcintf="port12"'
 ' srcintfrole="undefined" dstip=35.197.51.42'
 ' dstname="fortiguard.com" dstport=443'
)

# A contiguous excerpt of WatchGuard's officially published Member2 Traffic
# Monitor event. The actual complete event has further post-fix KV fields.
# https://www.watchguard.com/help/docs/help-center/en-us/content/en-US/Fireware/logging/read_log-msg.html
WATCHGUARD_EXCERPT=(
 '2024-03-29 15:00:50 Member2 Allow 192.168.228.202 10.0.1.1'
 ' webcache/tcp 42973 8080 3-Trusted 1-WCI Allowed 60 63'
 ' (Outgoing-proxy-00) proc_id="firewall" rc="100"'
)


def token_spans(raw:str,result:dict,path:str)->list[str]:
    buffer=raw.encode('utf8')
    return [buffer[x['startByte']:x['endByte']].decode('utf8')
            for x in result['spans'] if x['path']==path]


class PublishedManufacturerExcerpts(unittest.TestCase):
    def verify_raw_identity(self,raw:str,report:dict):
        source=raw.encode('utf8')
        self.assertEqual(report['sourceBytes'],len(source))
        self.assertEqual(report['sourceSha256'],hashlib.sha256(source).hexdigest())
        self.assertFalse(report['nativeVerified'])
        self.assertFalse(report['targetVerified'])
        for field in report['spans']:
            a,b=field['startByte'],field['endByte']
            self.assertTrue(0<=a<=b<=len(source),field)
            for i in (a,b):
                self.assertTrue(i in (0,len(source)) or source[i]&0xc0!=0x80,
                                field)

    def test_fortinet_official_KV_prefix_extracts_reviewable_ip_fields(self):
        parsed=preview(FORTINET_EXCERPT)
        self.verify_raw_identity(FORTINET_EXCERPT,parsed)
        self.assertEqual(parsed['status'],'SOURCE_PARSED')
        self.assertEqual(parsed['syntax'],'KV')
        self.assertEqual(parsed['residuals'],[])
        self.assertEqual(parsed['fields']['srcip'],'10.1.100.155')
        self.assertEqual(parsed['fields']['dstip'],'35.197.51.42')
        self.assertEqual(parsed['fields']['srcport'],'40772')
        self.assertEqual(parsed['fields']['dstport'],'443')
        self.assertEqual(token_spans(FORTINET_EXCERPT,parsed,'srcip'),['10.1.100.155'])
        self.assertEqual(token_spans(FORTINET_EXCERPT,parsed,'dstip'),['35.197.51.42'])
        self.assertNotIn('action',parsed['fields'],
                         'The excerpt deliberately does not include the action field')

    def test_watchguard_official_prefix_preserves_positions_without_claiming_semantics(self):
        parsed=preview(WATCHGUARD_EXCERPT)
        self.verify_raw_identity(WATCHGUARD_EXCERPT,parsed)
        self.assertIn(parsed['status'],('PARTIAL','SOURCE_PARSED'))
        self.assertEqual(token_spans(WATCHGUARD_EXCERPT,parsed,
                         'generic_atoms.network.0'),['192.168.228.202'])
        self.assertEqual(token_spans(WATCHGUARD_EXCERPT,parsed,
                         'generic_atoms.network.1'),['10.0.1.1'])
        self.assertNotIn('srcip',parsed['fields'],
                         'Unreviewed positional tokens are not canonical Stellar fields')
        self.assertNotIn('dstip',parsed['fields'])
        self.assertTrue(parsed['residuals'] or parsed['issues'],
                        'This intentionally truncated sample cannot establish full coverage')

    def test_publisher_excerpts_are_not_rewritten_by_batch_order(self):
        for rows in ((FORTINET_EXCERPT,WATCHGUARD_EXCERPT),
                     (WATCHGUARD_EXCERPT,FORTINET_EXCERPT)):
            combined='\n'.join(rows)
            report=preview_batch(combined)
            source=combined.encode('utf8')
            self.assertEqual(report['eventCount'],2)
            self.assertEqual(report['sourceSha256'],hashlib.sha256(source).hexdigest())
            self.assertFalse(report['targetVerified'])
            for raw,entry in zip(rows,report['events']):
                actual=source[entry['startByte']:entry['endByte']].decode('utf8')
                self.assertEqual(actual,raw)
                self.verify_raw_identity(raw,entry['preview'])
            self.assertEqual(len(report['separators']),1)
            sep=report['separators'][0]
            self.assertEqual(source[sep['startByte']:sep['endByte']],b'\n')


if __name__=='__main__':
    unittest.main()
