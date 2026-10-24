"""Lossless, conservative recovery for two generic textual header grammars."""
from pathlib import Path
import sys
import unittest

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime/multipass'))
from generic_text_envelope import recover_textual_header
from multipass_adjudicator import parse_security_multipass
from security_source import parse_security_source
from source_parse import assert_source_accounting

PROXY='[10.30 16:49:06] chrome.exe - gateway.example:5070 open through proxy gateway.example:5070 HTTPS'
PROXY_ALT='[07.26 17:31:09] firefox.exe *17 - intranet.example:80 close, 8 bytes sent, 15 bytes received, lifetime 00:01'
HDFS='081109 203615 148 INFO dfs.DataNode$PacketResponder: PacketResponder 1 for block blk_-123 terminating'
HDFS_ALT='081110 014601 592 ERROR dfs.FSNamesystem: Unable to delete block blk_124 due to I/O exception'

class GenericTextHeaderTests(unittest.TestCase):
 def test_source_values_and_utf8_spans(self):
  for raw in [PROXY,PROXY_ALT,HDFS,HDFS_ALT]:
   with self.subTest(raw=raw[:20]):
    expected=recover_textual_header(raw)
    self.assertIsNotNone(expected)
    self.assertIn('GENERIC_TEXT_ENVELOPE_',expected.syntax)
    self.assertEqual(expected.status,'PARTIAL')
    self.assertEqual(expected.issues,['FREE_TEXT_FIELD_ROLES_NEED_REVIEW'])
    self.assertFalse(expected.native_verified)
    self.assertFalse(expected.target_verified)
    self.assertEqual(expected.residual_bytes,0)
    self.assertIn('message',expected.vendor_fields['body'])
    self.assertGreater(len(expected.value_spans),2)
    assert_source_accounting(expected)
    data=raw.encode('utf8')
    for span in expected.value_spans:
     actual=data[span.start_byte:span.end_byte].decode('utf8')
     group,field=span.path.split('.',1)
     self.assertEqual(actual,expected.vendor_fields[group][field])
    self.assertEqual(len(data),expected.source_bytes)
    selected=parse_security_multipass(raw)
    assert_source_accounting(selected)
    # A qualified earlier strong grammar is not replaced by a review-only
    # generic interpretation of the same source.
    self.assertIn(selected.status,('PARTIAL','SOURCE_PARSED'))
    if selected.status=='PARTIAL':
     self.assertTrue(
      'GENERIC_TEXT_ENVELOPE_' in selected.syntax or
      selected.syntax=='BRACKETED_MONTH_DAY_APPLICATION_TARGET',
      selected.syntax)

 def test_unstructured_unicode_survives(self):
  sample='[02.29 01:02:03] 보안.exe - 전송 차단됨 호스트.example:443'
  event=parse_security_source(sample)
  self.assertEqual(event.status,'PARTIAL')
  self.assertEqual(event.vendor_fields['body']['message'],'전송 차단됨 호스트.example:443')
  assert_source_accounting(event)

 def test_no_guessing_malformed_headers(self):
  for raw in [
   '[13.99 24:70:88] firefox.exe - bad',
   '[02.30 16:01:01] firefox.exe - bad',
   '[04.31 16:01:01] firefox.exe - bad',
   '081332 203615 148 INFO dfs.Component: invalid datecode',
   '081109 246060 148 INFO dfs.Component: invalid clockcode',
   '081109 203615 148 OTHER dfs.Component: invalid severity',
   '[10.30 16:49:06] firefox.exe - invalid\nnext',
   'action=deny srcip=192.0.2.12',
   '{"action":"deny","src_ip":"192.0.2.1"}',
   '<134>Oct 24 12:10:21 testbox app: action=deny',
  ]:
   with self.subTest(raw=raw[:24]):
    event=recover_textual_header(raw)
    self.assertIsNone(event)

 def test_previous_verified_parsers_unchanged(self):
  samples=[
   'action=deny srcip=192.0.2.12 dstport=443',
   '{"action":"deny","src_ip":"192.0.2.1"}',
   'Dec 10 06:55:46 sshbox sshd[24200]: Invalid user unknown from 192.0.2.3',
  ]
  for raw in samples:
   a=parse_security_source(raw)
   b=parse_security_multipass(raw)
   self.assertNotIn('GENERIC_TEXT_ENVELOPE_',a.syntax)
   self.assertNotIn('GENERIC_TEXT_ENVELOPE_',b.syntax)
   assert_source_accounting(a);assert_source_accounting(b)

 def test_malformed_overlong_and_control_characters_fail_closed(self):
  for raw in [PROXY+'\x00',PROXY+'\r',PROXY+'\nnext',PROXY+'z'*9000]:
   self.assertIsNone(recover_textual_header(raw))

if __name__=='__main__':unittest.main()
