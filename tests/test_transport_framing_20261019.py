"""Standards source framing replay, preserving original UTF-8 byte partitions."""
import sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/multipass'))
from multipass_preview_api import preview_batch
from security_framing import parse_security_batch,assert_batch_accounting

MSG='<134>1 2026-10-19T08:05:00Z host demo 42 evt - action=deny user="김민수"'
JSON='{"event_type":"alert","src_ip":"192.0.2.1","username":"김민수"}'
OCTET=(str(len(MSG.encode('utf8')))+' '+MSG)*2
JSON_SEQUENCE='\x1e'+JSON+'\n\x1e'+JSON+'\n'
GELF='{"version":"1.1","host":"host","short_message":"blocked","level":3}\x00'
JOURNAL='MESSAGE=action=deny src=192.0.2.1\nPRIORITY=5\n\nMESSAGE=action=allow src=192.0.2.2\nPRIORITY=6\n'
class TransportStream(unittest.TestCase):
 def test_rfc6587_octet_length_utf8_not_char_length(self):
  result=preview_batch(OCTET)
  self.assertEqual(result['eventCount'],2)
  self.assertTrue(all(e['preview']['status']=='PARTIAL' for e in result['events']))
  self.assertEqual(sum(x['kind']=='SOURCE_FRAMING' for x in result['separators']),2)
 def test_rfc6587_nul(self):
  result=preview_batch(MSG+'\x00'+MSG+'\x00')
  self.assertEqual(result['eventCount'],2)
  self.assertTrue(all(e['preview']['status']=='PARTIAL' for e in result['events']))
 def test_rfc7464_sequence(self):
  result=preview_batch(JSON_SEQUENCE)
  self.assertEqual(result['eventCount'],2)
  self.assertTrue(all(e['preview']['status']=='PARTIAL' for e in result['events']))
  self.assertTrue(any(x['kind']=='SOURCE_FRAMING' for x in result['separators']))
 def test_gelf_tcp_framing(self):
  result=preview_batch(GELF)
  self.assertEqual(result['eventCount'],1)
  self.assertEqual(result['events'][0]['preview']['fields']['host'],'host')
  self.assertEqual(result['events'][0]['preview']['status'],'PARTIAL')
 def test_journal_export_event_grouping(self):
  result=preview_batch(JOURNAL)
  self.assertEqual(result['eventCount'],2)
  self.assertEqual(result['events'][0]['preview']['fields']['MESSAGE'],'action=deny src=192.0.2.1')
  self.assertTrue(all(e['preview']['status']=='PARTIAL' for e in result['events']))
 def test_byte_accounting_all_cases(self):
  for source in [OCTET,MSG+'\x00'+MSG+'\x00',JSON_SEQUENCE,GELF,JOURNAL]:
   batch=parse_security_batch(source);assert_batch_accounting(batch)
   self.assertEqual(sum(x.end_byte-x.start_byte for x in batch.frames)+sum(x.end_byte-x.start_byte for x in batch.separators),len(source.encode()))
 def test_bad_octet_does_not_claim_success(self):
  result=preview_batch(str(len(MSG.encode())+15)+' '+MSG)
  self.assertTrue(all(e['preview']['status']!='SOURCE_PARSED' for e in result['events']))
if __name__=='__main__':unittest.main()
