"""RFC 5424 SD-ELEMENT length: the preview reads what the generated parser reads.

RFC 5424 gives structured data no maximum length. A Junos RT_FLOW_SESSION_CLOSE element with NAT and
application fields is longer than 1 KiB; the bound of the preview is the 8192 bytes of the browser's Junos reader. Synthetic values; no target verification implied.
"""
import sys
import unittest
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'runtime/multipass'))
from multipass_preview_api import preview, preview_batch

HEAD='<14>1 2026-11-21T09:15:22.123Z srx01 RT_FLOW - RT_FLOW_SESSION_CLOSE '
def element(pairs):
    return '[junos@2636.1.1.1.2.129 '+' '.join(f'{name}="{value}"' for name,value in pairs)+']'
def flow(padding):
    return [('reason','TCP FIN'),('source-address','10.3.255.203'),('source-port','47776'),
            ('destination-address','198.51.100.15'),('destination-port','80'),('protocol-id','6'),
            *[(f'application-field-{index:03d}','value-'+'x'*24) for index in range(padding)]]

class Rfc5424SdElementLength(unittest.TestCase):
    def test_element_longer_than_one_kibibyte_is_read_completely(self):
        pairs=flow(40)
        raw=HEAD+element(pairs)
        self.assertGreater(len(element(pairs).encode('utf8')),1024)
        result=preview(raw)
        self.assertEqual(result['status'],'SOURCE_PARSED')
        self.assertEqual(result['issues'],[])
        self.assertEqual(result['residuals'],[])
        original=raw.encode('utf8')
        for name,value in pairs:
            spans=[s for s in result['spans'] if s['path'].endswith('.'+name)]
            self.assertEqual(len(spans),1,name)
            self.assertEqual(original[spans[0]['startByte']:spans[0]['endByte']],value.encode('utf8'),name)

    def test_short_and_long_elements_of_one_batch_have_the_same_status(self):
        short,long=HEAD+element(flow(0)),HEAD+element(flow(40))
        result=preview_batch(short+'\n'+long)
        self.assertEqual([event['preview']['status'] for event in result['events']],['SOURCE_PARSED','SOURCE_PARSED'])

    def test_multibyte_values_count_bytes_and_stay_exact(self):
        pairs=flow(20)+[('user-note','보안 이벤트 🌐'*20)]
        raw=HEAD+element(pairs)
        result=preview(raw)
        self.assertEqual(result['status'],'SOURCE_PARSED')
        span=next(s for s in result['spans'] if s['path'].endswith('.user-note'))
        self.assertEqual(raw.encode('utf8')[span['startByte']:span['endByte']].decode('utf8'),'보안 이벤트 🌐'*20)

    def test_structured_data_above_the_shared_bound_is_not_a_complete_parse(self):
        raw=HEAD+element(flow(200))
        self.assertGreater(len(element(flow(200)).encode('utf8')),8192)
        result=preview(raw)
        self.assertNotEqual(result['status'],'SOURCE_PARSED')
        self.assertIn('RFC5424_SD_BYTE_LIMIT',result['issues'])

    def test_an_unterminated_long_element_is_still_not_a_complete_parse(self):
        raw=HEAD+element(flow(40))[:-1]
        self.assertNotEqual(preview(raw)['status'],'SOURCE_PARSED')

if __name__=='__main__':
    unittest.main()
