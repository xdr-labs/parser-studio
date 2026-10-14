import json
import unittest
from multipass_preview_api import allowed_origin,preview

class PreviewContract(unittest.TestCase):
    def test_source_spans_and_residual_are_exact(self):
        raw='%ASA-4-106023: Deny udp src outside:192.0.2.1/53'
        result=preview(raw)
        self.assertEqual('parser-studio.multipass-source-preview.v0.1',result['contract'])
        self.assertEqual('PARTIAL',result['status'])
        self.assertEqual('Deny',result['fields']['asa']['action'])
        for span in result['spans']:
            key=span['path'].split('.')[-1]
            self.assertEqual(result['fields']['asa'][key],raw.encode()[span['startByte']:span['endByte']].decode())
        self.assertFalse(result['nativeVerified'])
    def test_dictionary_projection_is_optional_exact_key_metadata_only(self):
        raw='{"srcip":"192.0.2.1","dstport":443,"action":"deny","src_ip":"198.51.100.4"}'
        result=preview(raw);dictionary=result['dictionary']
        self.assertEqual('parser-studio.stellar-dictionary-projection.v0.1',dictionary['contract'])
        self.assertEqual(['srcip','dstport','action'],[item['targetField'] for item in dictionary['mapped']])
        self.assertEqual(1,dictionary['unmappedCount'])
        self.assertFalse(dictionary['automaticAliasInference'])
        self.assertTrue(dictionary['sourceExtractionPreserved'])
        self.assertFalse(dictionary['nativeVerified']);self.assertFalse(dictionary['targetVerified'])
        source_token=raw.encode()[result['spans'][0]['startByte']:result['spans'][0]['endByte']].decode()
        self.assertEqual('192.0.2.1',json.loads(source_token))
        self.assertEqual((result['spans'][0]['startByte'],result['spans'][0]['endByte']),
                         (dictionary['mapped'][0]['startByte'],dictionary['mapped'][0]['endByte']))
        self.assertNotIn('value',dictionary['mapped'][0])
    def test_source_limits(self):
        with self.assertRaises(ValueError):preview('')
        with self.assertRaises(ValueError):preview('a'*65537)
    def test_only_loopback_http_development_origins_are_allowed(self):
        for origin in (None,'http://127.0.0.1:5180','http://127.0.0.1:5284','http://localhost:65535'):
            self.assertTrue(allowed_origin(origin),origin)
        for origin in ('https://127.0.0.1:5180','http://example.com:5180',
                       'http://127.0.0.1.evil.example:5180','http://127.0.0.1:80',
                       'http://user@127.0.0.1:5180','null','http://[::1]:5180'):
            self.assertFalse(allowed_origin(origin),origin)

if __name__=='__main__':unittest.main()
