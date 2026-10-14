import unittest
from multipass_preview_api import preview

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
    def test_source_limits(self):
        with self.assertRaises(ValueError):preview('')
        with self.assertRaises(ValueError):preview('a'*65537)

if __name__=='__main__':unittest.main()
