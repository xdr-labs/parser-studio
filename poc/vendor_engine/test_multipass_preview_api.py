import json
import unittest
from multipass_preview_api import allowed_origin,preview,preview_batch

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
        self.assertTrue(dictionary['standardizedAliasMapping'])
        self.assertTrue(dictionary['sourceExtractionPreserved'])
        self.assertFalse(dictionary['nativeVerified']);self.assertFalse(dictionary['targetVerified'])
        source_token=raw.encode()[result['spans'][0]['startByte']:result['spans'][0]['endByte']].decode()
        self.assertEqual('192.0.2.1',json.loads(source_token))
        self.assertEqual((result['spans'][0]['startByte'],result['spans'][0]['endByte']),
                         (dictionary['mapped'][0]['startByte'],dictionary['mapped'][0]['endByte']))
        self.assertNotIn('value',dictionary['mapped'][0])
    def test_dictionary_projection_exposes_only_standardized_cef_alias_metadata(self):
        raw='CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.10 dpt=443 act=deny cs1=private'
        dictionary=preview(raw)['dictionary']
        mapped={item['sourcePath']:(item['targetField'],item['mappingClass'])
                for item in dictionary['mapped']}
        self.assertEqual(('srcip','CEF_STANDARD_ALIAS'),mapped['cef_extension.src'])
        self.assertEqual(('dstport','CEF_STANDARD_ALIAS'),mapped['cef_extension.dpt'])
        self.assertEqual(('action','CEF_STANDARD_ALIAS'),mapped['cef_extension.act'])
        self.assertNotIn('cef_extension.cs1',mapped)
        self.assertEqual(8,dictionary['unmappedCount'])
        self.assertFalse(dictionary['automaticAliasInference'])
        self.assertTrue(dictionary['standardizedAliasMapping'])
        self.assertNotIn('192.0.2.10',json.dumps(dictionary))
        self.assertNotIn('private',json.dumps(dictionary))

    def test_redaction_projection_recognizes_only_visible_markers_and_never_reconstructs(self):
        raw='{"src":"REDACTED","payload":"***","note":"visible","similar":"redacted-user"}'
        result=preview(raw)
        redaction=result['redaction']
        self.assertEqual('parser-studio.visible-redaction-assessment.v0.1',redaction['contract'])
        self.assertEqual('EXPLICIT_VISIBLE_MASKS',redaction['assessment'])
        self.assertEqual(4,redaction['sourceOccurrences'])
        self.assertEqual(2,redaction['explicitMaskOccurrences'])
        self.assertEqual(2,redaction['unassessedVisibleOccurrences'])
        self.assertFalse(redaction['excludedEvent'])
        self.assertTrue(redaction['sourceExtractionPreserved'])
        self.assertFalse(redaction['hiddenValueReconstruction'])
        self.assertEqual(
            [('src','REDACTED_KEYWORD','REDACTED'),('payload','ASTERISK_RUN','***')],
            [(item['sourcePath'],item['markerClass'],
              raw.encode()[item['startByte']:item['endByte']].decode())
             for item in redaction['occurrences']],
        )
        self.assertNotIn('value',json.dumps(redaction))
        self.assertEqual('REDACTED',result['fields']['src'])
        self.assertEqual('***',result['fields']['payload'])
        self.assertEqual('redacted-user',result['fields']['similar'])

    def test_redaction_projection_never_calls_absence_of_marker_unmasked(self):
        redaction=preview('srcip=192.0.2.1 action=allow')['redaction']
        self.assertEqual('NOT_ASSESSED_NO_LITERAL_MARKER',redaction['assessment'])
        self.assertEqual(0,redaction['explicitMaskOccurrences'])
        self.assertGreater(redaction['unassessedVisibleOccurrences'],0)
        excluded=preview('unsupported sentence only')['redaction']
        self.assertEqual('EXCLUDED_NO_SOURCE_OCCURRENCES',excluded['assessment'])
        self.assertTrue(excluded['excludedEvent'])

    def test_batch_preview_frames_ndjson_and_preserves_source_accounting(self):
        raw='{"action":"BLOCK","srcip":"192.0.2.1"}\n{"action":"ALLOW","srcip":"192.0.2.2"}'
        result=preview_batch(raw)
        self.assertEqual('parser-studio.multipass-source-batch-preview.v0.1',result['contract'])
        self.assertEqual(2,result['eventCount'])
        self.assertEqual(['SOURCE_PARSED','SOURCE_PARSED'],
                         [item['preview']['status'] for item in result['events']])
        encoded=raw.encode()
        for item in result['events']:
            frame=encoded[item['startByte']:item['endByte']].decode()
            self.assertEqual(item['preview']['sourceBytes'],len(frame.encode()))
            self.assertEqual(item['preview']['sourceSha256'],
                             __import__('hashlib').sha256(frame.encode()).hexdigest())
        partitions=[(x['startByte'],x['endByte']) for x in result['events']]
        partitions += [(x['startByte'],x['endByte']) for x in result['separators']]
        position=0
        for start,end in sorted(partitions):
            self.assertEqual(position,start);self.assertGreater(end,start);position=end
        self.assertEqual(len(encoded),position)
        self.assertFalse(result['nativeVerified']);self.assertFalse(result['targetVerified'])

    def test_batch_preview_runs_bounded_funnel_learning_without_false_complete(self):
        from multipass_adjudicator import parse_security_multipass
        rows=[
            '05/30-19:09:10.917356  alert one',
            '12/30-14:09:21.116402  alert two',
            '01/21-02:23:42.327730  alert three',
            '09/04-21:55:02.041364  alert four',
        ]
        result=preview_batch('\n'.join(rows))
        self.assertEqual(4,result['eventCount'])
        for raw,item in zip(rows,result['events']):
            baseline=parse_security_multipass(raw)
            previewed=item['preview']
            self.assertEqual('PARTIAL',previewed['status'])
            self.assertIn('NO_SUPPORTED_GRAMMAR',previewed['issues'])
            self.assertGreater(len(previewed['spans']),len(baseline.value_spans))
            self.assertEqual(__import__('hashlib').sha256(raw.encode()).hexdigest(),
                             previewed['sourceSha256'])

    def test_batch_preview_uses_security_stream_framing_for_mixed_records(self):
        raw=('date=2026-10-14 type="utm" subtype="webfilter" srcip=192.0.2.10 action="blocked"\n'
             'CEF:0|Synthetic|FW|1|42|Blocked|8|src=192.0.2.20 act=deny')
        result=preview_batch(raw)
        self.assertEqual(2,result['eventCount'])
        self.assertEqual(['SOURCE_PARSED','SOURCE_PARSED'],
                         [item['preview']['status'] for item in result['events']])
        self.assertEqual('192.0.2.10',result['events'][0]['preview']['fields']['srcip'])
        self.assertEqual('192.0.2.20',
                         result['events'][1]['preview']['fields']['cef_extension']['src'])

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
