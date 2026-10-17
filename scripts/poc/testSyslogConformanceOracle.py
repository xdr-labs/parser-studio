#!/usr/bin/env python3
"""Independent Python oracle tests; neither product nor TypeScript candidate is imported."""
import hashlib
import json
import stat
import unittest
from pathlib import Path

from freezeSyslogConformanceOracle import (
    STATE, BYTE_INPUT, expected_go, parse_rfc3164, parse_rfc5424,
    unquote, value_span, case_blocks, freeze,
)


class SourceConformanceOracleTests(unittest.TestCase):
    def test_rfc3164_header_byte_spans_from_separate_upstream_fields(self):
        raw = '<13>Dec  2 16:31:03 host app: Test'
        expected = dict(priority=13,facility=1,severity=5,hostname='host',
                        appname='app',timestamp='Dec 2 16:31:03',message='Test')
        fields = parse_rfc3164(raw,expected)
        self.assertEqual({x['name'] for x in fields},
                         {'pri','month','day','time','hostname','appname','message'})
        for field in fields:
            b = raw.encode('utf8')
            self.assertEqual(b[field['start_byte']:field['end_byte']].decode('utf8'),
                             field['value'])

    def test_rfc5424_structured_data_and_header_expected_values(self):
        raw = ('<86>1 2016-01-15T01:00:43Z gateway app 1234 ALERT '
               '[meta id="2" note="abc"] payload')
        expected = dict(priority=86,version=1,timestamp='2016-01-15T01:00:43Z',
                        hostname='gateway',appname='app',procid='1234',
                        msgid='ALERT',message='payload')
        fields = parse_rfc5424(raw,expected)
        self.assertEqual(len(fields),9)
        for field in fields:
            b = raw.encode('utf8')
            self.assertEqual(b[field['start_byte']:field['end_byte']].decode('utf8'),
                             field['value'])

    def test_upstream_semantic_conflict_is_excluded(self):
        raw = '<1>1 - host a - - - message'
        with self.assertRaises(ValueError):
            parse_rfc5424(raw,dict(priority=17,version=1,message='message'))
        with self.assertRaises(ValueError):
            parse_rfc5424(raw,dict(priority=1,version=1,hostname='different',
                                  appname='a',message='message'))

    def test_raw_go_literal_decoding_never_evaluates_nonliteral_source(self):
        self.assertEqual(unquote('`source bytes`'),'source bytes')
        self.assertEqual(unquote('"a\\nb"'),'a\nb')
        with self.assertRaises(ValueError):
            unquote('"\\xFF"')
        with self.assertRaises(ValueError):
            unquote('"\\u0000"')

    def test_exact_source_spans_reject_reconstruction(self):
        with self.assertRaises(ValueError):
            value_span('safe', 'k', 'different',0,4)
        valid = value_span('safe', 'field', 'afe',1,4)
        self.assertEqual((valid['start_byte'],valid['end_byte']),(1,4))

    def test_all_pre_frozen_source_shas_still_match(self):
        manifest = json.loads((STATE/'sources.pinned.json').read_text())
        for original in manifest['files']:
            source=(STATE/'upstream'/(original['id']+'.go')).read_bytes()
            self.assertEqual(hashlib.sha256(source).hexdigest(),original['sha256'])
        self.assertEqual(len(manifest['files']),3)

    def test_v3_original_denominator_and_byte_oracle(self):
        summary=json.loads((STATE/'oracle-summary.v3.pinned.json').read_text())
        reference=(STATE/'records-and-expected.v3.pinned.json').read_bytes()
        records=json.loads(reference)
        self.assertEqual(summary['all_cases'],len(records))
        self.assertEqual(summary['scorable'],41)
        self.assertEqual(summary['negative_only'],79)
        self.assertEqual(summary['unscorable'],84)
        self.assertEqual(summary['source_field_triples'],279)
        self.assertEqual(hashlib.sha256(reference).hexdigest(),
                         summary['private_oracle_sha256'])
        for record in records:
            if record.get('raw') is None:
                self.assertFalse(record['fields'])
                continue
            source=record['raw'].encode('utf8')
            self.assertEqual(hashlib.sha256(source).hexdigest(),record['raw_sha256'])
            for field in record['fields']:
                observed=source[field['start_byte']:field['end_byte']].decode('utf8')
                self.assertEqual(observed,field['value'])

    def test_private_data_permissions_and_sealed_source_identity(self):
        self.assertEqual(stat.S_IMODE(STATE.stat().st_mode),0o700)
        for file in ('records-and-expected.v3.pinned.json',
                     'oracle-summary.v3.pinned.json','candidate-frozen.json'):
            target=STATE/file
            self.assertTrue(target.is_file())
            self.assertEqual(stat.S_IMODE(target.stat().st_mode),0o600)
        self.assertEqual(json.loads((STATE/'candidate-frozen.json').read_text())['state'],
                         'FROZEN_AFTER_DEV_BEFORE_SEALED_HOLDOUT')


if __name__ == '__main__':
    unittest.main()
