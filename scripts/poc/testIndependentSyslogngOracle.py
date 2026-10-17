#!/usr/bin/env python3
"""Independent C upstream assertions: small, partial and byte-faithful oracles."""
import hashlib
import json
import os
import stat
import unittest
from pathlib import Path

from freezeIndependentSyslogngOracle import (
    STATE, expected, literal, original_range, raw_data
)


class IndependentSyslogngPartialSourceOracleTests(unittest.TestCase):
    def test_literal_c_source_reconstruction(self):
        code='const gchar *data = "<13>Jan " " 7 12:00:00 host tag: hello";'
        self.assertEqual(raw_data(code), '<13>Jan  7 12:00:00 host tag: hello')
        with self.assertRaises(ValueError):
            literal('"\\xFF"')

    def test_upstream_expectations_are_not_inferred(self):
        assertions = (
            'assert_log_message_value_by_name(msg, "HOST", "host");'
            'assert_log_message_value_by_name(msg, "PROGRAM", "tag");'
            'assert_log_message_value_by_name(msg, "MSG", "hello");'
        )
        self.assertEqual({item['name'] for item in expected(assertions)},
                         {'hostname', 'appname', 'message'})
        self.assertEqual(expected("const char* message = \"hello\";"), [])

    def test_original_byte_locations_are_independent_of_candidate(self):
        raw = '<13>Jan  7 12:00:00 host tag: hello'
        value = original_range(raw, {'name':'message','value':'hello'})
        self.assertEqual(raw.encode()[value['start_byte']:value['end_byte']],b'hello')
        with self.assertRaises(ValueError):
            original_range(raw, {'name':'message','value':'not_original'})

    def test_duplicate_expected_source_occurrence_is_unscorable(self):
        with self.assertRaises(ValueError):
            original_range('<13>Jan  7 12:00:00 host host: hello',
                           {'name':'hostname','value':'host'})

    def test_frozen_third_party_source_identity_and_denominators(self):
        source=(STATE/'upstream-original.c').read_bytes()
        manifest=json.loads((STATE/'source.pinned.json').read_text())
        self.assertEqual(hashlib.sha256(source).hexdigest(),
                         manifest['original_sha256'])
        summary=json.loads((STATE/'partial-summary.pinned.json').read_text())
        private=(STATE/'partial-source-oracle.pinned.json').read_bytes()
        self.assertEqual(hashlib.sha256(private).hexdigest(),
                         summary['private_oracle_sha256'])
        items=json.loads(private)
        self.assertEqual(len(items),summary['stats']['cases'])
        self.assertEqual(summary['stats']['cases'],36)
        self.assertEqual(summary['stats']['scorable_partial'],7)
        self.assertEqual(summary['stats']['unscorable'],29)
        self.assertEqual(summary['stats']['scoped_field_triples'],19)
        for row in items:
            if row['status']!='PARTIAL_UPSTREAM_ASSERTED_SOURCE_TRUTH':
                self.assertEqual(row['fields'],[])
                continue
            original=row['raw'].encode('utf8')
            self.assertEqual(hashlib.sha256(original).hexdigest(),row['raw_sha256'])
            for f in row['fields']:
                actual=original[f['start_byte']:f['end_byte']].decode('utf8')
                self.assertEqual(f['value'],actual)

    def test_nonpromotable_scored_negative_finding_retained(self):
        report=json.loads((STATE/'first-partial-field-comparison.pinned.json').read_text())
        measured=report['result']
        self.assertEqual(measured['independentlyAssertedFields'],19)
        self.assertEqual(measured['baselineMatchedValues'],10)
        self.assertEqual(measured['candidateMatchedValues'],3)
        self.assertEqual(measured['candidateExactByteTriples'],3)
        self.assertEqual(measured['candidateAbstainedScorable'],5)
        self.assertEqual(measured['autoPromoted'],0)
        self.assertTrue(report['cannotScoreUnassertedFieldFP'])
        self.assertTrue(report['cannotScoreFullEventExactness'])

    def test_private_state_is_not_git_published(self):
        self.assertEqual(stat.S_IMODE(STATE.stat().st_mode),0o700)
        for name in ('upstream-original.c','partial-source-oracle.pinned.json',
                     'partial-summary.pinned.json',
                     'first-partial-field-comparison.pinned.json'):
            self.assertEqual(stat.S_IMODE((STATE/name).stat().st_mode),0o600)


if __name__=="__main__":
    unittest.main()
