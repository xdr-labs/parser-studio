"""H3 independent original-byte and semantic source truth for six grammars.

The fixture values, UTF-8 offsets, expected fields and negative cases are
authored from source grammar examples, never copied from engine results.
This is source parsing evidence, NOT generated Ruby/DP conformance.
"""
from __future__ import annotations

import hashlib
import json
import pathlib
import sys
import unittest

ROOT = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'runtime' / 'multipass'))

from multipass_preview_api import preview, preview_batch

UTF8_LABELS = ('한글', '김민수', '山田', '😀', '👩🏽‍💻', 'αβγ', 'مرحبا', 'ไทย')
IP = '192.0.2.10'
ACTION = 'deny'

def six_source_truth(label: str):
    json_string = lambda value: json.dumps(value, ensure_ascii=False)
    return [
        ('kv', f'srcip={IP} action={ACTION} user={label}',
         [('srcip', IP), ('action', ACTION), ('user', label)]),
        ('json', json.dumps({'srcip': IP, 'action': ACTION, 'user': label},
                            ensure_ascii=False, separators=(',', ':')),
         [('srcip', json_string(IP)), ('action', json_string(ACTION)),
          ('user', json_string(label))]),
        ('cef', f'CEF:0|Test|FW|1|100|Blocked|8|src={IP} act={ACTION} msg={label}',
         [('cef_extension.src', IP), ('cef_extension.act', ACTION),
          ('cef_extension.msg', label)]),
        ('leef', f'LEEF:2.0|Test|FW|1|100|src={IP}\tact={ACTION}\tmsg={label}',
         [('leef_extension.src', IP), ('leef_extension.act', ACTION),
          ('leef_extension.msg', label)]),
        ('rfc5424', f'<165>1 2026-11-08T01:02:03Z edge app 1 ID42 - '
                    f'srcip={IP} action={ACTION} msg={label}',
         [('body.srcip', IP), ('body.action', ACTION), ('body.msg', label)]),
        ('rfc3164', f'<134>Nov  8 01:02:03 edge app: '
                    f'srcip={IP} action={ACTION} msg={label}',
         [('body.srcip', IP), ('body.action', ACTION), ('body.msg', label)]),
    ]


def assert_truth(test: unittest.TestCase, raw: str, expected: list[tuple[str,str]], report: dict):
    source = raw.encode('utf8')
    test.assertEqual(report['status'], 'SOURCE_PARSED')
    test.assertEqual(report['sourceBytes'], len(source))
    test.assertEqual(report['sourceSha256'], hashlib.sha256(source).hexdigest())
    test.assertEqual(report['residuals'], [])
    test.assertFalse(report['nativeVerified'])
    test.assertFalse(report['targetVerified'])

    by_path: dict[str, list[bytes]] = {}
    for span in report['spans']:
        a, b = span['startByte'], span['endByte']
        test.assertTrue(0 <= a <= b <= len(source), span)
        # Boundaries cannot point into a UTF-8 continuation byte.
        for offset in (a, b):
            test.assertTrue(offset in (0, len(source)) or
                            source[offset] & 0xc0 != 0x80, span)
        by_path.setdefault(span['path'], []).append(source[a:b])
    for path, token in expected:
        test.assertEqual(by_path.get(path), [token.encode('utf8')], path)
        test.assertEqual(source.count(token.encode('utf8')), 1,
                         'Source truth should identify exactly one occurrence')


class IndependentSixFamilySourceOracle(unittest.TestCase):
    def test_positive_per_grammar_utf8_field_ownership_and_original_bytes(self):
        for label in UTF8_LABELS:
            for family, raw, expected in six_source_truth(label):
                with self.subTest(family=family, label=label):
                    assert_truth(self, raw, expected, preview(raw))

    def test_fixed_seed_reordering_preserves_each_event_and_exact_framing(self):
        for label in UTF8_LABELS:
            truth = six_source_truth(label)
            orders = [
                list(range(6)),
                list(reversed(range(6))),
                list(range(2, 6)) + list(range(2)),
            ]
            for permutation in orders:
                ordered = [truth[index] for index in permutation]
                raw = '\n'.join(case[1] for case in ordered)
                batch = preview_batch(raw)
                self.assertEqual(batch['eventCount'], 6)
                data = raw.encode('utf8')
                self.assertEqual(batch['sourceSha256'], hashlib.sha256(data).hexdigest())
                self.assertEqual(batch['sourceBytes'], len(data))
                self.assertFalse(batch['nativeVerified'])
                cursor = 0
                for index, ((family, original, expected), event) in enumerate(
                        zip(ordered, batch['events'])):
                    with self.subTest(label=label, order=permutation, family=family):
                        size = len(original.encode('utf8'))
                        self.assertEqual(event['index'], index)
                        self.assertEqual((event['startByte'], event['endByte']),
                                         (cursor, cursor+size))
                        self.assertEqual(data[cursor:cursor+size], original.encode('utf8'))
                        assert_truth(self, original, expected, event['preview'])
                        cursor += size
                        if index < len(ordered)-1:
                            self.assertEqual(data[cursor:cursor+1], b'\n')
                            cursor += 1
                self.assertEqual(cursor, len(data))
                self.assertEqual(
                    [(s['startByte'], s['endByte']) for s in batch['separators']],
                    [(sum(len(x[1].encode('utf8'))+1 for x in ordered[:i+1])-1,
                      sum(len(x[1].encode('utf8'))+1 for x in ordered[:i+1]))
                     for i in range(5)],
                )

    def test_duplicate_kv_preserves_both_values_but_never_overwrites_them(self):
        raw = 'srcip=192.0.2.10 srcip=198.51.100.10'
        result = preview(raw)
        # Repeated keys are valid physical observations represented as a list,
        # not a single normalized IP or evidence to auto-assign a scalar field.
        self.assertEqual(result['fields']['srcip'],
                         ['192.0.2.10', '198.51.100.10'])
        self.assertEqual(result['sourceSha256'], hashlib.sha256(raw.encode()).hexdigest())
        spans = [s for s in result['spans'] if s['path'] == 'srcip']
        self.assertEqual([raw.encode()[s['startByte']:s['endByte']].decode()
                          for s in spans], ['192.0.2.10', '198.51.100.10'])
        self.assertFalse(result['targetVerified'])

    def test_duplicate_json_and_cef_do_not_claim_clean_source_success(self):
        for raw in [
            '{"srcip":"192.0.2.10","srcip":"198.51.100.10"}',
            'CEF:0|Test|FW|1|100|Blocked|8|src=192.0.2.10 src=198.51.100.10',
        ]:
            with self.subTest(raw=raw):
                result = preview(raw)
                self.assertNotEqual(result['status'], 'SOURCE_PARSED')
                self.assertTrue(result['issues'] or result['residuals'])
                self.assertEqual(result['sourceBytes'], len(raw.encode('utf8')))


if __name__ == '__main__':
    unittest.main()
