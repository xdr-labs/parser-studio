"""Authored conformance and negative tests, not unseen-vendor evidence."""
import csv
import io
import random
import unittest
from candidate import (parse_candidate, parse_document, infer_dialect,
                       delimited_cells, byte_offsets, MAX_FIELDS)
from source_parse import parse_source, assert_source_accounting

class CandidateTests(unittest.TestCase):
    def check(self, raw):
        event = parse_candidate(raw)
        assert_source_accounting(event)
        self.assertEqual(event.raw, raw)
        self.assertFalse(event.normalization_attempted)
        return event

    def test_duplicate_and_following_fields(self):
        raw = 'tag=alpha tag=beta result=deny'
        self.assertEqual(parse_source(raw).vendor_fields, {'tag':'alpha'})
        event = self.check(raw)
        self.assertEqual(event.vendor_fields, {'tag':['alpha','beta'], 'result':'deny'})
        self.assertEqual(event.status, 'SOURCE_PARSED')
        self.assertEqual([s.path for s in event.value_spans], ['tag[0]','tag[1]','result'])

    def test_quotes_backslashes_and_unicode(self):
        raw = "user='Jos\u00e9 Smith' path=\"C:\\logs\\new\" note=\"x=1 y=2\""
        event = self.check(raw)
        self.assertEqual(event.vendor_fields, {'user':'Jos\u00e9 Smith','path':'C:\\logs\\new','note':'x=1 y=2'})
        for s in event.value_spans:
            raw.encode()[s.start_byte:s.end_byte].decode('utf8')

    def test_empty_and_constant_fields(self):
        event = self.check('action=deny proto=tcp empty= quoted="" n=000123')
        self.assertEqual(event.vendor_fields, {'action':'deny','proto':'tcp','empty':'','quoted':'','n':'000123'})
        self.assertEqual(event.primitive_fields, 5)

    def test_container_is_one_native_value(self):
        raw = 'payload={"x": 1, "msg": "a=b"} address=[2001:db8::1]:443 ok=yes'
        event = self.check(raw)
        self.assertEqual(event.vendor_fields['payload'], '{"x": 1, "msg": "a=b"}')
        self.assertEqual(event.vendor_fields['address'], '[2001:db8::1]:443')
        self.assertEqual(event.status, 'SOURCE_PARSED')

    def test_malformed_tail_is_not_a_field(self):
        for tail in ('bad="open', "bad='open", 'bad={"a": 1', 'bad=[} mismatch', 'bad="x"suffix'):
            event = self.check('good=one ' + tail)
            self.assertEqual(event.vendor_fields, {'good':'one'})
            self.assertEqual(event.status, 'PARTIAL')
            self.assertGreater(event.residual_bytes, 0)

    def test_no_prose_query_promotion(self):
        for raw in ('https://example.test/?x=1&y=2', 'literal "a=1 b=2" prose', 'one, two, three'):
            event = self.check(raw)
            self.assertNotEqual(event.status, 'SOURCE_PARSED')

    def test_limits_and_bad_keys(self):
        for raw in ('x=1\x00 y=2', 'x='+'a'*131072, '__proto__=x safe=y'):
            self.assertNotEqual(self.check(raw).status, 'SOURCE_PARSED')
        event = self.check(' '.join(f'key{i}=v' for i in range(MAX_FIELDS+1)))
        self.assertLessEqual(event.primitive_fields, MAX_FIELDS)
        self.assertEqual(event.status, 'PARTIAL')

    def test_csv_scanner_matches_independent_stdlib(self):
        rng = random.Random(8401)
        for delimiter in (',',';','|','\t'):
            for quote in ('"', "'"):
                for _ in range(40):
                    values = [str(rng.randrange(10000)), 'a'+delimiter+'b', 'q'+quote+'z', '', '\u00e9']
                    stream = io.StringIO(newline='')
                    csv.writer(stream, delimiter=delimiter, quotechar=quote, lineterminator='\n').writerow(values)
                    raw = stream.getvalue()[:-1]
                    cells = delimited_cells(raw, delimiter, quote)
                    self.assertEqual([v for v,_,_ in cells], values)
                    self.assertEqual(next(csv.reader([raw], delimiter=delimiter, quotechar=quote, strict=True)), values)
                    for _,a,b in cells:
                        self.assertTrue(0 <= a <= b <= len(raw))

    def test_dialect_raw_only_and_frozen_width(self):
        train = ['101;deny;alpha','102;allow;beta','103;deny;gamma']
        model = infer_dialect(train)
        self.assertIsNotNone(model)
        self.assertEqual(model.delimiter, ';')
        self.assertEqual(model.width, 3)
        self.assertEqual(parse_candidate('104;allow;delta', dialect=model).vendor_fields['column_0'], '104')
        event = parse_candidate('104;allow;delta;extra', dialect=model)
        self.assertEqual(event.status, 'RAW_ONLY')
        self.assertEqual(len(model.train_sha256), 3)

    def test_dialect_ambiguity_and_prose_abstain(self):
        for train in (['1;a|2','3;b|4','5;c|6'], ['one, two, three','red, green, blue','small, medium, large'], ['1;one','2;two']):
            self.assertIsNone(infer_dialect(train))

    def test_source_metadata_rotates_without_guessing_types(self):
        raws = ['#separator \\x09','#fields\tts\tid.orig_h','#types\ttime\taddr','1.25\t192.0.2.1',
                '#fields\tvalue\tid','#types\tcount\tstring','0003\talpha','#close\t0','tail']
        doc = parse_document(raws)
        self.assertEqual(doc.records, raws)
        self.assertEqual(len(doc.events)+len(doc.metadata_indices), len(raws))
        self.assertEqual(doc.events[0][1].vendor_fields, {'ts':'1.25','id.orig_h':'192.0.2.1'})
        self.assertEqual(doc.events[1][1].vendor_fields, {'value':'0003','id':'alpha'})
        self.assertEqual(doc.events[2][1].status, 'RAW_ONLY')

    def test_bad_record_under_metadata_stays_raw(self):
        for raw in ('a\nb\tc', '\t'.join(['v']*1025)):
            doc = parse_document(['#separator \\x09','#fields\ta\tb','#types\tstring\tstring',raw])
            self.assertEqual(doc.events[0][1].status, 'RAW_ONLY')
            assert_source_accounting(doc.events[0][1])

    def test_bad_metadata_cannot_certify(self):
        for header in ('#fields\ta\ta','#fields\t__proto__\tb','#fields\ta\tb\tc'):
            doc = parse_document(['#separator \\x09',header,'#types\tstring\tstring','a\tb'])
            self.assertEqual(doc.events[0][1].status, 'RAW_ONLY')

if __name__ == '__main__':
    unittest.main()
