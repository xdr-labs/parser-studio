"""WAF/IPS JSON negative controls: never label invalid or unbounded data parsed."""
from pathlib import Path
import json,sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_parse import parse_source,assert_source_accounting
from security_framing import parse_security_batch,assert_batch_accounting
from engine import MAX_CAPTURED_FIELDS


class SecurityJsonLimitsTests(unittest.TestCase):
    def test_non_json_number_constants_are_not_parsed_security_values(self):
        for token in ('NaN','Infinity','-Infinity'):
            raw='{"event_type":"alert","alert":{"severity":'+token+'}}'
            with self.subTest(token=token):
                out=parse_source(raw)
                self.assertEqual('RAW_ONLY',out.status)
                self.assertEqual(raw,out.raw);assert_source_accounting(out)

    def test_number_range_cannot_silently_turn_into_infinity(self):
        raw='{"timestamp":1791921600000,"httpRequest":{"bodySize":1e999}}'
        out=parse_source(raw)
        self.assertEqual('RAW_ONLY',out.status)
        self.assertTrue(any('NUMBER' in issue for issue in out.issues))
        assert_source_accounting(out)

    def test_json_leaf_limit_has_no_off_by_one_acceptance(self):
        for extra in (0,1):
            raw=json.dumps({f'field_{i}':i for i in range(MAX_CAPTURED_FIELDS+extra)})
            out=parse_source(raw)
            self.assertEqual('RAW_ONLY' if extra else 'SOURCE_PARSED',out.status)
            self.assertEqual(raw,out.raw);assert_source_accounting(out)

    def test_empty_containers_after_limit_are_still_visible(self):
        values={f'field_{i}':i for i in range(MAX_CAPTURED_FIELDS)}
        values['empty_object']={};values['empty_array']=[]
        raw=json.dumps(values);out=parse_source(raw)
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertEqual(values,out.vendor_fields)
        self.assertEqual(MAX_CAPTURED_FIELDS,out.primitive_fields)

    def test_invalid_record_does_not_block_next_valid_security_record(self):
        raw='{"event_type":"alert","severity":NaN}\n{"action":"BLOCK","timestamp":1791921600000}'
        batch=parse_security_batch(raw);assert_batch_accounting(batch)
        self.assertEqual(['RAW_ONLY','SOURCE_PARSED'],[f.event.status for f in batch.frames])

    def test_large_integer_and_finite_float_remain_original_types(self):
        value={'flow_id':900719925474099312345,'severity':2,'ratio':0.125,'active':True,'other':None}
        out=parse_source(json.dumps(value))
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertEqual(value,out.vendor_fields)
        self.assertIs(type(out.vendor_fields['flow_id']),int)
        self.assertIs(type(out.vendor_fields['ratio']),float)


if __name__=='__main__':unittest.main()
