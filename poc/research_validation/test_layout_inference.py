"""Independent H2 layout tests; no H3 metadata importer or evaluator changes."""
import dataclasses
import os
from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / '.cache/latest-baseline/poc/vendor_engine'))
from source_parse import parse_source, assert_source_accounting
sys.path.insert(0, str(ROOT))

if os.environ.get('LAYOUT_TEST_BASELINE') == '1':
    from candidate import infer_dialect as fit_layout
    from dialect_adapter import parse_with_dialect as parse_with_layout
else:
    from layout_inference import fit_layout, parse_with_layout


class LayoutTests(unittest.TestCase):
    def parse(self, raw, training):
        model = fit_layout(training)
        self.assertIsNotNone(model)
        result = parse_with_layout(raw, model, base_parser=parse_source)
        assert_source_accounting(result)
        self.assertEqual(raw, result.raw)
        return result

    def test_unobserved_quote_style_selected_only_when_unique(self):
        train = [f'{i};allow;node{i}' for i in range(10, 14)]
        result = self.parse("123;deny;'node;edge'", train)
        self.assertEqual(result.vendor_fields,
                         {'column_0': '123', 'column_1': 'deny', 'column_2': 'node;edge'})
        self.assertEqual(result.status, 'SOURCE_PARSED')

    def test_different_valid_quote_interpretations_abstain(self):
        result = self.parse("123;deny;'plain'", [f'{i};allow;node{i}' for i in range(10,14)])
        self.assertNotEqual(result.status, 'SOURCE_PARSED')

    def test_same_width_source_switch_does_not_certify_prose(self):
        result = self.parse('the system;was restarted;check status',
                            [f'{i};allow;node{i}' for i in range(10,14)])
        self.assertNotEqual(result.status, 'SOURCE_PARSED')

    def test_space_layout_requires_multiple_typed_columns(self):
        train = [f'{i} 192.0.2.{i} 443 1234 allow' for i in range(10,14)]
        result = self.parse('101 192.0.2.100 80 9999 deny', train)
        self.assertEqual(result.primitive_fields, 5)
        self.assertEqual(result.vendor_fields['column_4'], 'deny')
        self.assertEqual(result.status, 'SOURCE_PARSED')

    def test_single_numeric_word_does_not_admit_space_prose(self):
        self.assertIsNone(fit_layout([f'retry number {i} failed again' for i in range(10,14)]))

    def test_multiline_quoted_value_keeps_utf8_spans(self):
        result = self.parse('101;"Zo\u00eb\nSmith";done',
                            [f'{i};"analyst;name";done' for i in range(10,14)])
        self.assertEqual(result.vendor_fields['column_1'], 'Zo\u00eb\nSmith')
        span = result.value_spans[1]
        self.assertEqual(result.raw.encode()[span.start_byte:span.end_byte].decode(), 'Zo\u00eb\nSmith')

    def test_current_kv_and_json_are_never_replaced(self):
        train = [f'{i},1,2,3,4' for i in range(10,14)]
        model = fit_layout(train)
        for raw in ('message=a,b,c,d,e', '{"a":1,"b":2,"c":3,"d":4,"e":5}',
                    'tag=a tag=b message=visible\\ value'):
            before = parse_source(raw)
            after = parse_with_layout(raw, model, base_parser=parse_source)
            self.assertEqual(dataclasses.asdict(before), dataclasses.asdict(after))

    def test_short_mixed_and_malformed_training_abstain(self):
        for train in (['1;a','2;b'], ['1;a','2;b','3;c;d'],
                      ['1;"a','2;"b','3;"c'], ['x=1 a=b','x=2 a=b','x=3 a=b']):
            self.assertIsNone(fit_layout(train))

    def test_malformed_and_invalid_size_preserve_base(self):
        train = [f'{i};"a;b";done' for i in range(10,14)]
        model = fit_layout(train)
        for raw in ('123;"unclosed', '123;a;b;c', '123;bad\x00;done', 'x'*131073):
            before = parse_source(raw)
            after = parse_with_layout(raw, model, base_parser=parse_source)
            self.assertEqual(dataclasses.asdict(before), dataclasses.asdict(after))

    def test_shape_drift_retains_syntactic_fields_without_certifying(self):
        result = self.parse('NA;allow;node', [f'{i};allow;node{i}' for i in range(10,14)])
        self.assertEqual(result.vendor_fields['column_0'], 'NA')
        self.assertEqual(result.primitive_fields, 3)
        self.assertEqual(result.status, 'PARTIAL')

    @unittest.skipIf(os.environ.get('LAYOUT_TEST_BASELINE') == '1', 'New bounded model-bank interface')
    def test_unlabeled_width_groups_and_bounds(self):
        from layout_inference import fit_layouts
        rows = [f'{i} 192.0.2.{i} 443 99 allow' for i in range(10,14)]
        rows += [f'{i} 192.0.2.{i} 443 99 allow extra' for i in range(20,24)]
        models = fit_layouts(rows)
        self.assertEqual(len(models), 2)
        for raw, count in [('100 192.0.2.100 443 99 allow',5),
                           ('200 192.0.2.200 443 99 allow extra',6)]:
            result = parse_with_layout(raw, models, base_parser=parse_source)
            self.assertEqual(result.primitive_fields,count)
        self.assertEqual(fit_layouts([f'{i};a;b' for i in range(65)]), ())

    def test_fitted_model_does_not_change_during_predictions(self):
        model = fit_layout([f'{i};allow;node{i}' for i in range(10,14)])
        before = dataclasses.asdict(model)
        for raw in ('999;deny;node', 'not;our;source', "999;deny;'node;other'"):
            parse_with_layout(raw, model, base_parser=parse_source)
        self.assertEqual(before, dataclasses.asdict(model))

if __name__ == '__main__':
    unittest.main()
