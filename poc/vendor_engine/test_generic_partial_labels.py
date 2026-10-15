"""Partial delimiter label/value recovery remains source-only."""
import unittest

from generic_partial_labels import augment_incomplete_labels
from security_source import parse_security_source
from source_parse import assert_source_accounting


class GenericPartialLabelTests(unittest.TestCase):
    def test_comma_labels_add_exact_values_but_stay_partial(self):
        raw=(
            'Info: query. File Name = sample.bin, MID = 5, '
            'File Size = 12345 bytes, File Type = application/octet-stream '
            'trailing prose'
        )
        event=augment_incomplete_labels(parse_security_source(raw))
        assert_source_accounting(event)
        self.assertEqual('PARTIAL',event.status)
        labels=event.vendor_fields['generic_labels']
        self.assertEqual(['sample.bin'],labels['File Name'])
        self.assertEqual(['5'],labels['MID'])
        self.assertEqual(['12345 bytes'],labels['File Size'])

    def test_semicolon_colon_labels_are_source_backed(self):
        raw='notice; Action: blocked; User: example-user; Rule: policy one'
        event=augment_incomplete_labels(parse_security_source(raw))
        self.assertEqual('PARTIAL',event.status)
        self.assertEqual(['blocked'],event.vendor_fields['generic_labels']['Action'])
        data=raw.encode()
        for span in event.value_spans:
            if span.path.startswith('generic_labels.'):
                self.assertTrue(data[span.start_byte:span.end_byte])

    def test_single_label_url_and_nested_label_prose_abstain(self):
        for raw in (
            'notice File Name = sample.bin trailing prose',
            'https://example.test/a:b,c=d,e=f',
            'notice, A = value B = nested, C = ok, D = ok',
        ):
            with self.subTest(raw=raw):
                event=augment_incomplete_labels(parse_security_source(raw))
                self.assertNotIn('generic_labels',event.vendor_fields)

    def test_bracket_labels_are_exact_candidate_only_values(self):
        raw=(
            'Login Success [user: analyst] [Source: 192.0.2.7] '
            '[localport: 22] trailing prose'
        )
        event=augment_incomplete_labels(parse_security_source(raw))
        assert_source_accounting(event)
        self.assertEqual('PARTIAL',event.status)
        labels=event.vendor_fields['generic_labels']
        self.assertEqual(['analyst'],labels['user'])
        self.assertEqual(['192.0.2.7'],labels['Source'])
        self.assertEqual(['22'],labels['localport'])
        data=raw.encode()
        for span in event.value_spans:
            if span.path.startswith('generic_labels.'):
                self.assertTrue(data[span.start_byte:span.end_byte])

    def test_bracket_without_explicit_separator_is_ignored(self):
        raw='alert [ordinary prose] [0x0, 0x0] trailing'
        event=augment_incomplete_labels(parse_security_source(raw))
        self.assertNotIn('generic_labels',event.vendor_fields)

    def test_existing_spans_and_complete_events_are_never_changed(self):
        complete=parse_security_source('a=1 b=2 c=3 d=4 e=5')
        self.assertIs(complete,augment_incomplete_labels(complete))
        raw='prefix user=Zoë action=allow, Code = 7, Detail = some text, tail'
        base=parse_security_source(raw)
        event=augment_incomplete_labels(base)
        old={(s.path,s.start_byte,s.end_byte) for s in base.value_spans}
        new={(s.path,s.start_byte,s.end_byte) for s in event.value_spans}
        self.assertTrue(old<=new)
        self.assertEqual(raw,event.raw)
        self.assertNotEqual('SOURCE_PARSED',event.status)


if __name__=='__main__':
    unittest.main()
