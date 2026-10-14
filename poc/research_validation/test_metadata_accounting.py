"""Metadata regressions for the previously unfinished Zeek comparison."""
import unittest
from candidate import parse_document
from source_parse import assert_source_accounting

class MetadataAccountingTests(unittest.TestCase):
    def test_preamble_is_retained_outside_field_success_denominator(self):
        rows=['### source provenance',r'#separator \x09','#fields\tuid\taction','#types\tstring\tstring','a1\tallow','#close\tend']
        doc=parse_document(rows,kv=False)
        self.assertEqual(doc.records,rows)
        self.assertEqual(set(doc.metadata_indices),{1,2,3,5})
        data=dict(doc.events);self.assertEqual(set(data),{0,4})
        self.assertEqual(data[0].status,'RAW_ONLY');self.assertEqual(data[0].vendor_fields,{})
        self.assertEqual(data[4].vendor_fields,{'uid':'a1','action':'allow'})
        for event in data.values():assert_source_accounting(event)

    def test_malformed_data_does_not_abort_subsequent_valid_record(self):
        rows=[r'#separator \x09','#fields\tuid\taction','#types\tstring\tstring','bad\nrecord\tdeny','a1\tallow']
        doc=parse_document(rows,kv=False);data=dict(doc.events)
        self.assertNotEqual(data[3].status,'SOURCE_PARSED')
        self.assertEqual(data[4].vendor_fields,{'uid':'a1','action':'allow'})
        self.assertEqual(len(doc.events)+len(doc.metadata_indices),len(rows))
        for event in data.values():assert_source_accounting(event)

if __name__=='__main__':unittest.main()
