"""Current-parser-first document composition, no legacy KV replacement."""
import dataclasses
import unittest
from source_parse import parse_source
from security_document import parse_security_document

class SecurityDocumentTests(unittest.TestCase):
    def test_no_metadata_means_identical_current_outputs(self):
        rows=['{"action":"BLOCK","ruleGroupList":[]}',r'message=visible\ value action=deny','tag=a tag=b result=deny']
        doc=parse_security_document(rows,base_parser=parse_source)
        self.assertEqual(doc.metadata_indices,[])
        for i,event in doc.events:self.assertEqual(dataclasses.asdict(event),dataclasses.asdict(parse_source(rows[i])))

    def test_explicit_source_names_and_ordinary_fallback(self):
        rows=['{"action":"BLOCK"}',r'#separator \x09','#fields\tuid\taction','#types\tstring\tstring','a1\tallow']
        calls=[]
        def base(raw):calls.append(raw);return parse_source(raw)
        doc=parse_security_document(rows,base_parser=base);events=dict(doc.events)
        self.assertEqual(events[4].vendor_fields,{'uid':'a1','action':'allow'})
        self.assertEqual(events[0].vendor_fields,{'action':'BLOCK'})
        self.assertIn(rows[0],calls);self.assertNotIn(rows[4],calls)
        self.assertEqual(doc.records,rows)

    def test_invalid_schema_stays_incomplete(self):
        rows=[r'#separator \x09','#fields\tuid\tuid','#types\tstring\tstring','a1\tallow']
        doc=parse_security_document(rows,base_parser=parse_source);event=dict(doc.events)[3]
        self.assertNotEqual(event.status,'SOURCE_PARSED');self.assertEqual(event.vendor_fields,{})
        self.assertEqual(doc.records,rows)

if __name__=='__main__':unittest.main()
