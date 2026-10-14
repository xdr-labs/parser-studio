"""Mixed ordinary security sources must not inherit a stale table schema."""
import dataclasses
import unittest
from security_source import parse_security_source
from security_document import parse_security_document

HEADER=[r'#separator \x09','#fields\tuid\taction','#types\tstring\tstring']

class SecurityRotationTests(unittest.TestCase):
    def compare_base(self,rows,indices):
        doc=parse_security_document(rows,base_parser=parse_security_source)
        self.assertEqual(doc.records,rows)
        self.assertEqual(sorted([i for i,e in doc.events]+doc.metadata_indices),list(range(len(rows))))
        events=dict(doc.events)
        for i in indices:
            self.assertIn(i,events)
            self.assertEqual(dataclasses.asdict(events[i]),dataclasses.asdict(parse_security_source(rows[i])))
        return events

    def test_active_schema_preserves_waf_cef_leef_and_cee(self):
        foreign=['{"action":"BLOCK","httpRequest":{"headers":[]}}',
                 'CEF:0|Vendor|IPS|1|42|Alert|5|src=192.0.2.1',
                 'LEEF:2.0|Vendor|IPS|1|42|^|src=192.0.2.1^action=deny',
                 '@cee: {"event_type":"alert","alert":{"signature_id":42}}']
        rows=HEADER+['row1\tallow']+foreign+['row2\tdeny']
        events=self.compare_base(rows,range(4,8))
        self.assertEqual(events[8].vendor_fields,{'uid':'row2','action':'deny'})

    def test_close_releases_schema_for_following_event(self):
        rows=HEADER+['row1\tallow','#close\t2026-10-14-10-00-00','action=deny src=192.0.2.2']
        self.compare_base(rows,[5])

    def test_unknown_hash_record_is_not_hidden_as_metadata(self):
        rows=HEADER+['#unrecognized-source-event','row1\tallow']
        doc=parse_security_document(rows,base_parser=parse_security_source)
        self.assertNotIn(3,doc.metadata_indices)
        self.assertEqual(dict(doc.events)[3].raw,rows[3])
        self.assertNotEqual(dict(doc.events)[3].status,'SOURCE_PARSED')

    def test_new_fields_require_new_types(self):
        rows=HEADER+['row1\tallow','#fields\tflow\taction\tbytes','row2\tdeny\t8',
                     '#types\tstring\tstring\tcount','row3\tdeny\t9']
        doc=parse_security_document(rows,base_parser=parse_security_source);events=dict(doc.events)
        self.assertNotEqual(events[5].status,'SOURCE_PARSED')
        self.assertEqual(events[7].vendor_fields,{'flow':'row3','action':'deny','bytes':'9'})

    def test_rotation_does_not_reuse_old_delimiter(self):
        rows=HEADER+['row1\tallow',r'#separator \x7c','#fields|flow|bytes','#types|string|count','f2|9']
        doc=parse_security_document(rows,base_parser=parse_security_source)
        self.assertEqual(dict(doc.events)[7].vendor_fields,{'flow':'f2','bytes':'9'})

    def test_no_declaration_means_current_parser_only(self):
        self.compare_base(['{"action":"BLOCK"}','tag=a tag=b action=deny'],[0,1])

if __name__=='__main__':unittest.main()
