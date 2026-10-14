import dataclasses
import unittest
from security_source import parse_security_source
from security_cef import parse_security_cef
from security_leef import parse_security_leef
try:
    from security_document import parse_security_document
except ModuleNotFoundError:
    parse_security_document=None


def current(raw):
    return parse_security_leef(raw,base_parser=lambda text:parse_security_cef(text,base_parser=parse_security_source))

HEADER=[r'#separator \x09','#fields\tuid\taction','#types\tstring\tstring']

class MultiPassDocumentTests(unittest.TestCase):
    def parse(self,rows):
        self.assertIsNotNone(parse_security_document)
        doc=parse_security_document(rows,base_parser=current)
        self.assertEqual(rows,doc.records)
        self.assertEqual(list(range(len(rows))),sorted(doc.metadata_indices+[i for i,_ in doc.events]))
        return doc

    def test_active_schema_does_not_capture_security_formats(self):
        foreign=['{"action":"BLOCK","httpRequest":{"headers":[]}}',
                 'CEF:0|Vendor|IPS|1|42|Alert|5|src=192.0.2.1 msg="a b"',
                 'LEEF:2.0|Vendor|IPS|1|42|x7C|src=192.0.2.1|action=deny',
                 '@cee: {"event_type":"alert","alert":{"signature_id":42}}',
                 'action=deny src=192.0.2.2']
        rows=HEADER+['row1\tallow']+foreign+['row2\tdeny']
        events=dict(self.parse(rows).events)
        for i,raw in enumerate(foreign,4):self.assertEqual(dataclasses.asdict(current(raw)),dataclasses.asdict(events[i]))
        self.assertEqual({'uid':'row2','action':'deny'},events[9].vendor_fields)

    def test_close_drops_schema_state(self):
        rows=HEADER+['row1\tallow','#close\t2026-10-14-10-00-00','row2\tdeny','action=allow src=192.0.2.3']
        events=dict(self.parse(rows).events)
        self.assertNotEqual('DECLARED_SCHEMA_ROW',events[5].syntax)
        self.assertEqual(dataclasses.asdict(current(rows[6])),dataclasses.asdict(events[6]))

    def test_unknown_hash_record_is_not_hidden(self):
        rows=HEADER+['#future_security_record\topaque','row1\tallow']
        doc=self.parse(rows);events=dict(doc.events)
        self.assertNotIn(3,doc.metadata_indices);self.assertEqual(rows[3],events[3].raw)
        self.assertNotEqual('SOURCE_PARSED',events[3].status)

    def test_fields_rotation_invalidates_types(self):
        rows=HEADER+['row1\tallow','#fields\tflow\taction\tbytes','row2\tdeny\t8',
                     '#types\tstring\tstring\tcount','row3\tdeny\t9']
        events=dict(self.parse(rows).events)
        self.assertNotEqual('SOURCE_PARSED',events[5].status)
        self.assertEqual({'flow':'row3','action':'deny','bytes':'9'},events[7].vendor_fields)

    def test_separator_rotation_does_not_reuse_old_schema(self):
        rows=HEADER+['row1\tallow',r'#separator \x7c','#fields|flow|bytes','#types|string|count','f2|9']
        events=dict(self.parse(rows).events);self.assertEqual({'flow':'f2','bytes':'9'},events[7].vendor_fields)

    def test_invalid_separator_resets_state_and_is_visible(self):
        rows=HEADER+['row1\tallow',r'#separator \x00','row2\tdeny']
        doc=self.parse(rows);events=dict(doc.events)
        self.assertIn(4,events);self.assertNotIn(4,doc.metadata_indices)
        self.assertNotEqual('DECLARED_SCHEMA_ROW',events[5].syntax)

    def test_declared_repeated_names_and_width_mismatch_fail_closed(self):
        rows=[r'#separator \x09','#fields\tuid\tuid','#types\tstring\tstring','a\tb']
        event=dict(self.parse(rows).events)[3]
        self.assertEqual({},event.vendor_fields);self.assertNotEqual('SOURCE_PARSED',event.status)
        rows=HEADER+['only-one-column']
        event=dict(self.parse(rows).events)[3];self.assertEqual({},event.vendor_fields);self.assertNotEqual('SOURCE_PARSED',event.status)

if __name__=='__main__':unittest.main()
