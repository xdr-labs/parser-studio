"""Lossless source JSON path identity, separate from semantic path aliases."""
import json,sys,unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parent))
from source_parse import parse_source,assert_source_accounting


def reference_leaves(node,path=()):
    if isinstance(node,dict):
        for key,value in node.items():yield from reference_leaves(value,path+(key,))
    elif isinstance(node,list):
        for index,value in enumerate(node):yield from reference_leaves(value,path+(index,))
    else:yield path,node


def examples():
    for index in range(32):
        yield {'a.b':index,'a':{'b':str(index)},'a[0]':True,'empty':{'':None}}
        yield {'a[0]':index,'a':[index+1,{'0':index+2}],'0':'numeric-key'}
        yield {'':index,'/vendor~':{'':f'Zoë {index}','with.dot':'literal'},'list':[]}
        yield [{'':index,'child.key':{'[0]':index+1}},None,True,f'value-{index}']


class SourceJsonPathTests(unittest.TestCase):
    def check(self,data):
        raw=json.dumps(data,ensure_ascii=False,separators=(',',':'))
        out=parse_source(raw)
        expected_tree=data if isinstance(data,dict) else {'$array':data}
        expected=dict(reference_leaves(expected_tree))
        self.assertEqual(expected_tree,out.vendor_fields)
        self.assertEqual(len(expected),len(out.value_spans))
        actual={}
        for span in out.value_spans:
            self.assertIsNotNone(span.source_segments)
            self.assertNotIn(span.source_segments,actual)
            actual[span.source_segments]=json.loads(raw.encode()[span.start_byte:span.end_byte])
        self.assertEqual(expected,actual)
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertFalse(out.normalization_attempted)
        self.assertEqual(raw,out.raw)
        assert_source_accounting(out)
        return out

    def test_literal_dotted_key_and_nested_field_keep_both_spans(self):
        out=self.check({'a.b':1,'a':{'b':2},'vendor':True})
        self.assertIn(('a.b',),[x.source_segments for x in out.value_spans])
        self.assertIn(('a','b'),[x.source_segments for x in out.value_spans])

    def test_array_text_and_numeric_object_key_are_distinct(self):
        self.check({'a[0]':'literal','a':[7], '0':{'0':9}})

    def test_empty_keys_and_root_arrays_have_source_locations(self):
        self.check({'':1,'nested':{'':2}})
        self.check([{'':1},None,True])

    def test_ordinary_display_paths_stay_backward_compatible(self):
        out=self.check({'vendor':{'name':'Zoë'},'items':[1,2]})
        self.assertEqual(['vendor.name','items[0]','items[1]'],[s.path for s in out.value_spans])

    def test_wrapped_json_preserves_source_segments_and_utf8_offsets(self):
        raw='<134>Nov 14 10:11:12 host app: {"a.b":"Zoë","a":{"b":2}}'
        out=parse_source(raw)
        spans=[x for x in out.value_spans if x.path.startswith('body.')]
        self.assertEqual(2,len(spans))
        self.assertEqual({('body','a.b'): 'Zoë',('body','a','b'):2},
            {x.source_segments:json.loads(raw.encode()[x.start_byte:x.end_byte]) for x in spans})
        self.assertEqual('SOURCE_PARSED',out.status)
        assert_source_accounting(out)

    def test_128_visible_original_json_records_against_stdlib_tree(self):
        for data in examples():self.check(data)

if __name__=='__main__':unittest.main()
