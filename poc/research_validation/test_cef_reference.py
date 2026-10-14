"""CEF native-source oracle contract, independently authored inputs only."""
import copy
import unittest
from cef_reference import reference_cef,score_cef

PREFIX='CEF:0|Example|IPS|1|sig42|Blocked|7|'

class CEFReferenceTests(unittest.TestCase):
    def test_header_and_extension_escapes_are_different(self):
        r=reference_cef(r'CEF:0|Example|IPS|1|sig42|A\|B=C|7|msg=a\=b | c path=C:\\temp note=line\nnext')
        self.assertEqual(r['tree']['cef_header']['name'],'A|B=C')
        self.assertEqual(r['tree']['cef_extension'],{'msg':'a=b | c','path':'C:\\temp','note':'line\nnext'})
    def test_quotes_are_literal_and_not_shell_grouping(self):
        r=reference_cef(PREFIX+'msg="blocked connection" act=deny')
        self.assertEqual(r['tree']['cef_extension']['msg'],'"blocked connection"')
    def test_only_last_space_is_separator(self):
        r=reference_cef(PREFIX+'msg=a   act=deny   ')
        self.assertEqual(r['tree']['cef_extension'],{'msg':'a  ','act':'deny'})
    def test_duplicates_empty_and_utf8_spans(self):
        raw=PREFIX+'user=Zoë tag=a tag=b empty= last=x';r=reference_cef(raw)
        self.assertEqual(r['tree']['cef_extension']['tag'],['a','b'])
        self.assertEqual(r['tree']['cef_extension']['empty'],'')
        p,v,a,b=next(f for f in r['fields'] if f[0]==('cef_extension','user'))
        self.assertEqual(raw.encode()[a:b].decode(),'Zoë')
    def test_escaped_equal_does_not_create_field(self):
        r=reference_cef(PREFIX+r'msg=blocked nested\=value act=deny')
        self.assertEqual(r['tree']['cef_extension'],{'msg':'blocked nested=value','act':'deny'})
    def test_unresolved_structure_and_limits_are_not_gold(self):
        for raw in ('CEF:0|x',PREFIX+'broken',PREFIX+'msg=bad\\','CEF:9|a|b|c|d|e|f|',PREFIX+'msg=\x00'):
            with self.subTest(raw=raw),self.assertRaises(ValueError):reference_cef(raw)
    def test_wrong_span_and_missing_duplicate_fail_scoring(self):
        ref=reference_cef(PREFIX+'tag=a tag=b')
        event={'raw':ref['raw'],'vendor_fields':ref['tree'],'status':'SOURCE_PARSED',
          'value_spans':[{'path':'.'.join(p),'start_byte':a,'end_byte':b} for p,v,a,b in ref['fields']]}
        self.assertEqual(score_cef([ref],[event])['FP'],0)
        event=copy.deepcopy(event);event['value_spans'][-1]['end_byte']-=1
        result=score_cef([ref],[event]);self.assertEqual((result['FP'],result['FN'],result['falsely_complete']),(1,1,1))
    def test_no_engine_import(self):
        import ast,cef_reference
        from pathlib import Path
        tree=ast.parse(Path(cef_reference.__file__).read_text())
        imports={n.module for n in ast.walk(tree) if isinstance(n,ast.ImportFrom)}
        self.assertFalse(imports & {'engine','source_parse','structured_source','security_source','candidate'})

if __name__=='__main__':unittest.main()
