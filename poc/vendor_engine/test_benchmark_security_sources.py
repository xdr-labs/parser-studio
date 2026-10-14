"""Independent security-source truth and large nested WAF/IPS regression."""
from pathlib import Path
import json
import sys
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from benchmark_security_sources import reference_json,_tree_leaves,_cell,evaluate,MANIFEST
from security_source import parse_security_source
from source_parse import assert_source_accounting


def complex_waf(headers=200,groups=8):
    return {'timestamp':1791943872000,'formatVersion':1,'webaclId':'arn:aws:wafv2:region:123456789012:regional/webacl/test/id',
        'terminatingRuleId':'rule-1','terminatingRuleType':'MANAGED_RULE_GROUP','action':'BLOCK',
        'ruleGroupList':[{'ruleGroupId':f'group-{i}','terminatingRule':{'ruleId':f'rule-{i}',
            'action':'BLOCK','ruleMatchDetails':[{'conditionType':'SQL_INJECTION','location':'ARGS','matchedData':['x=y','a,b']} ]},
            'nonTerminatingMatchingRules':[{'ruleId':'monitor','action':'COUNT'}],'excludedRules':[]} for i in range(groups)],
        'nonTerminatingMatchingRules':[{'ruleId':'captcha','action':'CAPTCHA','captchaResponse':{'responseCode':200,'solveTimestamp':1791943871}}],
        'rateBasedRuleList':[{'rateBasedRuleId':'rate-1','limitKey':'IP','maxRateAllowed':2000}],
        'labels':[{'name':'awswaf:managed:test:label'}],'oversizeFields':['REQUEST_BODY'],
        'httpRequest':{'clientIp':'2001:db8::4','country':'KR','headers':[{'name':'x-repeated' if i%2 else 'User-Agent',
            'value':f'client-{i} unicode=Zoë quote=" x=y,a:b'} for i in range(headers)],
            'uri':'/path/%2f?not=normalized','args':'a=one&a=two&q=%7B%22x%22%3A1%7D',
            'httpVersion':'HTTP/2.0','httpMethod':'POST','requestId':'req-1'},
        'responseCodeSent':None,'vendor.extra':{'0':'numeric object key','a[0]':'literal bracket key','optional':[]}}


def complex_ips():
    return {'timestamp':'2026-10-14T10:11:12.123456+0900','event_type':'alert',
        'flow_id':18446744073709551615,'src_ip':'2001:db8::1','dest_ip':'2001:db8::2','src_port':49152,'dest_port':443,
        'proto':'TCP','app_proto':'tls','alert':{'action':'blocked','gid':1,'signature_id':900001,'rev':3,
            'signature':'Demo detection: key=value, opaque description','category':'Security policy','severity':1,
            'metadata':{'attack_target':['Server','Client'],'deployment':['Perimeter'],'affected_product':['Service']},
            'rule':'alert tcp any any -> any 443 (msg:"opaque rule text"; sid:900001;)'},
        'http':{'url':'/login?q=a=b&next=%2f','request_headers':[{'name':'x-id','value':'one'},{'name':'x-id','value':'two'}]},
        'tls':{'subject':'CN=service, O=Example','issuerdn':'','ja3':{'hash':'a'*32,'string':'1,2-3,4-5'},'chain':[]},
        'files':[{'filename':'x,y=a.txt','size':4096,'sha256':'b'*64}],
        'payload':'YWJjK2RlZj0=','payload_printable':'POST /x HTTP/1.1\r\nX-Id: one\r\n\r\na=b&x=y',
        'packet':'AAECAwQF','flow':{'pkts_toserver':10,'bytes_toserver':4096},'metadata':{},'optional':None}


class SecurityReferenceTests(unittest.TestCase):
    def assert_source(self,data,prefix=''):
        encoded=json.dumps(data,ensure_ascii=False,indent=2 if prefix=='' else None)
        tree,leaves=reference_json(encoded)
        self.assertEqual(data,tree)
        self.assertEqual(sorted(_cell(p,v) for p,v in _tree_leaves(data)),sorted(_cell(x.path,x.value) for x in leaves))
        raw=prefix+encoded;out=parse_security_source(raw)
        self.assertEqual('SOURCE_PARSED',out.status)
        self.assertEqual(data,out.vendor_fields)
        self.assertEqual(len(leaves),len(out.value_spans))
        expected={(x.path,x.start_byte+len(prefix.encode()),x.end_byte+len(prefix.encode())) for x in leaves}
        self.assertEqual(expected,{(x.source_segments,x.start_byte,x.end_byte) for x in out.value_spans})
        self.assertEqual(raw,out.raw);assert_source_accounting(out)

    def test_large_waf_headers_rule_groups_and_nested_matches(self):
        for headers,groups in ((0,0),(1,1),(32,3),(200,8)):
            with self.subTest(headers=headers,groups=groups):self.assert_source(complex_waf(headers,groups))

    def test_ips_metadata_payload_and_max_unsigned_flow_id(self):
        self.assert_source(complex_ips())
        self.assert_source(complex_ips(),'@cee: ')

    def test_reference_paths_do_not_collapse_literal_and_nested_keys(self):
        self.assert_source({'a.b':1,'a':{'b':2},'array[0]':'literal','array':['item'],'':None})

    def test_reference_rejects_duplicates_and_nonfinite_values(self):
        for raw in ('{"a":1,"a":2}','{"x":NaN}','{"x":Infinity}'):
            with self.assertRaises(ValueError):reference_json(raw)

    def test_reference_unicode_duplicate_values_keep_distinct_offsets(self):
        raw='{"headers":[{"name":"x","value":"Zoë"},{"name":"x","value":"Zoë"}]}'
        tree,leaves=reference_json(raw)
        duplicate=[leaf for leaf in leaves if leaf.value=='Zoë']
        self.assertEqual(2,len(duplicate))
        self.assertNotEqual(duplicate[0].start_byte,duplicate[1].start_byte)
        for leaf in duplicate:self.assertEqual(leaf.value,json.loads(raw.encode()[leaf.start_byte:leaf.end_byte]))

    @unittest.skipUnless(all((MANIFEST.parent/'.cache'/f['cache_path']).is_file() for f in json.loads(MANIFEST.read_text())['fixtures']),
                         'Local license-restricted security fixtures are unavailable')
    def test_pinned_security_corpus_and_derived_transports_have_explicit_denominators(self):
        result=evaluate()
        raw=result['direct_original_security_events'];framed=result['documented_cee_transport_variants']
        self.assertEqual(77,raw['candidate']['events'])
        self.assertEqual(2110,raw['candidate']['TP'])
        self.assertEqual(0,raw['candidate']['FP']+raw['candidate']['FN'])
        self.assertEqual(2110,raw['candidate']['exact_span_TP'])
        self.assertEqual(198,framed['candidate']['events'])
        self.assertEqual(5127,framed['candidate']['TP'])
        self.assertEqual(5127,framed['candidate']['exact_span_TP'])
        self.assertEqual(0,framed['baseline']['TP'])
        self.assertEqual(0,result['excluded_events'])
        self.assertFalse(result['dictionary_attempted'])
        self.assertFalse(result['masking_optimization'])
        self.assertFalse(result['native_verified'])


if __name__=='__main__':unittest.main()
