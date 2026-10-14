"""Independent self-authored security source gold and bounded regression."""
from pathlib import Path
from collections import Counter
import json,sys,unittest
sys.path.insert(0,str(Path(__file__).resolve().parent))
from benchmark_security_framing import streams,waf,ips,json_record,evaluate
from security_framing import parse_security_batch,assert_batch_accounting


class SecurityBenchmarkTests(unittest.TestCase):
    def test_independent_gold_has_exact_original_typed_values(self):
        rows=streams()
        self.assertEqual(96,len(rows))
        self.assertEqual(216,sum(len(row['events']) for row in rows))
        self.assertEqual(6048,sum(len(row['gold']) for row in rows))
        self.assertEqual(rows,streams())
        for row in rows:
            data=row['raw'].encode('utf8')
            for path,value,start,end in row['gold']:
                owners=[tree for a,b,tree in row['events'] if a<=start<=end<=b]
                self.assertEqual(1,len(owners));node=owners[0]
                for segment in path:node=node[segment]
                self.assertIs(type(value),type(node));self.assertEqual(value,node)
                token=data[start:end].decode('utf8')
                if isinstance(value,str):
                    decoded=json.loads(token) if token.startswith('"') else token
                else:decoded=json.loads(token)
                self.assertIs(type(value),type(decoded));self.assertEqual(value,decoded)

    def test_security_baseline_comparison_has_explicit_denominators(self):
        report=evaluate();after=report['candidate']['total'];before=report['baseline']['total']
        self.assertEqual((6048,0,0),(after['TP'],after['FP'],after['FN']))
        self.assertEqual(216,after['exact_record_boundaries'])
        self.assertEqual(216,after['exact_record_trees'])
        self.assertEqual(60,before['exact_record_boundaries'])
        self.assertEqual(0,report['external_upstream_scored_records'])
        self.assertEqual(0,report['excluded_records'])
        self.assertFalse(report['dictionary_attempted'])

    def test_lexical_layout_changes_preserve_nested_values_and_spans(self):
        for seed in range(20):
            items=[waf(seed),ips(seed)]
            for width in (None,1,3):
                records=[json_record(item,width) for item in items]
                raw='\r\n'.join(record['raw'] for record in records)
                result=parse_security_batch(raw);assert_batch_accounting(result)
                self.assertEqual(items,[f.event.vendor_fields for f in result.frames])
                self.assertEqual(2,len(result.frames))
                for f,r in zip(result.frames,records):
                    expected=Counter((tuple(path),a,b) for path,value,a,b in r['fields'])
                    actual=Counter((s.source_segments,s.start_byte,s.end_byte) for s in f.event.value_spans)
                    self.assertEqual(expected,actual)

    def test_many_waf_headers_preserve_array_occurrences(self):
        item=waf(0)
        item['httpRequest']['headers']=[{'name':'X-Repeated','value':f'value-{i}'} for i in range(200)]
        record=json_record(item,2);batch=parse_security_batch(record['raw'])
        self.assertEqual(item,batch.frames[0].event.vendor_fields)
        self.assertEqual(len(record['fields']),len(batch.frames[0].event.value_spans))
        self.assertEqual('SOURCE_PARSED',batch.frames[0].event.status)


if __name__=='__main__':unittest.main()
