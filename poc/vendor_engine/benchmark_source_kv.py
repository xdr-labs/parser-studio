"""Deliberately unmasked KV regression; not a new-vendor accuracy claim.

Source fields and spans are assembled before parsing. Baseline and candidate
execute independently on identical inputs. Only aggregate results are exported.
"""
from __future__ import annotations
import hashlib,json,subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
from benchmark_unmasked_boundaries import run_parser

HERE=Path(__file__).resolve().parent
REPO=HERE.parent.parent
BASELINE='acc3a903e19597af44635b243fa4be3b4949e35f'
MODULES=('engine.py','source_parse.py','structured_source.py','residual_kv.py','java_source.py')

class Builder:
    def __init__(self,family:str,leading:str=''):
        self.family=family;self.raw=leading;self.fields={};self.spans=[]
    def value(self,key:str,value:str,quote:str=''):
        if self.spans:self.raw+=' '
        self.raw+=key+'='+quote
        a=len(self.raw.encode('utf8'))
        if quote:
            visible=value.replace('\\','\\\\').replace(quote,'\\'+quote)
        else:visible=value.replace(' ','\\ ')
        self.raw+=visible
        self.spans.append([key,a,len(self.raw.encode('utf8'))])
        self.raw+=quote
        if key in self.fields:
            old=self.fields[key]
            if isinstance(old,list):old.append(value)
            else:self.fields[key]=[old,value]
        else:self.fields[key]=value
        return self
    def record(self,tail:str=''):
        return {'family':self.family,'raw':self.raw+tail,'fields':self.fields,'spans':self.spans}


def records()->list[dict]:
    rows=[]
    for i in range(16):
        user=f'analyst{i}';group=f'group{i}';note=f"O'Brien Ž{i}"
        rows.append(Builder('repeated_keys').value('user',user).value('group',group)
                    .value('group',group).value('action','allow').record())
        rows.append(Builder('single_quoted_values').value('name',f'Zoë analyst{i}',"'")
                    .value('note',note,"'").value('action','allow').record())
        rows.append(Builder('quoted_empty_occurrences').value('empty','',"'")
                    .value('empty','','"').value('user',user).record())
        rows.append(Builder('underscore_native_key').value('_vendor',f'vendor{i}')
                    .value('user',user).value('action','allow').record())
        rows.append(Builder('leading_whitespace',' \t ').value('user',user)
                    .value('action','allow').record(' \t'))
        rows.append(Builder('escaped_bare_space').value('message',f'visible value {i}')
                    .value('user',user).record())
        rows.append(Builder('malformed_tail_preservation').value('user',user)
                    .value('action','allow').record(' message="unclosed fake=x nested=y'))
        rows.append(Builder('ordinary_control').value('user',user).value('count',str(i))
                    .value('action','allow').record())
    return rows


def evaluate()->dict:
    rows=records()
    with TemporaryDirectory(prefix='parser-source-kv-baseline-') as directory:
        root=Path(directory)
        for name in MODULES:
            blob=subprocess.run(['git','show',f'{BASELINE}:poc/vendor_engine/{name}'],
                cwd=REPO,check=True,capture_output=True,timeout=10).stdout
            (root/name).write_bytes(blob)
        before=run_parser(root,rows)
    after=run_parser(HERE,rows)
    return {
        'contract':'parser-studio.poc.source-kv-occurrence-regression-v0.1',
        'evidence_class':'SYNTHETIC_UNMASKED_REGRESSION_NOT_NEW_VENDOR_VALIDATION',
        'all_events':len(rows),'unmasked_events':len(rows),'masked_events':0,
        'unassessed_events':0,'excluded_events':0,
        'expected_source_field_occurrences':sum(len(r['spans']) for r in rows),
        'baseline_revision':BASELINE,'baseline':before,'candidate':after,
        'source_corpus_sha256':hashlib.sha256(json.dumps(rows,sort_keys=True,ensure_ascii=True).encode()).hexdigest(),
        'candidate_module_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in (*MODULES,'source_kv.py')},
        'measurement':'Occurrence-aware native field path + exact byte span; decoded field tree equality checked separately',
        'training_performed':False,'dictionary_attempted':False,'masking_optimized':False,
        'native_verified':False,'target_verified':False,
        'limitations':['Purpose-built bug regression, not unseen-vendor accuracy.','Malformed tails stay raw; they are not counted as parsed fields.','Duplicate keys retain ordered arrays without semantic normalization.'],
    }

if __name__=='__main__':
    report=evaluate()
    (HERE/'source-kv-regression-summary.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('UNMASKED_KV_CORPUS',report['all_events'],'events',report['expected_source_field_occurrences'],'fields')
    print('BASELINE',report['baseline']['total']);print('CANDIDATE',report['candidate']['total'])
