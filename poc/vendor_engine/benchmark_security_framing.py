"""Self-authored AWS-WAF/IPS-shaped framing differential, not vendor accuracy.

Independent source construction records field identity, type, value and UTF-8
span BEFORE the parser runs. Baseline is explicit physical-line splitting plus
committed source parser, not a claim about the complete product's ingestion UI.
Only aggregate results and hashes are published; no external source IO.
"""
from __future__ import annotations
from pathlib import Path
from collections import Counter
import hashlib
import json
import os
import subprocess
import sys
from tempfile import TemporaryDirectory

HERE=Path(__file__).resolve().parent
REPO=HERE.parent.parent
BASELINE='c2f464444a7aa899bd8b251507234720e4cbdde2'
MODULES=('engine.py','source_parse.py','structured_source.py','residual_kv.py','source_kv.py','java_source.py','security_source.py')


def waf(seed):
    return {
        'timestamp':1791921600000+seed,'formatVersion':1,'webaclId':'synthetic-webacl',
        'terminatingRuleId':'synthetic-rule','terminatingRuleType':'REGULAR','action':'BLOCK',
        'terminatingRuleMatchDetails':[{'conditionType':'SQL_INJECTION','location':'BODY',
                                      'matchedData':['synthetic-token','literal } ] { \\"']}],
        'ruleGroupList':[{'ruleGroupId':'synthetic-group','terminatingRule':None,
                          'nonTerminatingMatchingRules':[{'ruleId':'test-count','action':'COUNT',
                                                          'ruleMatchDetails':[]}],
                          'excludedRules':[]}],
        'rateBasedRuleList':[],'labels':[{'name':'synthetic:label'}],
        'httpRequest':{'clientIp':'192.0.2.10','country':'ZZ',
                       'headers':[{'name':'Host','value':'example.test'},
                                  {'name':'X-Sample','value':f'Zoë {seed} 😀'},
                                  {'name':'X-Sample','value':'second occurrence'}],
                       'uri':'/api?literal={x:[y]}','args':'a=1&b=2','httpVersion':'HTTP/2.0',
                       'httpMethod':'POST','requestId':f'synthetic-request-{seed}'},
        'oversizeFields':['REQUEST_BODY'],'responseCodeSent':403,
        'vendor.extension':{'flag':False,'value':0},'vendor':{'extension':{'flag':True}},
    }


def ips(seed):
    return {
        'timestamp':'2026-10-14T10:11:12.123456+0000','event_type':'alert',
        'flow_id':9007199254740993+seed,'src_ip':'192.0.2.20','src_port':42000+seed,
        'dest_ip':'198.51.100.30','dest_port':443,'proto':'TCP',
        'alert':{'action':'blocked','signature_id':900000+seed,'rev':1,
                 'signature':'Synthetic IPS structural test','category':'Test category',
                 'severity':2,'metadata':{'tag':['first','second'],'empty':[]}},
        'http':{'hostname':'example.test','url':'/path?x={a:[b]}',
                'http_user_agent':'self-authored \\ client "quoted"','status':403},
        'tls':{'version':'TLS 1.3','sni':'example.test','fingerprints':{'sha256':'0'*64}},
        'fileinfo':{'filename':f'sample-{seed}.bin','size':1024,'stored':False},
        'empty_object':{},'null_value':None,
    }


def json_record(value,indent=None):
    raw='';fields=[]
    def emit(text):
        nonlocal raw
        raw+=text
    def encode(node,path=(),depth=0):
        if isinstance(node,(dict,list)):
            obj=isinstance(node,dict);pairs=list(node.items()) if obj else list(enumerate(node))
            emit('{' if obj else '[')
            for index,(key,item) in enumerate(pairs):
                if index:emit(',')
                if indent is not None:emit('\n'+' '*(indent*(depth+1)))
                if obj:emit(json.dumps(key,ensure_ascii=False)+(':' if indent is None else ': '))
                encode(item,path+(key,),depth+1)
            if pairs and indent is not None:emit('\n'+' '*(indent*depth))
            emit('}' if obj else ']')
        else:
            start=len(raw.encode('utf8'));emit(json.dumps(node,ensure_ascii=False,allow_nan=False))
            identity=path if isinstance(value,dict) else ('$array',)+path
            fields.append([list(identity),node,start,len(raw.encode('utf8'))])
    encode(value)
    return {'raw':raw,'tree':value if isinstance(value,dict) else {'$array':value},'fields':fields}


def cee_record(record):
    offset=6
    return {'raw':'@cee: '+record['raw'],'tree':record['tree'],
            'fields':[[path,value,a+offset,b+offset] for path,value,a,b in record['fields']]}


def syslog_record(record):
    parts=[('pri','134','<','>'),('version','1','',' '),
           ('timestamp','2026-10-14T10:11:12Z','',' '),('hostname','sensor','',' '),
           ('appname','ips','',' '),('procid','4','',' '),('msgid','alert','',' '),
           ('structured_data_raw','-','',' ')]
    raw='';fields=[];header={}
    for key,value,before,after in parts:
        raw+=before;start=len(raw.encode());raw+=value
        fields.append([['syslog',key],value,start,len(raw.encode())]);raw+=after;header[key]=value
    header['structured_data']={};offset=len(raw.encode())
    fields.extend([[['body']+path,value,a+offset,b+offset] for path,value,a,b in record['fields']])
    return {'raw':raw+record['raw'],'tree':{'syslog':header,'body':record['tree']},'fields':fields}


def flat_record(kind,seed):
    raw='';fields=[];tree={}
    def cell(path,value,lexical=None):
        nonlocal raw
        start=len(raw.encode());raw+=value if lexical is None else lexical
        fields.append([path,value,start,len(raw.encode())]);node=tree
        for key in path[:-1]:node=node.setdefault(key,{})
        node[path[-1]]=value
    if kind=='kv':
        raw='<'
        cell(['syslog','pri'],'189');raw+='>'
        for key,value in [('type','utm'),('subtype','ips'),('action','dropped'),('srcip','192.0.2.40'),('sessionid',str(seed))]:
            if not raw.endswith('>'):raw+=' '
            raw+=key+'=';cell(['body',key],value)
    else:
        cef=kind=='cef';raw='CEF:' if cef else 'LEEF:'
        names=['version','vendor','product','device_version','signature_id','name','severity'] if cef else ['version','vendor','product','product_version','event_id','delimiter']
        vals=['0','Example','IPS','1','100','Synthetic alert','7'] if cef else ['2.0','Example','IPS','1','100','0x09']
        section='cef_header' if cef else 'leef_header'
        for key,value in zip(names,vals):cell([section,key],value);raw+='|'
        section='cef_extension' if cef else 'leef_extension'
        for idx,(key,value) in enumerate([('src','192.0.2.40'),('act','blocked'),('request','/path?a=1,b=2'),('cn1',str(seed))]):
            if idx:raw+=' ' if cef else '\t'
            raw+=key+'=';cell([section,key],value)
    return {'raw':raw,'tree':tree,'fields':fields}


def streams():
    rows=[]
    for seed in range(12):
        cases=[
            ('waf_multiline',[json_record(waf(seed),2),json_record(waf(seed+100),4)],'\n',''),
            ('ips_multiline',[json_record(ips(seed),2),json_record(ips(seed+100),4)],'\n',''),
            ('security_ndjson',[json_record(waf(seed)),json_record(ips(seed))],'\n',''),
            ('cee_json',[cee_record(json_record(ips(seed),2)),syslog_record(cee_record(json_record(waf(seed),2)))],'\r\n',''),
            ('adjacent_json',[json_record(waf(seed)),json_record(ips(seed))],'',''),
            ('syslog_json',[syslog_record(json_record(ips(seed),2)),syslog_record(json_record(waf(seed),2))],'\r\n',''),
            ('mixed_security',[flat_record('kv',seed),flat_record('cef',seed),flat_record('leef',seed),json_record(waf(seed),2)],'\r\n',''),
            ('bom_crlf',[json_record(waf(seed),2),json_record(ips(seed),2)],'\r\n\r\n','\ufeff \t'),
        ]
        for family,records,separator,prefix in cases:
            raw=prefix;gold=[];events=[]
            for index,record in enumerate(records):
                if index:raw+=separator
                offset=len(raw.encode());raw+=record['raw']
                events.append([offset,len(raw.encode()),record['tree']])
                gold.extend([[path,value,a+offset,b+offset] for path,value,a,b in record['fields']])
            raw+='\r\n'
            rows.append({'family':family,'raw':raw,'gold':gold,'events':events})
    return rows


RUNNER=r'''
from collections import Counter
import json,re,sys
from source_parse import assert_source_accounting
from security_source import parse_security_source as parse_source
mode=sys.argv[1]
if mode=='candidate':from security_framing import parse_security_batch

def key(path,value,a,b):
    # Source scopes, not an adapter-specific presentation wrapper. Header PRI
    # is now explicit oracle data, never silently excluded as an extra field.
    path=(['header']+path[1:] if path[:1]==['syslog'] else
          ['payload']+(path[1:] if path[:1]==['body'] else path))
    return (json.dumps(path,ensure_ascii=True),type(value).__name__,json.dumps(value,ensure_ascii=True,sort_keys=True,allow_nan=False),a,b)
def measure(row):
    raw=row['raw'];frames=[]
    if mode=='candidate':
        batch=parse_security_batch(raw)
        frames=[(f.start_byte,f.end_byte,f.event) for f in batch.frames]
    else:
        for match in re.finditer(r'[^\r\n]+',raw):
            if not match[0].strip():continue
            event=parse_source(match[0]);assert_source_accounting(event)
            frames.append((len(raw[:match.start()].encode()),len(raw[:match.end()].encode()),event))
    actual=Counter()
    for offset,end,event in frames:
        indexes=Counter()
        for span in event.value_spans:
            path=list(span.source_segments) if span.source_segments is not None else span.path.split('.')
            try:
                value=event.vendor_fields
                for part in path:value=value[part]
                if span.source_segments is None and isinstance(value,list):
                    k=tuple(path);value=value[indexes[k]];indexes[k]+=1
            except (KeyError,IndexError,TypeError):value='UNRESOLVED_SOURCE_IDENTITY'
            actual[key(path,value,offset+span.start_byte,offset+span.end_byte)]+=1
    expected=Counter(key(*cell) for cell in row['gold'])
    expected_frames=Counter((a,b) for a,b,tree in row['events'])
    actual_frames=Counter((a,b) for a,b,event in frames)
    frame_map={(a,b):event for a,b,event in frames}
    exact_trees=sum((a,b) in frame_map and frame_map[a,b].vendor_fields==tree for a,b,tree in row['events'])
    return Counter(streams=1,expected_records=len(row['events']),observed_records=len(frames),gold_fields=sum(expected.values()),
                   TP=sum((actual&expected).values()),FP=sum((actual-expected).values()),FN=sum((expected-actual).values()),
                   exact_record_boundaries=sum((actual_frames&expected_frames).values()),
                   false_record_boundaries=sum((actual_frames-expected_frames).values()),
                   missing_record_boundaries=sum((expected_frames-actual_frames).values()),
                   exact_record_trees=exact_trees,
                   source_parsed_records=sum(e.status=='SOURCE_PARSED' for a,b,e in frames))
def metric(c):
    tp,fp,fn=(c[k] for k in ('TP','FP','FN'))
    return {**dict(c),'precision':round(tp/(tp+fp),6) if tp+fp else None,
            'recall':round(tp/(tp+fn),6) if tp+fn else None,
            'f1':round(2*tp/(2*tp+fp+fn),6) if 2*tp+fp+fn else None}
total=Counter();families={}
for row in json.load(sys.stdin):
    counts=measure(row);total.update(counts);families.setdefault(row['family'],Counter()).update(counts)
json.dump({'total':metric(total),'families':{k:metric(v) for k,v in families.items()}},sys.stdout)
'''


def run(directory,rows,mode):
    result=subprocess.run([sys.executable,'-c',RUNNER,mode],cwd=directory,
                          env={**os.environ,'PYTHONPATH':str(directory)},
                          input=json.dumps(rows,ensure_ascii=True),text=True,
                          capture_output=True,check=True,timeout=45)
    return json.loads(result.stdout)


def evaluate():
    rows=streams()
    with TemporaryDirectory(prefix='security-baseline-') as tmp:
        directory=Path(tmp)
        for name in MODULES:
            blob=subprocess.check_output(['git','show',f'{BASELINE}:poc/vendor_engine/{name}'],cwd=REPO,timeout=10)
            (directory/name).write_bytes(blob)
        baseline=run(directory,rows,'baseline')
    candidate=run(HERE,rows,'candidate')
    return {
        'contract':'parser-studio.poc.security-source-framing-benchmark.v2',
        'evidence_class':'SELF_AUTHORED_SECURITY_SHAPES_NOT_UPSTREAM_OR_PRODUCT_ACCURACY',
        'baseline_definition':'physical-line splitting plus committed parse_security_source; not a full product ingestion benchmark',
        'baseline_revision':BASELINE,'candidate_definition':'lossless structural framing with current source decoder; source header/payload scopes canonicalized',
        'measurement':'original source identity + exact type/value + absolute UTF-8 span; all record boundaries and trees',
        'all_streams':len(rows),'all_original_records':sum(len(r['events']) for r in rows),
        'unmasked_original_records':sum(len(r['events']) for r in rows),'masked_records':0,
        'unassessed_synthetic_records':0,'excluded_records':0,
        'external_upstream_scored_records':0,
        'corpus_sha256':hashlib.sha256(json.dumps(rows,ensure_ascii=True,sort_keys=True).encode()).hexdigest(),
        'candidate_code_sha256':{name:hashlib.sha256((HERE/name).read_bytes()).hexdigest() for name in MODULES+('security_framing.py',)},
        'baseline':baseline,'candidate':candidate,
        'dictionary_attempted':False,'native_verified':False,'masking_optimization':False,
        'limitations':['Fixtures are intentionally self-authored AWS-WAF/IPS-shaped structural cases, not production/vendor captures.',
                       'The improvement is event framing, not a newly improved semantic or field-decoding model.',
                       'This self-authored structural corpus is separate from independently scored commercial/upstream source evidence.',
                       'Ambiguous incomplete suffixes remain raw-only. Native/Ruby/CONF/DP and product integration are separate gates.'],
    }


if __name__=='__main__':
    report=evaluate()
    (HERE/'security-framing-current-summary.json').write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print('SECURITY_STREAMS',report['all_streams'],'ORIGINAL_RECORDS',report['all_original_records'])
    print('PHYSICAL_LINE_BASELINE',report['baseline']['total'])
    print('STRUCTURAL_FRAMING',report['candidate']['total'])
