"""MP-2 exact CEF source benchmark with independent lexical oracle."""
from __future__ import annotations
from collections import Counter
import hashlib,json,re
from pathlib import Path
from security_source import parse_security_source
from security_cef import parse_security_cef
from source_parse import SourceEvent,assert_source_accounting

HERE=Path(__file__).resolve().parent
CACHE=HERE/'.cache/multipass-cef'
MANIFEST=HERE/'multipass-cef-manifest.json'
HEADER=('version','vendor','product','device_version','signature_id','name','severity')
HEADER_CELL=re.compile(r'(?:\\[\s\S]|[^\\|])*\|')
LEXEME=re.compile(r'\\[\s\S]|[ \t]+|[^\\ \t]+')
KEY=re.compile(r'([A-Za-z_][A-Za-z0-9_.-]{0,127})=')
ESC=re.compile(r'\\([\s\S])')
MAX_BYTES=131072;MAX_FIELDS=1024

def _decode(token,header):
    mapping={'\\':'\\','|':'|'} if header else {'\\':'\\','=':'=','n':'\n','r':'\r'}
    return ESC.sub(lambda m:mapping.get(m[1],m[0]),token)

def reference_cef(raw:str):
    if not raw.startswith('CEF:') or len(raw.encode())>MAX_BYTES or any(c in raw for c in '\x00\r\n'):
        raise ValueError('CEF_REFERENCE_INPUT_UNSUPPORTED')
    offsets=[0]
    for c in raw:offsets.append(offsets[-1]+len(c.encode()))
    tree={'cef_header':{},'cef_extension':{}};fields=[];pos=4
    for name in HEADER:
        m=HEADER_CELL.match(raw,pos)
        if m is None:raise ValueError('CEF_REFERENCE_HEADER_INCOMPLETE')
        end=m.end()-1;value=_decode(raw[pos:end],True)
        tree['cef_header'][name]=value;fields.append((('cef_header',name),value,offsets[pos],offsets[end]));pos=m.end()
    if tree['cef_header']['version'] not in ('0','1'):raise ValueError('CEF_REFERENCE_VERSION')
    begin=pos
    while begin<len(raw) and raw[begin] in ' \t':begin+=1
    if begin==len(raw):return {'raw':raw,'tree':tree,'fields':fields}
    first=KEY.match(raw,begin)
    if first is None:raise ValueError('CEF_REFERENCE_EXTENSION_KEY')
    keys=[first];end=begin
    for token in LEXEME.finditer(raw,begin):
        if token.start()!=end:raise ValueError('CEF_REFERENCE_LEXICAL_GAP')
        end=token.end()
        if token.group()[0] in ' \t':
            nxt=KEY.match(raw,token.end())
            if nxt is not None:keys.append(nxt)
    if end!=len(raw):raise ValueError('CEF_REFERENCE_TRUNCATED_ESCAPE')
    if len(keys)>MAX_FIELDS:raise ValueError('CEF_REFERENCE_FIELD_LIMIT')
    for i,m in enumerate(keys):
        a=m.end();b=keys[i+1].start()-1 if i+1<len(keys) else len(raw.rstrip(' \t'))
        b=max(a,b);value=_decode(raw[a:b],False);name=m[1]
        target=tree['cef_extension']
        if name in target:
            old=target[name];target[name]=old+[value] if isinstance(old,list) else [old,value]
        else:target[name]=value
        fields.append((('cef_extension',name),value,offsets[a],offsets[b]))
    return {'raw':raw,'tree':tree,'fields':fields}

def _encoded_header(v):return v.replace('\\','\\\\').replace('|','\\|')
def _encoded_ext(v):return v.replace('\\','\\\\').replace('=','\\=').replace('\n','\\n').replace('\r','\\r')
def authored():
    rows=[]
    for i in range(12):
        variants={
          'literal_double_quotes':[('msg',f'"IPS match {i}"'),('act','deny')],
          'literal_single_quotes':[('msg',f"'signature {i}'"),('act','deny')],
          'literal_quote_suffix':[('msg',f'"IPS{i}"suffix'),('act','deny')],
          'trailing_spaces':[('msg',f'IPS {i}   '),('act','deny')],
          'leading_spaces':[('msg',f'  IPS {i}'),('act','deny')],
          'encoded_payload':[('msg',f'Zoë{i}\nrule=value | boundary'),('act','deny')],
          'repeated_empty':[('tag','ips'),('tag',str(i)),('empty',''),('act','deny')],
          'ordinary_control':[('src','192.0.2.'+str(i+1)),('spt',str(1024+i)),('act','deny')],
        }
        for family,values in variants.items():
            raw='CEF:'
            for value in ('0','Example','IPS','1','42','Rule | match','7'):raw+=_encoded_header(value)+'|'
            for n,(key,value) in enumerate(values):
                if n:raw+=' '
                raw+=key+'='+_encoded_ext(value)
            ref=reference_cef(raw);ref['family']=family;rows.append(ref)
    return rows

def commercial():
    manifest=json.loads(MANIFEST.read_text());rows=[];groups={}
    for item in manifest['files']:
        blob=(CACHE/item['name']).read_bytes()
        if hashlib.sha256(blob).hexdigest()!=item['sha256']:raise ValueError('CEF_SOURCE_PIN_MISMATCH')
        originals=[e['event']['original'] for e in json.loads(blob)['events']]
        if len(originals)!=item['records']:raise ValueError('CEF_SOURCE_COUNT_MISMATCH')
        refs=[reference_cef(raw) for raw in originals];groups[item['name']]=refs;rows.extend(refs)
    return rows,groups

def _event_cells(event:SourceEvent):
    counts=Counter();out=[]
    for span in event.value_spans:
        root,sep,key=span.path.partition('.')
        if not sep:continue
        value=event.vendor_fields.get(root,{}).get(key)
        if isinstance(value,list):
            idx=counts[(root,key)];counts[(root,key)]+=1;value=value[idx]
        out.append(((root,key),value,span.start_byte,span.end_byte))
    return out

def score(refs,parser):
    total=Counter();states=Counter()
    for ref in refs:
        event=parser(ref['raw']);assert_source_accounting(event)
        if event.raw!=ref['raw']:raise ValueError('CEF_RAW_CHANGED')
        gold=Counter((p,json.dumps(v,ensure_ascii=True,sort_keys=True),a,b) for p,v,a,b in ref['fields'])
        actual=Counter((p,json.dumps(v,ensure_ascii=True,sort_keys=True),a,b) for p,v,a,b in _event_cells(event))
        common=gold&actual
        total.update(records=1,reference_fields=len(ref['fields']),TP=sum(common.values()),FP=sum((actual-common).values()),FN=sum((gold-common).values()),
                     raw_preserved=1,exact_records=int(actual==gold and event.vendor_fields==ref['tree']),
                     falsely_complete=int(event.status=='SOURCE_PARSED' and not (actual==gold and event.vendor_fields==ref['tree'])))
        states[event.status]+=1
    tp,fp,fn=total['TP'],total['FP'],total['FN'];total['statuses']=dict(states)
    total['precision']=tp/(tp+fp) if tp+fp else None;total['recall']=tp/(tp+fn) if tp+fn else None
    total['f1']=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None
    return dict(total)
def evaluate():
    authored_rows=authored();commercial_rows,groups=commercial()
    base=parse_security_source;candidate=lambda raw:parse_security_cef(raw,base_parser=parse_security_source)
    invalid=[r['raw']+'\\' for r in authored_rows[:12]]+[r['raw']+'\nextra' for r in authored_rows[:12]]
    malformed={}
    for name,parser in [('baseline',base),('candidate',candidate)]:
        events=[parser(x) for x in invalid]
        malformed[name]={'records':len(events),'raw_preserved':sum(e.raw==x for e,x in zip(events,invalid)),
                         'falsely_complete':sum(e.status=='SOURCE_PARSED' for e in events)}
    return {'contract':'parser-studio.poc.multipass-cef.v1','commercial':{'baseline':score(commercial_rows,base),'candidate':score(commercial_rows,candidate)},
            'authored':{'baseline':score(authored_rows,base),'candidate':score(authored_rows,candidate)},
            'commercial_groups':{name:{'baseline':score(refs,base),'candidate':score(refs,candidate)} for name,refs in groups.items()},
            'malformed':malformed,'dictionary_attempted':False,'masking_optimization':False,'native_verified':False}
if __name__=='__main__':
    result=evaluate();(HERE/'multipass-cef-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('COMMERCIAL',result['commercial']);print('AUTHORED',result['authored']);print('MALFORMED',result['malformed'])
