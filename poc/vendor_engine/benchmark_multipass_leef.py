"""MP-3 LEEF xHH exact-source benchmark, independent from parser decoder."""
from __future__ import annotations
from collections import Counter
import hashlib,json,re
from pathlib import Path
from security_source import parse_security_source
from security_leef import parse_security_leef
from source_parse import assert_source_accounting

HERE=Path(__file__).resolve().parent
CACHE=HERE/'.cache/multipass-leef';MANIFEST=HERE/'multipass-leef-manifest.json'
HEADER=('version','vendor','product','product_version','event_id','delimiter')

def authored():
    rows=[]
    forms=('', '<134>Oct 14 10:00:00 sensor ips: ',
           '<134>1 2026-10-14T10:00:00Z sensor ips 1 THREAT - ',
           'Oct 14 10:00:00 sensor ips: ')
    for n in range(16):
        for token,delimiter in (('x7C','|'),('x09','\t'),('x5e','^')):
            values=[('cat','THREAT'),('src','192.0.2.'+str(n+1)),('dst','198.51.100.2'),
                    ('srcPort',str(10000+n)),('dstPort','443'),('action','deny'),
                    ('usrName','Zoë '+str(n)),('rule.id','000'+str(n)),('empty',''),
                    ('request','/api?a=1&b=2'),('msg','signature "probe"'),('proto','TCP')]
            if n%4==0:values.extend([('tag','network'),('tag','ips')])
            for prefix in forms:
                raw=prefix+'LEEF:';refs=[];tree={'leef_header':{},'leef_extension':{}}
                def append(root,key,value,sep):
                    nonlocal raw
                    if root=='leef_extension':raw+=key+'='
                    a=len(raw.encode());raw+=value;b=len(raw.encode());refs.append(((root,key),value,a,b));raw+=sep
                    target=tree[root]
                    if key in target:
                        old=target[key];target[key]=old+[value] if isinstance(old,list) else [old,value]
                    else:target[key]=value
                for key,value in zip(HEADER,('2.0','PoC Security','IPS','11.1','42',token)):append('leef_header',key,value,'|')
                for i,(key,value) in enumerate(values):append('leef_extension',key,value,delimiter if i<len(values)-1 else '')
                rows.append({'raw':raw,'refs':refs,'tree':tree,'wrapped':bool(prefix)})
    return rows

def reference_leef(raw):
    if not raw.startswith('LEEF:2.0|') or '\x00' in raw or '\r' in raw or '\n' in raw:raise ValueError('LEEF_REFERENCE_INPUT')
    offsets=[0]
    for c in raw:offsets.append(offsets[-1]+len(c.encode()))
    pos=5;parts=[]
    for _ in range(6):
        end=raw.find('|',pos)
        if end<0:raise ValueError('LEEF_REFERENCE_HEADER')
        parts.append((raw[pos:end],pos,end));pos=end+1
    token=parts[-1][0]
    if re.fullmatch(r'x[0-9a-fA-F]{2}',token):delimiter=chr(int(token[1:],16))
    elif re.fullmatch(r'0x[0-9a-fA-F]{2}',token):delimiter=chr(int(token[2:],16))
    elif len(token)==1:delimiter=token
    else:raise ValueError('LEEF_REFERENCE_DELIMITER')
    if ord(delimiter)<9 or delimiter in ('=','\\'):raise ValueError('LEEF_REFERENCE_DELIMITER')
    tree={'leef_header':{},'leef_extension':{}};fields=[]
    for name,(value,a,b) in zip(HEADER,parts):tree['leef_header'][name]=value;fields.append((('leef_header',name),value,offsets[a],offsets[b]))
    i=pos
    while i<=len(raw):
        end=raw.find(delimiter,i)
        if end<0:end=len(raw)
        if end>i:
            cell=raw[i:end];split=cell.find('=')
            if split<1:raise ValueError('LEEF_REFERENCE_EXTENSION')
            key=cell[:split];value=cell[split+1:]
            if not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}',key):raise ValueError('LEEF_REFERENCE_KEY')
            target=tree['leef_extension']
            if key in target:
                old=target[key];target[key]=old+[value] if isinstance(old,list) else [old,value]
            else:target[key]=value
            fields.append((('leef_extension',key),value,offsets[i+split+1],offsets[end]))
        if end==len(raw):break
        i=end+1
    return {'raw':raw,'tree':tree,'refs':fields,'wrapped':False}

def _score(rows,parser):
    total=Counter();states=Counter()
    for row in rows:
        event=parser(row['raw']);assert_source_accounting(event)
        tree=event.vendor_fields.get('body',{}) if row.get('wrapped') else event.vendor_fields
        actual=Counter();occ=Counter()
        for span in event.value_spans:
            path=span.path
            if row.get('wrapped'):
                if not path.startswith('body.'):continue
                path=path[5:]
            root,sep,key=path.partition('.')
            if not sep:continue
            value=tree.get(root,{}).get(key,{'missing':True})
            if isinstance(value,list):idx=occ[(root,key)];occ[(root,key)]+=1;value=value[idx] if idx<len(value) else {'missing':True}
            actual[(root,key,json.dumps(value,ensure_ascii=True,sort_keys=True),span.start_byte,span.end_byte)]+=1
        gold=Counter((p[0],p[1],json.dumps(v,ensure_ascii=True,sort_keys=True),a,b) for p,v,a,b in row['refs'])
        common=gold&actual;exact=actual==gold and tree==row['tree']
        total.update(records=1,reference_fields=len(row['refs']),TP=sum(common.values()),FP=sum((actual-common).values()),FN=sum((gold-common).values()),
                     exact_records=int(exact),raw_preserved=int(event.raw==row['raw']),falsely_complete=int(event.status=='SOURCE_PARSED' and not exact))
        states[event.status]+=1
    tp,fp,fn=total['TP'],total['FP'],total['FN'];total['statuses']=dict(states)
    total['precision']=tp/(tp+fp) if tp+fp else None;total['recall']=tp/(tp+fn) if tp+fn else None;total['f1']=2*tp/(2*tp+fp+fn) if 2*tp+fp+fn else None
    return dict(total)
def evaluate():
    rows=authored();base=parse_security_source;candidate=lambda raw:parse_security_leef(raw,base_parser=base)
    manifest=json.loads(MANIFEST.read_text());item=manifest['files'][0];blob=(CACHE/item['name']).read_bytes()
    if hashlib.sha256(blob).hexdigest()!=item['sha256']:raise ValueError('LEEF_EXTERNAL_PIN')
    external=[reference_leef(blob.decode('utf8','strict').strip('\r\n'))]
    return {'contract':'parser-studio.poc.multipass-leef.v1','authored':{'baseline':_score(rows,base),'candidate':_score(rows,candidate)},
            'external_xa6':{'baseline':_score(external,base),'candidate':_score(external,candidate)},
            'dictionary_attempted':False,'masking_optimization':False,'native_verified':False}
if __name__=='__main__':
    result=evaluate();(HERE/'multipass-leef-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print('AUTHORED',result['authored']);print('EXTERNAL_XA6',result['external_xa6'])
