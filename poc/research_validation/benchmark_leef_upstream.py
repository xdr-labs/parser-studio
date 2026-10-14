"""Fresh upstream LEEF native-token comparison, with explicit invalid inputs.

The source oracle uses Python split and source-length accumulation, not parser
output or vendor normalization. Literal backslash-t stays a native source value;
only an actual declared delimiter separates attributes. No fixture is repaired.
"""
from __future__ import annotations
import hashlib,json,re
from pathlib import Path
from benchmark_security_followon import ROOT,leaf_metrics,parse_security_source,parse_security_leef
from functools import partial


def native_reference(raw:str):
    marker=raw.find('LEEF:')
    if marker<0:raise ValueError('NO_EXPLICIT_LEEF')
    prefix=raw[:marker]
    if prefix and not re.fullmatch(r'<\d{1,3}>1 (?:\S+ ){6}',prefix):
        raise ValueError('UNSUPPORTED_REFERENCE_ENVELOPE')
    body=raw[marker:]
    version=body.split('|',1)[0]
    count=5 if version=='LEEF:1.0' else 6 if version=='LEEF:2.0' else 0
    if not count:raise ValueError('UNSUPPORTED_REFERENCE_VERSION')
    parts=body[5:].split('|',count)
    if len(parts)!=count+1:raise ValueError('MISSING_REQUIRED_HEADER_DELIMITER')
    header=parts[:-1];extension=parts[-1]
    if any('\\' in value for value in header):raise ValueError('UNSUPPORTED_REFERENCE_HEADER_ESCAPE')
    token=header[-1] if count==6 else '\t'
    if count==5:delimiter='\t'
    elif re.fullmatch(r'(?:0x|x)[0-9a-fA-F]{2}',token):delimiter=chr(int(token.split('x',1)[1],16))
    elif len(token)==1:delimiter=token
    else:raise ValueError('UNSUPPORTED_REFERENCE_DELIMITER')
    if delimiter in ('=','\\') or ord(delimiter)<9:raise ValueError('UNSAFE_REFERENCE_DELIMITER')
    names=('version','vendor','product','product_version','event_id','delimiter')[:count]
    refs=[];tree={'leef_header':dict(zip(names,header)),'leef_extension':{}}
    position=len((prefix+'LEEF:').encode())
    for name,value in zip(names,header):
        end=position+len(value.encode());refs.append((('leef_header',name),value,position,end));position=end+1
    for token in extension.split(delimiter):
        if not token:position+=len(delimiter.encode());continue
        key,separator,value=token.partition('=')
        if not separator or not re.fullmatch(r'[A-Za-z_][A-Za-z0-9_.-]{0,127}',key):
            raise ValueError('UNSUPPORTED_REFERENCE_ATTRIBUTE')
        start=position+len((key+'=').encode());end=start+len(value.encode())
        refs.append((('leef_extension',key),value,start,end))
        if key in tree['leef_extension']:
            old=tree['leef_extension'][key]
            tree['leef_extension'][key]=old+[value] if isinstance(old,list) else [old,value]
        else:tree['leef_extension'][key]=value
        position+=len((token+delimiter).encode())
    return {'raw':raw,'refs':refs,'tree':tree,'wrapped':bool(prefix)}


def main():
    manifest=json.loads((ROOT/'leef-upstream-manifest.json').read_text());cache=ROOT/'.cache/leef-upstream'
    for name,digest in manifest['candidate_frozen_sha256'].items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest
    rows=[];invalid=[];groups={}
    for entry in manifest['files']:
        if entry['name']=='LICENSE':continue
        data=(cache/entry['name']).read_bytes();assert hashlib.sha256(data).hexdigest()==entry['sha256']
        group={'input_records':0,'reference_scored_records':0,'invalid_records':0}
        for raw in data.decode().splitlines():
            group['input_records']+=1
            try:ref=native_reference(raw)
            except ValueError as exc:
                invalid.append({'raw':raw,'reason':str(exc)});group['invalid_records']+=1
            else:rows.append(ref);group['reference_scored_records']+=1
        groups[entry['name']]=group
    selected=partial(parse_security_leef,base_parser=parse_security_source)
    invalid_status={}
    for name,parser in (('current_main',parse_security_source),('frozen_candidate',selected)):
        events=[parser(item['raw']) for item in invalid]
        invalid_status[name]={'records':len(events),'raw_preserved':sum(e.raw==r['raw'] for e,r in zip(events,invalid)),
                              'falsely_complete':sum(e.status=='SOURCE_PARSED' for e in events)}
    result={'contract':'parser-studio.fresh-upstream-leef-native-token.v1','upstream_commit':manifest['revision'],
      'main_commit':'c2f464444a7aa899bd8b251507234720e4cbdde2','freeze_verified':True,
      'input_records':len(rows)+len(invalid),'reference_scored_records':len(rows),'invalid_records':len(invalid),
      'current_main':leaf_metrics(rows,parse_security_source),'frozen_candidate':leaf_metrics(rows,selected),
      'invalid_accounting':invalid_status,'groups':groups,'invalid_reasons':dict(__import__('collections').Counter(r['reason'] for r in invalid)),
      'decision':'NO ADDITIONAL GAIN on this new source set; xHH cases are absent. Preserve malformed template negatives.',
      'limitations':['Upstream regression data, not independently verified production logs. Redaction unassessed.',
        'Native scalar token spelling and source byte spans, not Tenzir semantic type coercion or string escape interpretation.',
        'Literal backslash-t does not create additional source fields; actual header separators govern this reference.',
        'Four malformed header/template inputs retained, not counted as correct field extraction.',
        'Syslog envelope fields are outside this native LEEF body oracle.']}
    (ROOT/'leef-upstream-summary.json').write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    print(json.dumps(result,indent=2,sort_keys=True))

if __name__=='__main__':main()
