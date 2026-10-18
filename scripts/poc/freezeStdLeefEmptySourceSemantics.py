#!/usr/bin/env python3
"""Independent LEEF lexical source claims. Empty values are NOT producer semantics."""
from pathlib import Path
import hashlib,json
sha=lambda b:hashlib.sha256(b).hexdigest()
cases=[]
def add(case_id,version,delimiter,attributes,*,browser_accepted=True,
        source_lexical=True,vendor='ExampleOrg',invalid_suffix='',header_only=False):
    header=('LEEF:'+version+'|'+vendor+'|Sensor|3.2|E42|'+
      ('^|' if version=='2.0' and delimiter=='^' else
       ('x09|' if version=='2.0' and delimiter=='\t' else '')))
    parts=[key+'='+val for key,val in attributes]
    wire=header+delimiter.join(parts)+invalid_suffix
    expected=[]
    if source_lexical:
        offset=len(header.encode('utf8'))
        counts={}
        for key,val in attributes:
            count=counts.get(key,0)
            counts[key]=count+1
            start=offset+len((key+'=').encode('utf8'))
            end=start+len(val.encode('utf8'))
            expected.append(dict(name=key,value=val,occurrence=count,
                startByte=start,endByte=end))
            offset+=len((key+'='+val+delimiter).encode('utf8'))
    cases.append(dict(id=case_id,wire=wire,sha256=sha(wire.encode('utf8')),
       browserAccepted=browser_accepted,sourceLexical=source_lexical,
       expectedExtensionClaims=expected,headerOnly=header_only))
add('LEEF1_EMPTY_LAST','1.0','\t',[('src','192.0.2.1'),('msg','')])
add('LEEF1_EMPTY_FIRST','1.0','\t',[('msg',''),('src','192.0.2.1')])
add('LEEF1_EMPTY_MIDDLE','1.0','\t',[('src','192.0.2.1'),('note',''),('dst','198.51.100.2')])
add('LEEF2_CARET_EMPTY_LAST','2.0','^',[('src','192.0.2.1'),('note','')])
add('LEEF2_CARET_EMPTY_MIDDLE','2.0','^',[('note',''),('src','192.0.2.1'),('other','')])
add('LEEF2_HEX_TAB_EMPTY','2.0','\t',[('src','192.0.2.1'),('note','')])
add('LEEF2_CARET_UTF8','2.0','^',[('event','€😀'),('msg','')])
add('LEEF1_DUPLICATE_KEY_EMPTY','1.0','\t',[('src','192.0.2.1'),('src','')],
    browser_accepted=False)
add('LEEF2_DUPLICATE_IDENTICAL','2.0','^',[('src','192.0.2.1'),('src','192.0.2.1')],
    browser_accepted=False)
add('LEEF1_EMPTY_HEADER_VENDOR','1.0','\t',[('src','192.0.2.1')],
    vendor='',browser_accepted=False,source_lexical=False)
add('LEEF1_UNQUALIFIED_QUOTED','1.0','\t',[('msg','"ambiguous"')],
    source_lexical=False)
add('LEEF2_TRAILING_DELIMITER','2.0','^',[('src','192.0.2.1')],
    invalid_suffix='^',source_lexical=False,browser_accepted=False)
add('LEEF1_MISSING_EQUALS','1.0','\t',[('src','192.0.2.1')],
    invalid_suffix='\tmalformed',source_lexical=False,browser_accepted=False)
add('LEEF2_RESERVED_KEY','2.0','^',[('__proto__','evil')],
    source_lexical=False,browser_accepted=False)
add('LEEF2_MISSING_VALUE_KEY','2.0','^',[('src','192.0.2.1')],
    invalid_suffix='^=bad',source_lexical=False,browser_accepted=False)
data={
 'authority':'IBM LEEF event components and custom key guide: repeated attributes may be ignored by QRadar. Empty lexical value alone has no publisher/null semantics.',
 'evidenceScope':'INDEPENDENTLY_AUTHORED_SYNTHETIC_SOURCE_ONLY_NO_NATIVE',
 'cases':cases,
}
p=Path('scripts/poc/standardLeefEmptySourceSemantics.pinned.json')
b=(json.dumps(data,ensure_ascii=True,indent=2)+'\n').encode('utf8')
p.write_bytes(b)
print('PINNED',len(cases),'sourceLexical',sum(x['sourceLexical'] for x in cases),
  'emptyFields',sum(not f['value'] for x in cases for f in x['expectedExtensionClaims']),
  'SHA256',sha(b))
