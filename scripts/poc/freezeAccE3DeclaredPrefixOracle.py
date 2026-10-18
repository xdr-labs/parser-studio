#!/usr/bin/env python3
"""Freeze independently authored generic prefix/body lexeme and byte expectations.

This script never imports or executes Parser Studio source parsers.
Documentary manufacturer examples are separately preserved, not committed.
"""
import hashlib
import json
import re
from pathlib import Path

OUTPUT=Path(__file__).with_name('accE3DeclaredPrefixOracle.pinned.json')
SOURCE_CASES=[
 ('bsd_name_and_clock','Apr 18 01:12:33 host.example ','device=sf user="maria" count=5'),
 ('bsd_ip_origin','Apr 18 01:12:33 192.0.2.13 ','src_ip=192.0.2.3 dst_ip=198.51.100.2 proto=tcp'),
 ('utf8_source_value','Oct 18 20:40:02 origin ','dst="naïve😀" action=allow serial=7'),
 ('short_documentary_prefix','2: ','date=2026-10-18 time=21:00:00 kind=traffic id=1'),
 ('declared_arbitrary_context','relay: zone1 ','source=alpha empty="" dest=beta'),
 ('repeated_literal_source_key','Oct 18 20:40:02 device42 ','app=ssh app=telnet result=deny'),
 ('single_quote_lexical','2026-10-18 upstream ',"quoted='value' eq=\"a=b\" note=done"),
 ('bounded_punctuation_prefix','meta! custom | ','x=1 y=2 comment="origin field"'),
 ('source_equal_sign_in_value','prefix: ','flag=0 message="x=y" final=1'),
 ('unicode_unquoted_value','Dec 08 10:13:42 relay-gw ','foo=bar key=Unicode☃ status=ok')
]
TOKEN=re.compile(r'([A-Za-z_][A-Za-z0-9_.-]*)=("(?:[^"\\]|\\.)*"|\'(?:[^\'\\]|\\.)*\'|[^\s"\'\\]+)')
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def reference_fields(raw:str,prefix:str):
    pos=len(prefix);out=[];seen={}
    while pos<len(raw):
        m=TOKEN.match(raw,pos)
        assert m and m.start()==pos,(pos,raw[pos:pos+30])
        key,lex=m.group(1,2)
        name_start=pos
        key_end=name_start+len(key)
        value_start=key_end+1
        decoded=lex[1:-1] if lex[0] in ('"',"'") else lex
        n=seen.get(key,0);seen[key]=n+1
        def b(offset):return len(raw[:offset].encode('utf8'))
        out.append({'name':key,'occurrence':n,'sourceValueLexeme':lex,'decodedSourceValue':decoded,
                    'nameStartByte':b(name_start),'nameEndByte':b(key_end),
                    'valueStartByte':b(value_start),'valueEndByte':b(m.end())})
        pos=m.end()
        if pos<len(raw):
            assert raw[pos]==' ',raw[pos:]
            pos+=1
    assert len(out)>=2
    return out
cases=[]
for name,prefix,body in SOURCE_CASES:
    raw=prefix+body
    octets=raw.encode('utf8');pre=prefix.encode('utf8')
    cases.append({'id':name,'category':'positive','recordFraming':'CONFIRMED_SINGLE_SOURCE_RECORD',
        'sourceHex':octets.hex(),'sourceSha256':sha(octets),'declaredBodyFormat':'space_kv',
        'prefixEndByte':len(pre),'prefixSha256':sha(pre),
        'expectedDisposition':'REVIEW_ONLY_DECLARED_PREFIX',
        'expectedFields':reference_fields(raw,prefix)})
anchor=cases[0]
def mutate(name,*,source=None,raw=None,context=None,expected='ABSTAIN_UNSAFE'):
    value={
        'id':name,'category':'negative',
        'recordFraming':anchor['recordFraming'],
        'sourceHex':anchor['sourceHex'],
        'sourceSha256':anchor['sourceSha256'],
        'declaredBodyFormat':'space_kv',
        'prefixEndByte':anchor['prefixEndByte'],
        'prefixSha256':anchor['prefixSha256'],
        'expectedDisposition':expected,
        'expectedFields':[]
    }
    if raw is not None:
        encoded=raw.encode('utf8') if isinstance(raw,str) else raw
        value['sourceHex']=encoded.hex()
        value['sourceSha256']=sha(encoded)
    if context is not None:value.update(context)
    cases.append(value)
mutate('missing_context',context={'recordFraming':'UNVERIFIED'},expected='RAW_ONLY')
mutate('source_hash_mismatch',context={'sourceSha256':'0'*64})
mutate('prefix_hash_mismatch',context={'prefixSha256':'0'*64})
mutate('empty_prefix',context={'prefixEndByte':0})
mutate('prefix_past_record',context={'prefixEndByte':50000})
mutate('middle_of_name',context={'prefixEndByte':anchor['prefixEndByte']+2})
mutate('unsupported_format',context={'declaredBodyFormat':'json'})
mutate('bad_sha_upper',context={'sourceSha256':anchor['sourceSha256'].upper()})
mutate('embedded_newline',raw='Apr 18 01:12:33 host.example device=sf\n user=maria count=5')
mutate('broken_double_quote',raw='Apr 18 01:12:33 host.example device=sf user="maria count=5')
mutate('unkeyed_residual',raw='Apr 18 01:12:33 host.example device=sf unkeyed user=maria count=5')
mutate('missing_separator',raw='Apr 18 01:12:33 host.example device=sf user="maria"count=5')
mutate('canonical_key_collision',raw='Apr 18 01:12:33 host.example device=sf a-b=1 a_b=2')
mutate('truncated_utf8',raw=anchor and bytes.fromhex(anchor['sourceHex'])[:-1]+b'\xff')
mutate('incomplete_alone',raw='Apr 18 01:12:33 host.example user=maria')
mutate('prefix_hides_source_key',raw='device=sf user=maria count=5',
       context={'prefixEndByte':10,'prefixSha256':sha(b'device=sf ')})
mutate('pseudo_syslog_pri',raw='<134>Apr 18 01:12:33 host.example device=sf user=maria count=5',
       context={'prefixEndByte':30,'prefixSha256':sha(b'<134>Apr 18 01:12:33 host.ex')})
mutate('unsafe_utf8_short_prefix',raw=b'\xf0\x9f\x92',context={'prefixEndByte':1,'prefixSha256':sha(b'\xf0')})
mutate('over_budget',raw=b'Apr 18 01:12:33 host.example '+b'a=' + b'x'*20000+b' b=y')
item={'authority':'INDEPENDENT_STANDARDS_AUTHORED_SYNTHETIC_ONLY',
      'frozenBeforeParserImplementation':True,
      'positiveCaseCount':len(SOURCE_CASES),
      'negativeCaseCount':len(cases)-len(SOURCE_CASES),
      'cases':cases}
data=(json.dumps(item,indent=2,ensure_ascii=False)+'\n').encode('utf8')
OUTPUT.write_bytes(data)
print(json.dumps({'file':OUTPUT.name,'cases':len(cases),'positive':item['positiveCaseCount'],
 'negative':item['negativeCaseCount'],
 'claims':sum(len(x['expectedFields']) for x in cases),
 'sha256':sha(data)}))
