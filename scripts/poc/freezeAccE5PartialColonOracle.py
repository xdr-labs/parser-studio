#!/usr/bin/env python3
"""Freeze independent source-only byte claims for colon-labelled comma fields.

Authored without importing any Parser Studio parser; never a device-wire oracle.
"""
import hashlib
import json
import re
from pathlib import Path

TARGET=Path(__file__).with_name('accE5PartialColonOracle.pinned.json')
LABEL=re.compile(r'^[A-Za-z][A-Za-z0-9_ ./()#-]{0,127}$')
samples=[
 ('prefix_and_broken_remainder','2026-10-18T19:00:00Z host : ',
  'EventPriority: Low, ConnectionID: 1234, SrcIP: 192.0.2.2',
  ', ResponderB<166>2026-10-18T19:01:00Z another event'),
 ('complete_reporter_text','source=manually_marked | ',
  'Provider: XYZ, Action: allow, Count: 3',''),
 ('ordered_duplicate_labels','collector: ',
  'User: A, User: B, Outcome: allowed',', unfinished'),
 ('colon_inside_values','device-label: ',
  'Endpoint Profile: Workstation:Vendor:OS, Access Rule: Some Rule, Bytes: 0',''),
 ('unicode_in_value','2026-10-18T19:00:00Z unicodehost: ',
  'Message: Unicode☃😀, Name: alpha, Status: ok',', downstream=unsafe'),
 ('ipv6_like_value','device info: ',
  'SrcIP: 2001:db8::1, DstIP: 198.51.100.42, Decision: allow',''),
 ('zero_and_literals','tag: ',
  'Connections: 0, Response: false, Optional: null',''),
 ('value_equals_sign','2026-10-18 source: ',
  'Subject: x=y, Destination: IPv6::1, Log: disabled',', AnotherEvent'),
 ('nested_delimited_text','node: ',
  'Scope: user:domain, Type: A:B:C, Flag: enabled',''),
 ('tiny_ascii_values','label: ',
  'X: 1, Y: 2, Z: 3','')
]
def sha(b):return hashlib.sha256(b).hexdigest()
def at(s,i):return len(s[:i].encode('utf8'))
def expectations(head,body):
  alltext=head+body
  parts=body.split(', ')
  cursor=len(head)
  rows=[]
  seen={}
  for i,part in enumerate(parts):
    assert ':' in part
    idx=part.index(': ')
    key=part[:idx];value=part[idx+2:]
    assert LABEL.fullmatch(key) and key.strip()==key and value and ',' not in value,(key,value)
    if i:cursor+=2
    start=cursor
    assert alltext[start:start+len(part)]==part
    n=seen.get(key,0);seen[key]=n+1
    rows.append({'name':key,'occurrence':n,'rawLexeme':value,'sourceValue':value,
      'nameStartByte':at(alltext,start),'nameEndByte':at(alltext,start+idx),
      'valueStartByte':at(alltext,start+idx+2),'valueEndByte':at(alltext,start+len(part))})
    cursor+=len(part)
  assert cursor==len(alltext)
  return rows
items=[]
for name,head,body,tail in samples:
  source=head+body+tail
  sb=source.encode('utf8')
  region=body.encode('utf8')
  items.append({'id':name,'kind':'valid',
    'fullSourceHex':sb.hex(),'sourceSha256':sha(sb),
    'scope':'EXPLICIT_SUBRECORD_SOURCE_SLICE',
    'declaredStartByte':len(head.encode('utf8')),
    'declaredEndByte':len((head+body).encode('utf8')),
    'sliceSha256':sha(region),
    'expectedDisposition':'REVIEW_ONLY_PARTIAL_LABELS',
    'expectedFields':expectations(head,body),
    'expectedResidualSuffixBytes':len(tail.encode('utf8'))})
anchor=items[0]
def invalid(id,update=None,src=None,disposition='ABSTAIN_UNSAFE'):
  row=dict(anchor)
  row.update({'id':id,'kind':'invalid','expectedDisposition':disposition,
   'expectedFields':[]})
  if src is not None:
    b=src.encode('utf8') if isinstance(src,str) else src
    sep=b.find(b': ')
    assert sep>0,(id,src)
    start=sep+2
    row['fullSourceHex']=b.hex()
    row['sourceSha256']=sha(b)
    row['declaredStartByte']=start
    row['declaredEndByte']=len(b)
    row['sliceSha256']=sha(b[start:])
  if update: row.update(update)
  items.append(row)
invalid('source_missing',update={'fullSourceHex':'','sourceSha256':sha(b'')})
invalid('wrong_source_hash',update={'sourceSha256':'0'*64})
invalid('wrong_slice_hash',update={'sliceSha256':'0'*64})
invalid('unqualified_scope',update={'scope':'UNVERIFIED_RECORD'},disposition='RAW_ONLY')
invalid('negative_start',update={'declaredStartByte':-1})
invalid('start_beyond_end',update={'declaredStartByte':1000})
invalid('end_beyond_total',update={'declaredEndByte':60000})
invalid('empty_region',update={'declaredEndByte':anchor['declaredStartByte']})
invalid('start_in_key',update={'declaredStartByte':anchor['declaredStartByte']+3})
invalid('end_in_value',update={'declaredEndByte':anchor['declaredEndByte']-2})
invalid('unpaired_surrogate_proxy',src=b'prefix: A: 1, B: \xf0\x9f, C: 3')
invalid('binary_source',src=b'prefix: A: 1, B: \x00, C: 3')
invalid('unknown_embedded_comma',src='node: A: alpha,bravo, B: x, C: z')
invalid('ambiguous_quoted_comma',src='node: A: "alpha, bravo", B: x, C: z')
invalid('truncated_colon_key',src='node: A: alpha, B, C: z')
invalid('zero_length_value',src='node: A: alpha, B: , C: z')
invalid('illegal_control_newline',src='node: A: alpha, B: ok\n, C: z')
invalid('canonical_key_hidden_prefix',
        src='node: A: 1, B: 2, C: 3',
        update={'declaredStartByte':len(b'node: A: 1, '),
                'sliceSha256':sha(b'B: 2, C: 3')})
invalid('duplicate_case_shaped',src='node: A: alpha, a: beta, C: z') # independent grammar is case sensitive, but wrong pinned region
invalid('missing_space_after_comma',src='node: A: alpha,B: x,C: z')
invalid('extra_delimiter_space',src='node: A: alpha,  B: x, C: z')
invalid('huge_source',src=b'prefix: '+b'A: x'*10000)
invalid('fused_syslog_literal',src='node: A: first<166>event, B: x, C: y')
invalid('new_label_outside_region',update={'declaredEndByte':anchor['declaredEndByte']-4})
record={'type':'INDEPENDENT_SYNTHETIC_SOURCE_ONLY_NOT_DEVICE',
 'frozenBeforeCandidate':True,
 'positive':len(samples),'negative':len(items)-len(samples),
 'cases':items}
encoded=(json.dumps(record,ensure_ascii=False,indent=2)+'\n').encode()
TARGET.write_bytes(encoded)
print(json.dumps({'filename':TARGET.name,'cases':len(items),'positives':len(samples),'negatives':record['negative'],
 'frozenSourceClaims':sum(len(x['expectedFields']) for x in items),'sha256':sha(encoded)}))
