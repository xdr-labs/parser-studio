#!/usr/bin/env python3
"""Freeze independently authored RFC8259 / RFC6901 nested JSON lexical source truth."""
import hashlib,json
from pathlib import Path
sha=lambda raw:hashlib.sha256(raw).hexdigest()

# Author-defined claim: RFC6901 pointer, member name raw source token or None
# for positional array elements, value raw token, occurrence index for
# the author's explicitly repeated member name in different object scopes.
valid=[
 ('JSON-NESTED-FIELDS',
  '{"event":{"actor":"alice","action":"allow"},"score":12}',
  [('/event','"event"','{"actor":"alice","action":"allow"}',0),
   ('/event/actor','"actor"','"alice"',0),
   ('/event/action','"action"','"allow"',0),
   ('/score','"score"','12',0)]),
 ('JSON-NESTED-ARRAY-OBJECTS',
  '{"events":[{"uid":"u1"},{"uid":"u2"}],"active":true}',
  [('/events','"events"','[{"uid":"u1"},{"uid":"u2"}]',0),
   ('/events/0',None,'{"uid":"u1"}',0),
   ('/events/0/uid','"uid"','"u1"',0),
   ('/events/1',None,'{"uid":"u2"}',0),
   ('/events/1/uid','"uid"','"u2"',1),
   ('/active','"active"','true',0)]),
 ('JSON-POINTER-KEY-ESCAPING',
  '{"a/b":{"m~n":3},"":false,"z\\u0065ro":0}',
  [('/a~1b','"a/b"','{"m~n":3}',0),
   ('/a~1b/m~0n','"m~n"','3',0),
   ('/','""','false',0),
   ('/zero','"z\\u0065ro"','0',0)]),
 ('JSON-UNICODE-LEXICAL',
  '{"message":"€😀","accent":"naïve","emoji":"\\uD83D\\uDE00"}',
  [('/message','"message"','"€😀"',0),
   ('/accent','"accent"','"naïve"',0),
   ('/emoji','"emoji"','"\\uD83D\\uDE00"',0)]),
 ('JSON-EMPTY-CONTAINERS-NULL',
  '{"emptyObj":{},"emptyArr":[],"nullVal":null,"neg":-12.5}',
  [('/emptyObj','"emptyObj"','{}',0),
   ('/emptyArr','"emptyArr"','[]',0),
   ('/nullVal','"nullVal"','null',0),
   ('/neg','"neg"','-12.5',0)]),
 ('JSON-ROOT-ARRAY',
  '[{"a":1},{"b":2},3]',
  [('/0',None,'{"a":1}',0),
   ('/0/a','"a"','1',0),
   ('/1',None,'{"b":2}',0),
   ('/1/b','"b"','2',0),
   ('/2',None,'3',0)]),
 ('JSON-ESCAPED-KEY-NAMES',
  '{"\\u0061":1,"a\\/b":"value"}',
  [('/a','"\\u0061"','1',0),
   ('/a~1b','"a\\/b"','"value"',0)]),
 ('JSON-SAFE-NUMBER-BOOLEAN',
  '{"negative":-0.125,"zero":0,"on":true,"off":false}',
  [('/negative','"negative"','-0.125',0),
   ('/zero','"zero"','0',0),
   ('/on','"on"','true',0),
   ('/off','"off"','false',0)]),
 ('JSON-ROOT-STRING','"hello"',[]),
]
issues=[
 ('JSON-SAME-SCOPE-DUPLICATE','{"a":1,"a":2}','REVIEW_ONLY_UNCERTAIN','DUPLICATE_MEMBER_SILENT_OVERWRITE'),
 ('JSON-ESCAPED-ALIAS-DUPLICATE','{"a":1,"\\u0061":2}','REVIEW_ONLY_UNCERTAIN','DUPLICATE_MEMBER_SILENT_OVERWRITE'),
 ('JSON-UNSAFE-INTEGER','{"id":9007199254740993}','REVIEW_ONLY_UNCERTAIN','NONFINITE_NUMBER_OR_LOSS_OF_PRECISION'),
 ('JSON-EXPONENT-OVERFLOW','{"risk":1e999}','REVIEW_ONLY_UNCERTAIN','NONFINITE_NUMBER_OR_LOSS_OF_PRECISION'),
 ('JSON-UNPAIRED-SURROGATE','{"broken":"\\uD800"}','REVIEW_ONLY_UNCERTAIN','UNPAIRED_UNICODE_SURROGATE'),
 ('JSON-INVALID-ESCAPE','{"bad":"\\q"}','ABSTAIN_UNSAFE','INVALID_SOURCE_LEXICAL_GRAMMAR'),
 ('JSON-TRAILING-GARBAGE','{"value":1}junk','ABSTAIN_UNSAFE','INVALID_SOURCE_LEXICAL_GRAMMAR'),
 ('JSON-TRUNCATED-NESTING','{"a":{"b":1}','ABSTAIN_UNSAFE','INVALID_SOURCE_LEXICAL_GRAMMAR'),
 ('JSON-RESOURCE-DEPTH','['*34+'0'+']'*34,'ABSTAIN_UNSAFE','RESOURCE_BOUNDS'),
]
def find_occurrence(raw,lexeme,ordinal):
  cursor=-1
  for _ in range(ordinal+1):
    cursor=raw.find(lexeme,cursor+1)
    if cursor<0:raise RuntimeError(('missing authored lexical marker',lexeme,ordinal))
  return cursor

cases=[]
for case_id,wire,expected in valid:
  # Strict independent built-in Python JSON decoder verifies that authored
  # positive raw source is valid, without calling Parser Studio candidate.
  json.loads(wire)
  claims=[]
  for pointer,namelex,valuelex,nameoccurrence in expected:
    if not pointer.startswith('/'):
      raise RuntimeError('Only non-root JSON Pointer field claims supported')
    if namelex is None:
      valueStart=wire.find(valuelex)
      if valueStart<0:raise RuntimeError((case_id,pointer))
      nameStart=nameEnd=None
    else:
      nameStart=find_occurrence(wire,namelex,nameoccurrence)
      nameEnd=nameStart+len(namelex)
      after=wire[nameEnd:]
      if not after.startswith(':'):
        raise RuntimeError((case_id,'name is not a JSON member'))
      remainder=nameEnd+1
      while remainder<len(wire) and wire[remainder] in ' \t\r\n':
        remainder+=1
      valueStart=remainder
      if wire[valueStart:valueStart+len(valuelex)]!=valuelex:
        raise RuntimeError((case_id,'value did not begin at authored member'))
    valueEnd=valueStart+len(valuelex)
    assert wire[valueStart:valueEnd]==valuelex
    raw=wire.encode('utf8')
    toByte=lambda ch:len(wire[:ch].encode('utf8'))
    s,e=toByte(valueStart),toByte(valueEnd)
    assert raw[s:e]==valuelex.encode('utf8')
    if namelex is not None:
      assert raw[toByte(nameStart):toByte(nameEnd)]==namelex.encode('utf8')
    claims.append({
      'pointer':pointer,
      'nameRawLexeme':namelex,
      'nameStartByte':None if nameStart is None else toByte(nameStart),
      'nameEndByte':None if nameEnd is None else toByte(nameEnd),
      'valueRawLexeme':valuelex,
      'valueStartByte':s,'valueEndByte':e,
    })
  cases.append({'id':case_id,'wire':wire,'expectedDisposition':'REVIEW_ONLY_LEXICAL',
    'expectedIssues':[],'claims':claims,'sourceBytes':len(wire.encode('utf8')),
    'sourceSha256':sha(wire.encode('utf8'))})
for case_id,wire,disposition,issue in issues:
  cases.append({'id':case_id,'wire':wire,'expectedDisposition':disposition,
    'expectedIssues':[issue],'claims':[],'sourceBytes':len(wire.encode('utf8')),
    'sourceSha256':sha(wire.encode('utf8'))})
obj={
 'authority':['RFC8259 source JSON grammar','RFC6901 JSON Pointer name/array reference tokens'],
 'evidence':'Independently authored synthetics with original lexical source claims, not native publisher goldens',
 'cases':cases,
}
blob=(json.dumps(obj,indent=2,ensure_ascii=False)+'\n').encode('utf8')
path=Path('scripts/poc/standardJsonNestedOriginalSpans.pinned.json')
path.write_bytes(blob)
print('JSON_NESTED_ORACLE_FROZEN',len(cases),'cases',len(valid),'valid',
      len(issues),'negative','claims',sum(len(x['claims']) for x in cases),
      'SHA256',sha(blob))
