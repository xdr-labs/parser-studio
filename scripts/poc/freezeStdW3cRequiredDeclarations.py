#!/usr/bin/env python3
"""Freeze independently authored W3C EFL 1.0 header truth before parser scoring."""
from pathlib import Path
import hashlib
import json

sha=lambda b:hashlib.sha256(b).hexdigest()
names=['time','cs-method','cs-uri']
header='#Fields: '+' '.join(names)
valid=[
 ('W3C-REQUIRED-VERSION-AND-FIELDS',
  ['#Version: 1.0',header],
  [['12:34:56','GET','/login']],
  [['12:34:56','GET','/login']],' ','\n'),
 ('W3C-FIELDS-BEFORE-VERSION-BOTH-PRECEDE-DATA',
  [header,'#Version: 1.0'],
  [['12:34:57','POST','/upload']],
  [['12:34:57','POST','/upload']],' ','\n'),
 ('W3C-EXTRA-WRITER-DIRECTIVES-BEFORE-ENTRY',
  ['#Software: ExampleServer 1.2','#Version: 1.0',
   '#Start-Date: 2026-10-18 12:00:00',header],
  [['12:34:58','GET','/image']],
  [['12:34:58','GET','/image']],' ','\n'),
 ('W3C-TAB-CRLF',
  ['#Version: 1.0',header],
  [['12:34:59','GET','/api']],
  [['12:34:59','GET','/api']],'\t','\r\n'),
 ('W3C-DOUBLE-QUOTE-DECODING',
  ['#Version: 1.0',header],
  [['12:35:00','GET','"/path""quote"']],
  [['12:35:00','GET','/path"quote']],' ','\n'),
 ('W3C-MULTIROW-AND-REMARK',
  ['#Version: 1.0',header],
  [['12:35:01','GET','/one'],['12:35:02','POST','-']],
  [['12:35:01','GET','/one'],['12:35:02','POST','-']],' ','\n'),
]
invalid=[
 ('W3C-MISSING-VERSION',[header,'12:34:56 GET /page\n'],True),
 ('W3C-VERSION-2-NOT-QUALIFIED',['#Version: 2.0',header,'12:34:56 GET /page\n'],True),
 ('W3C-VERSION-1-1-NOT-QUALIFIED',['#Version: 1.1',header,'12:34:56 GET /page\n'],True),
 ('W3C-DUPLICATE-VERSION',['#Version: 1.0','#Version: 1.0',header,'12:34:56 GET /page\n'],True),
 ('W3C-LATE-VERSION',[header,'12:34:56 GET /page\n','#Version: 1.0'],False),
 ('W3C-MISSING-FIELDS',['#Version: 1.0','12:34:56 GET /page\n'],True),
 ('W3C-LATE-FIELDS',['#Version: 1.0','12:34:56 GET /page\n',header],False),
 ('W3C-REPEATED-FIELDS',['#Version: 1.0',header,header,'12:34:56 GET /page\n'],True),
 ('W3C-BLANK-VERSION',['#Version:',header,'12:34:56 GET /page\n'],True),
 ('W3C-MALFORMED-VERSION',['#Version: 1.invalid',header,'12:34:56 GET /page\n'],True),
 ('W3C-LOWERCASE-VERSION-UNQUALIFIED',['#version: 1.0',header,'12:34:56 GET /page\n'],True),
 ('W3C-UNTERMINATED-LAST-ROW',['#Version: 1.0',header,'12:34:56 GET /page'],True),
]
cases=[]
for case_id,directives,lexical_rows,decoded_rows,delimiter,eol in valid:
 assert len(lexical_rows)==len(decoded_rows)
 data_lines=[delimiter.join(x) for x in lexical_rows]
 lines=directives+data_lines
 wire=eol.join(lines)+eol
 claims=[]
 startCursor=0
 for rowIndex,(line,parts,decoded) in enumerate(zip(data_lines,lexical_rows,decoded_rows)):
  at=wire.find(line,startCursor)
  if at<0:raise RuntimeError((case_id,'missing source row'))
  begin=0
  for name,lex,value in zip(names,parts,decoded):
   if line[begin:begin+len(lex)]!=lex:
    raise RuntimeError((case_id,'independent lexeme not at row position'))
   s=len(wire[:at+begin].encode('utf8'))
   end=s+len(lex.encode('utf8'))
   if wire.encode('utf8')[s:end]!=lex.encode('utf8'):
    raise RuntimeError((case_id,'wrong source byte interval'))
   claims.append({'rowIndex':rowIndex,'name':name,'rawLexeme':lex,
      'decodedValue':value,'startByte':s,'endByte':end})
   begin+=len(lex)+len(delimiter)
  startCursor=at+len(line)
 cases.append({'id':case_id,'wire':wire,'validV1':True,'claims':claims,
   'expectedRows':len(data_lines),'expectedFields':names,
   'lineEnding':'crlf' if eol=='\r\n' else 'lf',
   'sourceBytes':len(wire.encode('utf8')),
   'sourceSha256':sha(wire.encode('utf8'))})
for case_id,items,lastHasNewline in invalid:
 # Keep each original authored physical row exactly once; no accidental
 # blank lines should make a separate metadata-grammar probe trivial.
 lines=[item.removesuffix('\n') for item in items]
 if any('\n' in line for line in lines):
  raise RuntimeError((case_id,'unexpected embedded record separator'))
 wire='\n'.join(lines)
 if case_id!='W3C-UNTERMINATED-LAST-ROW':
  wire+='\n'
 if case_id=='W3C-UNTERMINATED-LAST-ROW' and wire.endswith('\n'):
  raise RuntimeError('truncation control unexpectedly has EOL')
 cases.append({'id':case_id,'wire':wire,'validV1':False,'claims':[],
   'expectedRows':0,'sourceBytes':len(wire.encode('utf8')),
   'sourceSha256':sha(wire.encode('utf8'))})
data={'authority':'W3C Extended Log File Format Working Draft WD-logfile-960323 Sections Format/Entries',
 'rule':'Version 1.0 and Fields must precede all entries; single W3C document source only',
 'evidence':'Independently authored synthetic expected outcome, NOT publisher device/native wire',
 'cases':cases}
blob=(json.dumps(data,ensure_ascii=False,indent=2)+'\n').encode('utf8')
p=Path('scripts/poc/standardW3cRequiredDeclarations.pinned.json')
p.write_bytes(blob)
print('FROZEN',p,'SHA256',sha(blob),'TOTAL',len(cases),
 'valid',len(valid),'invalid',len(invalid))
