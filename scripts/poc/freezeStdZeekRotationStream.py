#!/usr/bin/env python3
"""Freeze original Zeek ASCII-writer closed block rotation and source span truth."""
from pathlib import Path
import hashlib
import json
sha=lambda data:hashlib.sha256(data).hexdigest()
def block(path,columns,types,rows,eol='\n'):
  assert len(columns)==len(types)
  for row in rows:assert len(row)==len(columns)
  lines=[
    r'#separator \x09','#set_separator\t,','#empty_field\t(empty)',
    '#unset_field\t-','#path\t'+path,
    '#open\t2026-10-18-12-00-00',
    '#fields\t'+'\t'.join(columns),
    '#types\t'+'\t'.join(types),
    *['\t'.join(row) for row in rows],
    '#close\t2026-10-18-12-01-00',
  ]
  return eol.join(lines)+eol
conn=lambda rows,eol='\n':block('conn',['ts','uid','id.orig_h'],['time','string','addr'],rows,eol)
dns=lambda rows,eol='\n':block('dns',['ts','query','rcode_name'],['time','string','string'],rows,eol)
event=lambda rows,eol='\n':block('notice',['uid','ts','msg'],['string','time','string'],rows,eol)
a=conn([['1.0','C1','192.0.2.1']])
b=conn([['2.0','C2','198.51.100.2']])
c=dns([['3.0','example.test','NOERROR'],['4.0','other.test','NXDOMAIN']])
e=event([['C3','5.0','€😀']],'\n')
f=conn([['6.0','C4','203.0.113.1']],'\r\n')
g=dns([['7.0','name.test','NXDOMAIN']],'\r\n')
valid=[
 ('ZEEK-ROTATE-SINGLE', [a], '\n'),
 ('ZEEK-ROTATE-TWO-SAME-SCHEMA', [a,b], '\n'),
 ('ZEEK-ROTATE-SCHEMA-CHANGES', [a,c], '\n'),
 ('ZEEK-ROTATE-THREE-UTF8', [a,c,e], '\n'),
 ('ZEEK-ROTATE-TWO-CRLF', [f,g], '\r\n'),
]
def mutate(text,needle,replacement):
 assert needle in text
 return text.replace(needle,replacement,1)
invalid=[
 ('ZEEK-ROTATE-TRAILING-ROW-AFTER-CLOSE', a+'8.0\tC8\t192.0.2.8\n'),
 ('ZEEK-ROTATE-MISSING-SECOND-SCHEMA', a+mutate(b,'#fields\tts\tuid\tid.orig_h\n','')),
 ('ZEEK-ROTATE-SECOND-TYPE-COUNT', a+mutate(c,'#types\ttime\tstring\tstring\n','#types\ttime\tstring\n')),
 ('ZEEK-ROTATE-UNKNOWN-SECOND-DIRECTIVE',a+mutate(b,'#path\tconn\n','#custom\tunknown\n#path\tconn\n')),
 ('ZEEK-ROTATE-DANGLING-LAST-BLOCK',a+b[:b.rfind('#close\t')]),
 ('ZEEK-ROTATE-EXTRA-TRAILING-NONBLOCK',a+b+'random trailing text\n'),
 ('ZEEK-ROTATE-MIXED-LINE-ENDINGS',a+g),
 ('ZEEK-ROTATE-EMPTY-SECOND-BLOCK',a+b[:b.index('2.0\tC2')]+b[b.rfind('#close\t'):]),
]
out=[]
for case_id,blocks,eol in valid:
 wire=''.join(blocks)
 block_truth=[]
 byteStart=0
 for blockIndex,s in enumerate(blocks):
  lines=s.split(eol)
  assert lines[-1]==''
  if len(lines)<10:raise ValueError(case_id)
  colrow=next(line for line in lines if line.startswith('#fields\t'))
  columns=colrow.split('\t')[1:]
  path=next(line for line in lines if line.startswith('#path\t')).split('\t')[1]
  rows=[line for line in lines if line and not line.startswith('#')]
  claims=[]
  blockOffset=0
  for rowindex,line in enumerate(lines[:-1]):
   if line in rows:
    withinBlock=blockOffset
    pos=0
    for name,value in zip(columns,line.split('\t')):
     start=byteStart+withinBlock+len(line[:pos].encode('utf8'))
     end=start+len(value.encode('utf8'))
     assert wire.encode('utf8')[start:end]==value.encode('utf8')
     claims.append({'row':rows.index(line),'name':name,'rawLexeme':value,
                    'startByte':start,'endByte':end})
     pos+=len(value)+1
   blockOffset+=len(line.encode('utf8'))+len(eol.encode('utf8'))
  assert blockOffset==len(s.encode('utf8'))
  block_truth.append({'blockIndex':blockIndex,'path':path,'fields':columns,
     'sourceStartByte':byteStart,'sourceEndByte':byteStart+blockOffset,
     'physicalLines':len(lines)-1,'rowCount':len(rows),'claims':claims})
  byteStart+=blockOffset
 out.append({'id':case_id,'wire':wire,'valid':True,'expected':block_truth,
   'sourceBytes':len(wire.encode('utf8')),
   'sourceSha256':sha(wire.encode('utf8')),
   'eventCount':sum(b['rowCount'] for b in block_truth)})
for case_id,wire in invalid:
 out.append({'id':case_id,'wire':wire,'valid':False,'expected':[],
   'sourceBytes':len(wire.encode('utf8')),
   'sourceSha256':sha(wire.encode('utf8')),'eventCount':0})
data={'authority':'Zeek official ASCII writer directives (immutable upstream pinned in previous STD audit)',
      'scope':'Independently authored synthetic concatenated closed log files, not producer-captured real stream/native verification',
      'cases':out}
blob=(json.dumps(data,ensure_ascii=False,indent=2)+'\n').encode('utf8')
p=Path('scripts/poc/standardZeekRotationStream.pinned.json')
p.write_bytes(blob)
print('FROZEN',len(out),'CASES',len(valid),'VALID',len(invalid),'INVALID',
      'SHA256',sha(blob))
