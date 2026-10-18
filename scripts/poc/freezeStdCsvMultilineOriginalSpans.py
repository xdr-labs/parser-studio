#!/usr/bin/env python3
"""Freeze RFC4180 quoted multiline CSV source truth BEFORE scoring candidates.

Derived from independently authored raw and decoded field pairs, never from
Parser Studio source. No native or manufacturer original-log claim.
"""
from pathlib import Path
import hashlib,json,re

sha=lambda value:hashlib.sha256(value).hexdigest()
header=[('timestamp','timestamp'),('action','action'),('message','message'),('flag','flag')]
def make(case_id,source_header,data_rows,separator='\r\n',last_terminated=True):
    authored=[source_header]+data_rows
    wire=''
    expected_claims=[]
    expected_records=[]
    header_names=[decoded for _,decoded in source_header]
    for row_position,columns in enumerate(authored):
        assert len(columns)==len(header_names),case_id
        row_start=len(wire.encode('utf8'))
        raw_values=[raw for raw,_ in columns]
        decoded_values=[value for _,value in columns]
        line=','.join(raw_values)
        cursor=0
        for column,(raw_lexeme,decoded_value) in enumerate(columns):
            assert line[cursor:cursor+len(raw_lexeme)]==raw_lexeme
            originalStart=row_start+len(line[:cursor].encode('utf8'))
            originalEnd=originalStart+len(raw_lexeme.encode('utf8'))
            row_index=row_position-1
            expected_claims.append({
                'rowIndex':row_index,'columnIndex':column,
                'columnName':header_names[column],
                'rawLexeme':raw_lexeme,
                'decodedValue':decoded_value,
                'quoted':raw_lexeme.startswith('"'),
                'startByte':originalStart,'endByte':originalEnd,
            })
            cursor+=len(raw_lexeme)+1
        is_last=row_position==len(authored)-1
        delimiter='' if is_last and not last_terminated else separator
        end=row_start+len(line.encode('utf8'))
        wire+=line+delimiter
        expected_records.append({
            'rowIndex':row_position-1,
            'startByte':row_start,
            'endByte':end,
            'terminatorBytes':len(delimiter.encode('utf8')),
            'physicalLines':1+len(re.findall(r'\r\n|\r|\n',line)),
        })
    wire_bytes=wire.encode('utf8')
    for field in expected_claims:
        b=wire_bytes[field['startByte']:field['endByte']]
        assert b==field['rawLexeme'].encode('utf8')
    for record in expected_records:
        assert wire_bytes[record['endByte']:record['endByte']+record['terminatorBytes']]==(
          '' if record['terminatorBytes']==0 else separator).encode('utf8')
    return {
        'id':case_id,'wire':wire,'valid':True,
        'header':header_names,'dataRows':len(data_rows),
        'lineEnding':'crlf' if separator=='\r\n' else 'lf',
        'originalClaims':expected_claims,
        'records':expected_records,
        'sourceBytes':len(wire_bytes),'sourceSha256':sha(wire_bytes),
    }

v=[
 make('CSV-MULTILINE-RFC-CRLF',header,[
   [('2026-10-18T10:00:00Z','2026-10-18T10:00:00Z'),('deny','deny'),
    ('"line1\r\nline2"','line1\r\nline2'),('true','true')]
 ]),
 make('CSV-MULTIROW-EMBEDDED-CRLF',header,[
   [('1','1'),('allow','allow'),('"one,\r\ntwo"','one,\r\ntwo'),('yes','yes')],
   [('2','2'),('block','block'),('"three\r\nfour\r\nfive"','three\r\nfour\r\nfive'),('no','no')]
 ]),
 make('CSV-QUOTED-BARE-CR',header,[
   [('12','12'),('allow','allow'),('"value\rnext"','value\rnext'),('yes','yes')]
 ]),
 make('CSV-QUOTE-EMBEDDED-CRLF-LF-CR',header,[
   [('13','13'),('deny','deny'),('"one\r\ntwo\nthree\rfour"','one\r\ntwo\nthree\rfour'),('no','no')]
 ]),
 make('CSV-ESCAPED-QUOTE',header,[
   [('3','3'),('alert','alert'),('"He said ""stop"""','He said "stop"'),('yes','yes')]
 ]),
 make('CSV-UTF8-SOURCE-SPANS',header,[
   [('4','4'),('deny','deny'),('"UTF8 €😀"','UTF8 €😀'),('yes','yes')]
 ]),
 make('CSV-EMPTY-QUOTED-VS-UNQUOTED',header,[
   [('5','5'),('allow','allow'),('""',''),('','')],
   [('6','6'),('deny','deny'),('',''),('""','')]
 ]),
 make('CSV-UNQUOTED-EDGE-SPACES',header,[
   [(' 7 ',' 7 '),(' allow ',' allow '),(' padded source ',' padded source '),('true','true')]
 ]),
 make('CSV-LF-COMPAT-NO-LAST-TERMINATOR',header,[
   [('8','8'),('allow','allow'),('"line1\nline2"','line1\nline2'),('true','true')]
 ],separator='\n',last_terminated=False),
 make('CSV-CRLF-LAST-NO-TERMINATOR',header,[
   [('9','9'),('deny','deny'),('message','message'),('true','true')],
   [('10','10'),('alert','alert'),('final','final'),('false','false')]
 ],last_terminated=False),
 make('CSV-QUOTED-HEADER',[
   ('"timestamp"','timestamp'),('action','action'),('"message"','message'),('flag','flag')
 ],[
   [('11','11'),('allow','allow'),('"reported, by firewall"','reported, by firewall'),('yes','yes')]
 ]),
]
invalid=[
 ('CSV-UNTERMINATED-QUOTED-MULTILINE',
  'timestamp,action,message,flag\r\n1,deny,"unfinished\r\nstill open,false\r\n'),
 ('CSV-UNKNOWN-CHAR-AFTER-QUOTE',
  'timestamp,action,message,flag\r\n1,deny,"closed"junk,false\r\n'),
 ('CSV-SPACE-AFTER-QUOTED-CLOSE',
  'timestamp,action,message,flag\r\n1,deny,"closed" ,false\r\n'),
 ('CSV-QUOTE-INSIDE-UNQUOTED',
  'timestamp,action,message,flag\r\n1,deny,unquoted"bad,false\r\n'),
 ('CSV-ROW-COLUMN-DRIFT',
  'timestamp,action,message,flag\r\n1,deny,"quoted\r\nline"\r\n'),
 ('CSV-DUPLICATE-COLUMN',
  'timestamp,action,message,message\r\n1,deny,hello,false\r\n'),
 ('CSV-MIXED-OUTER-RECORD-TERMINATORS',
  'timestamp,action,message,flag\r\n1,deny,foo,false\n2,allow,bar,true\r\n'),
 ('CSV-UNQUOTED-TAB-DISALLOWED',
  'timestamp,action,message,flag\r\n1,deny,contains\tTAB,false\r\n'),
 ('CSV-QUOTED-TAB-DISALLOWED',
  'timestamp,action,message,flag\r\n1,deny,"contains\tTAB",false\r\n'),
 ('CSV-UNQUOTED-C0-DISALLOWED',
  'timestamp,action,message,flag\r\n1,deny,bad\x01value,false\r\n'),
 ('CSV-QUOTED-DEL-DISALLOWED',
  'timestamp,action,message,flag\r\n1,deny,"bad\x7fvalue",false\r\n'),
]
for case_id,wire in invalid:
 b=wire.encode('utf8')
 v.append({'id':case_id,'wire':wire,'valid':False,'header':[],
  'dataRows':0,'originalClaims':[],'records':[],
  'sourceBytes':len(b),'sourceSha256':sha(b)})
data={
 'sourceAuthority':'RFC4180 section 2 quoted fields can contain CRLF and escaped quotes; explicit LF compatibility is separate',
 'provenance':'Independently authored format synthetic, NOT native or manufacturer publisher wire',
 'cases':v,
}
raw=(json.dumps(data,ensure_ascii=False,indent=2)+'\n').encode('utf8')
p=Path('scripts/poc/standardCsvMultilineOriginalSpans.pinned.json')
p.write_bytes(raw)
print('PINNED',len(v),'cases',len(v)-len(invalid),'valid',len(invalid),'invalid',
 'authoredFields',sum(len(c['originalClaims']) for c in v),
 'SHA256',sha(raw))
