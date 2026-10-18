#!/usr/bin/env python3
"""Freeze hand-authored CSV source-field truth before scoring a candidate.

Palo Alto's official SD-WAN note documents non-RFC4180 curly-braced,
comma-containing link_switches cells. These particular raw records are
INDEPENDENTLY AUTHORED SYNTHETICS, not actual PAN-OS device captures.
"""
from pathlib import Path
import hashlib,json

SHA=lambda raw:hashlib.sha256(raw).hexdigest()
cases=[]
header4='event_id,link_switches,action,location'
def cell(lex,decoded=None,braced=False):
    return {'lexical':lex,'decoded':lex if decoded is None else decoded,
            'quoted':lex.startswith('"'),'braced':braced}
def valid(case_id, authored, *, header=header4,declared=(1,)):
    raw=','.join(c['lexical'] for c in authored)
    wire=raw.encode('utf8')
    cells=[];p=0
    names=header.split(',')
    assert len(names)==len(authored),case_id
    for ordinal,c in enumerate(authored):
        b=c['lexical'].encode('utf8')
        assert wire[p:p+len(b)]==b
        cells.append({
          'ordinal':ordinal,'name':names[ordinal],
          'value':c['decoded'],'quoted':c['quoted'],
          'bracedGroup':c['braced'],
          'startByte':p,'endByte':p+len(b),'rawLexeme':c['lexical'],
        })
        p+=len(b)+1
    assert len(wire)+1==p,case_id
    cases.append({'id':case_id,'wire':raw,'declaredColumns':list(declared),
       'headerRaw':header,'valid':True,'sourceBytes':len(wire),
       'sha256':SHA(wire),'cells':cells})
def invalid(case_id,wire,*,header=header4,declared=(1,)):
    b=''.join('\ufffd' if 0xd800<=ord(c)<=0xdfff else c for c in wire).encode('utf8')
    cases.append({'id':case_id,'wire':wire,'declaredColumns':list(declared),
       'headerRaw':header,'valid':False,'sourceBytes':len(b),
       'sha256':SHA(b),'cells':[]})

valid('BRACED_INNER_COMMAS',[
 cell('E7'),cell('{wan0, blue, ethernet, port1, 2026-10-18T12:00:00Z, 100, 120, up, -}',braced=True),
 cell('deny'),cell('EU')])
valid('BRACED_NESTED_GROUPS',[
 cell('E8'),cell('{{link1,up},{link2,down}}',braced=True),cell('allow'),cell('US')])
valid('BRACED_EMPTY_GROUP_NOT_NULL',[
 cell('E9'),cell('{}',braced=True),cell('allow'),cell('US')])
valid('DECLARED_COLUMN_EMPTY_SOURCE',[
 cell('E10'),cell(''),cell('allow'),cell('US')])
valid('DECLARED_COLUMN_PLAIN_LITERAL',[
 cell('E11'),cell('none'),cell('deny'),cell('US')])
valid('BRACED_QUOTED_NEXT_FIELD',[
 cell('E12'),cell('{wan1, 1, physical}',braced=True),
 cell('"blocked, policy"',decoded='blocked, policy'),cell('APAC')])
valid('BRACED_UTF8_ABSOLUTE_BYTE_OFFSETS',[
 cell('보안€😀'),cell('{링크1, 태그😀, port-1}',braced=True),cell('allow'),cell('KR')])
valid('BRACED_AT_FIRST_COLUMN',[
 cell('{a,b}',braced=True),cell('deny'),cell('KR')],
 header='link_switches,action,region',declared=(0,))
valid('BRACED_AT_LAST_COLUMN',[
 cell('E13'),cell('deny'),cell('{left,right}',braced=True)],
 header='event_id,action,link_switches',declared=(2,))
valid('TWO_DECLARED_BRACE_COLUMNS',[
 cell('E14'),cell('{wanA,1}',braced=True),cell('{wanB,2}',braced=True),cell('allow')],
 header='event_id,link_primary,link_secondary,action',declared=(1,2))
valid('BRACED_MULTIPLE_NESTED_WITH_TRAILING_EMPTY',[
 cell('E15'),cell('{{wanA,one},{wanB,two}}',braced=True),cell('allow'),cell('')],
 header=header4)
valid('STANDARD_QUOTED_GROUP_NOT_DIALECT',[
 cell('E16'),cell('"{quoted, ordinary}"',decoded='{quoted, ordinary}'),cell('allow'),cell('US')])
valid('STANDARD_PLAINTEXT_NO_GROUP',[
 cell('E17'),cell('word'),cell('allow'),cell('US')])
valid('BRACE_IN_SCALAR_NOT_START_OF_CELL',[
 cell('E18'),cell('pre{not-structural}'),cell('allow'),cell('US')])

invalid('NO_EXPLICIT_GROUP_DECLARATION',
 'E7,{a,b},deny,US',declared=())
invalid('GROUP_DECLARED_WRONG_COLUMN',
 'E7,{a,b},deny,US',declared=(2,))
invalid('UNCLOSED_GROUP','E7,{a,b,deny,US')
invalid('STRAY_GROUP_CLOSE','E7,{a,b}},deny,US')
invalid('TRAILING_TEXT_AFTER_CLOSE','E7,{a,b}x,deny,US')
invalid('TRAILING_SECOND_GROUP','E7,{a,b}{c,d},deny,US')
invalid('NESTING_BEYOND_BOUND','E7,{{{{{one,two}}}}},deny,US')
invalid('UNKNOWN_ESCAPE_IN_BRACED_GROUP','E7,{a\\,b},deny,US')
invalid('AMBIGUOUS_QUOTE_IN_GROUP','E7,{a"b,c},deny,US')
invalid('NEWLINE_IN_UNQUOTED_GROUP','E7,{a\nb,c},deny,US')
invalid('CONTROL_IN_GROUP','E7,{a\x01b,c},deny,US')
invalid('NUL_IN_GROUP','E7,{a\x00b,c},deny,US')
invalid('COLUMN_COUNT_MISMATCH','E7,{a,b},deny,US,extra')
invalid('DUPLICATE_DECLARATION_COLUMNS','E7,{a,b},deny,US',declared=(1,1))
invalid('OUT_OF_RANGE_DECLARED_ORDINAL','E7,{a,b},deny,US',declared=(1,9))
invalid('MALFORMED_HEADER_DUPLICATE','E7,{a,b},deny,US',
        header='event_id,link_switches,action,action')
invalid('NO_SOURCE_SCHEMA_NAMES','E7,{a,b},deny,US',header='')
invalid('UNPAIRED_SURROGATE','E7,{\ud800,b},deny,US')
invalid('UNCLOSED_STANDARD_QUOTE','E7,"{one,two},deny,US')

payload={
 'authority':'Palo Alto Networks official knowledgebase: SD-WAN link_switches cells can contain commas inside curly braces (PAN-OS 9.1+)',
 'officialReference':'https://knowledgebase.paloaltonetworks.com/KCSArticleDetail?id=kA14u0000004LaOCAU',
 'publisherSampleContext':'https://github.com/elastic/integrations/issues/16486',
 'scope':'SYNTHETIC_GENERAL_DECLARED_NON_RFC4180_CELL_GROUPING_NOT_MANUFACTURER_NATIVE',
 'observedRealDeviceCapturedHere':False,
 'manufacturerEscapeDecodeCertified':False,
 'cases':cases,
}
dest=Path('scripts/poc/standard83DeclaredBracedCsv.pinned.json')
wire=(json.dumps(payload,ensure_ascii=True,indent=2)+'\n').encode('utf8')
dest.write_bytes(wire)
print('STD83_PIN',json.dumps({
 'cases':len(cases),
 'valid':sum(x['valid'] for x in cases),
 'invalid':sum(not x['valid'] for x in cases),
 'manualFieldTruth':sum(len(x['cells']) for x in cases),
 'sha256':SHA(wire),
}))
