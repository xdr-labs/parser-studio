#!/usr/bin/env python3
"""Independent publisher-first CEF v26 escape/spacing source oracle.

Official HTML and canonical publisher examples remain private; Git receives
only source hash/field names/lexical and decoded value hash/UTF-8 intervals.
"""
from html.parser import HTMLParser
from pathlib import Path
import hashlib
import os
import re
import json

PUBLISHER='https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm'
PINNED_HTML_SHA='e5403a0362d8534af933c3038d15c4b847c70d9fab75a282f91097e27489a994'
private=Path.home()/'.local/state/parserstudio-std9-publisher-cef-leef-20261018'
data=(private/'cef.publisher.html').read_bytes()
digest=lambda b:hashlib.sha256(b).hexdigest()
if digest(data)!=PINNED_HTML_SHA:raise RuntimeError('CEF publisher original changed before scoring')
class TextFromHtml(HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.items=[]
 def handle_starttag(self,t,attrs):
  if t in ('p','br','li','tr','td','div','pre','h1','h2','h3'):self.items.append('\n')
 def handle_data(self,text):self.items.append(text)
doc=TextFromHtml();doc.feed(data.decode('utf8','strict'))
visible=''.join(doc.items)
# Select four explicit character-encoding examples, NOT the plain v0/1
# illustrations already frozen in the separate publisher PoC.
rx=r'^Sep [0-9]{2} 08:26:10 host CEF:0\|security\|threatmanager\|[^\r\n]+$'
examples=re.findall(rx,visible,re.M)
if len(examples)!=4:raise RuntimeError('The official v26 CEF encoding example set changed')
expected_markers=[
 (r'\|', 'act=', 'dst='),
 (r'\\', 'act=', 'dst='),
 (r'\=', 'act=', 'dst='),
 (r'\n', 'msg=', None),
]
for index,(needle,key,nextkey) in enumerate(expected_markers):
 raw=examples[index]
 if needle not in raw:raise RuntimeError(f'Official example {index} escape marker differs')
 if key not in raw:raise RuntimeError(f'Official example {index} field marker differs')
 if nextkey is not None and nextkey not in raw:raise RuntimeError('Official field sequence differs')

def decode_header(lex):
 result=[];pos=0
 while pos<len(lex):
  c=lex[pos]
  if c=='\\':
   if pos+1==len(lex) or lex[pos+1] not in ('|','\\'):
    raise RuntimeError('Unknown header escape in protected published example')
   result.append(lex[pos+1]);pos+=2;continue
  result.append(c);pos+=1
 return ''.join(result)

def decode_extension(lex):
 result=[];pos=0
 while pos<len(lex):
  c=lex[pos]
  if c=='\\':
   if pos+1==len(lex):raise RuntimeError('Truncated publisher CEF extension escape')
   token=lex[pos+1]
   values={'n':'\n','r':'\r','=':'=','\\':'\\'}
   result.append(values.get(token,'\\'+token))
   pos+=2
  else:result.append(c);pos+=1
 return ''.join(result)

originals=Path.home()/'.local/state/parserstudio-std9-cef-extension-publisher-20261018'
originals.mkdir(mode=0o700,parents=True,exist_ok=True)
os.chmod(originals,0o700)
names=['version','deviceVendor','deviceProduct','deviceVersion',
       'deviceEventClassId','name','severity']
records=[]
for index,wire in enumerate(examples):
 bodyStart=wire.index('CEF:')
 prefix=wire[:bodyStart]
 if prefix!='Sep 19 08:26:10 host ':raise RuntimeError('Publisher Syslog preamble changed')
 raw=wire.encode('utf8')
 basename=f'cef-encoding-{index}.raw'
 f=originals/basename
 f.write_bytes(raw);os.chmod(f,0o600)
 claims=[]
 cursor=bodyStart+4
 for i,name in enumerate(names):
  begin=cursor
  while cursor<len(wire):
   c=wire[cursor]
   if c=='\\':
    cursor+=2;continue
   if c=='|':break
   cursor+=1
  if cursor>=len(wire):raise RuntimeError('Publisher header has no required delimiter')
  end=cursor
  lexical=wire[begin:end]
  decoded=decode_header(lexical)
  startByte=len(wire[:begin].encode('utf8'))
  endByte=len(wire[:end].encode('utf8'))
  if raw[startByte:endByte]!=lexical.encode('utf8'):
    raise RuntimeError('Independent header raw source interval drift')
  claims.append({
    'name':name,'ordinal':i,'category':'header',
    'startByte':startByte,'endByte':endByte,
    'rawSha256':digest(lexical.encode('utf8')),
    'decodedSha256':digest(decoded.encode('utf8')),
  })
  cursor+=1
 ext=wire[cursor:]
 found=list(re.finditer(r'(?:^|[ \t])([A-Za-z_][A-Za-z0-9_.-]{0,127})=',ext))
 if len(found)<2 or found[0].start()!=0:raise RuntimeError('Publisher extension boundary shape differs')
 exp=['src','act','dst'] if index<3 else ['src','msg']
 if [m.group(1) for m in found]!=exp:
  raise RuntimeError(f'Publisher extension keys differ at example {index}')
 for j,match in enumerate(found):
  name=match.group(1)
  valStart=cursor+match.end()
  valEnd=cursor+(found[j+1].start() if j+1<len(found) else len(ext))
  # For CEF, the last space before the next key is the delimiter,
  # not part of the previous value. Other spaces are original value.
  lexical=wire[valStart:valEnd]
  decoded=decode_extension(lexical)
  startByte=len(wire[:valStart].encode('utf8'))
  endByte=len(wire[:valEnd].encode('utf8'))
  if raw[startByte:endByte]!=lexical.encode('utf8'):
    raise RuntimeError('Independent extension raw source interval drift')
  claims.append({
    'name':name,'ordinal':len(names)+j,'category':'extension',
    'startByte':startByte,'endByte':endByte,
    'rawSha256':digest(lexical.encode('utf8')),
    'decodedSha256':digest(decoded.encode('utf8')),
  })
 expected=10 if index<3 else 9
 if len(claims)!=expected:raise RuntimeError('Pinned case field denominator mismatch')
 records.append({
   'id':f'CEF-PUBLISHER-ESCAPE-{index}',
   'privateFile':basename,
   'originalSha256':digest(raw),
   'originalBytes':len(raw),
   'cefMarkerByte':len(prefix.encode('utf8')),
   'originalPrefixSha256':digest(prefix.encode('utf8')),
   'claimCount':len(claims),'claims':claims,
 })
manifest={
 'provenance':'Publisher-authored ArcSight CEF implementation standard v26 encoding examples, NOT live device wire, NOT native.',
 'publisherUri':PUBLISHER,
 'publisherHtmlSha256':PINNED_HTML_SHA,
 'canonicalization':'Exact four complete displayed source lines; surrounding HTML layout whitespace excluded.',
 'cases':records,'sourceOnly':True,'nativeTarget':'NOT_VERIFIED',
 'historicalCasesRelabeled':False,
}
blob=(json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode('utf8')
p=Path('scripts/poc/standardCefPublisherEscapes.pinned.json')
p.write_bytes(blob)
print('CEF_ESCAPE_ORACLE_FROZEN',p,'SHA256',digest(blob),
 'OFFICIAL_EXAMPLES',len(records),'TOTAL_FIELD_CLAIMS',
 sum(c['claimCount'] for c in records))
for x in records:print('PRIVATE_EXACT_ORIGINAL_SHA',x['id'],x['originalSha256'],
 'BYTES',x['originalBytes'],'MODE',oct((originals/x['privateFile']).stat().st_mode & 0o777))
