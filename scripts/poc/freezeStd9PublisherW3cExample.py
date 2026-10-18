#!/usr/bin/env python3
"""Freeze W3C's independently publisher-authored EFL example before parser scoring.

Actual standards HTML and exact published source example are PRIVATE.
Commit only field digests/source intervals and a public URL+SHA manifest.
"""
import hashlib
from html.parser import HTMLParser
import json
import os
from pathlib import Path
import urllib.request

URL='https://www.w3.org/TR/logfile/'
DOC_SHA='4d05a8d6da5b574bdcc9a4aeebc2df146140ece850e239e150069d15c4206175'
STATE=Path.home()/'.local/state/parserstudio-std9-publisher-w3c-20261018'
STATE.mkdir(parents=True,exist_ok=True,mode=0o700)
os.chmod(STATE,0o700)
with urllib.request.urlopen(urllib.request.Request(
    URL,headers={'User-Agent':'ParserStudio-Standards-Audit/1.0'}),timeout=15) as response:
    document=response.read(250000)
sha=lambda b:hashlib.sha256(b).hexdigest()
if sha(document)!=DOC_SHA:raise RuntimeError('Publisher HTML reference hash drift')
class PublishedPre(HTMLParser):
  def __init__(self):super().__init__();self.depth=0;self.buf='';self.blocks=[]
  def handle_starttag(self,tag,attrs):
    if tag=='pre':self.depth+=1
  def handle_endtag(self,tag):
    if tag=='pre' and self.depth:
      self.depth-=1
      if self.depth==0:self.blocks.append(self.buf);self.buf=''
  def handle_data(self,data):
    if self.depth:self.buf+=data
p=PublishedPre();p.feed(document.decode('utf8'))
candidates=[x for x in p.blocks if '#Fields: time cs-method cs-uri' in x]
if len(candidates)!=1:raise RuntimeError('Expected one publisher-authored example only')
example=candidates[0]
if not example.startswith('\n#Version: 1.0\n'):
    raise RuntimeError('Publisher example formatting differs from the pinned source')
# Remove exactly one leading display-layout LF in the publisher HTML <pre>.
# All actual directive/data bytes are retained verbatim thereafter.
original=example[1:].encode('utf8')
lines=original.decode('utf8').splitlines(keepends=True)
if len(lines)!=7 or not all(x.endswith('\n') for x in lines):
    raise RuntimeError('Publisher example physical record shape differs')
names=lines[2][len('#Fields: '):].rstrip('\n').split(' ')
if names!=['time','cs-method','cs-uri']:
    raise RuntimeError('Publisher-declared field identity changed')
private_html=STATE/'w3c-efl-working-draft.html'
private_source=STATE/'w3c-efl-publisher-example.raw'
private_html.write_bytes(document);private_source.write_bytes(original)
for f in [private_html,private_source]:os.chmod(f,0o600)
fields=[]
bytepos=sum(len(x.encode('utf8')) for x in lines[:3])
rows=[]
for rowindex,line in enumerate(lines[3:]):
    rawrow=line[:-1]
    parts=rawrow.split(' ')
    if len(parts)!=3:raise RuntimeError('Publisher data row shape changed')
    ordered=[];cursor=0
    for col,(key,value) in enumerate(zip(names,parts)):
        original_start=bytepos+len(rawrow[:cursor].encode('utf8'))
        original_end=original_start+len(value.encode('utf8'))
        if original[original_start:original_end]!=value.encode('utf8'):
            raise RuntimeError('Publisher expected field interval drift')
        ordered.append({'rowIndex':rowindex,'ordinal':col,'name':key,
            'startByte':original_start,'endByte':original_end,
            'lexemeSha256':sha(value.encode('utf8')),
            'decodedSha256':sha(value.encode('utf8'))})
        cursor+=len(value)+1
    rows.append(ordered)
    bytepos+=len(line.encode('utf8'))
if bytepos!=len(original):raise RuntimeError('Full publisher example bytes not accounted')
manifest={
 'sourceClass':'PUBLISHER_AUTHORED_STANDARDS_EXAMPLE_NOT_PRODUCTION_WIRE',
 'uri':URL,
 'htmlSha256':DOC_SHA,
 'canonicalization':'Remove exactly one leading layout LF from the published <pre> example',
 'canonicalSourceSha256':sha(original),
 'canonicalSourceBytes':len(original),
 'physicalLines':7,
 'rows':4,
 'fieldClaims':12,
 'fieldNames':names,
 'publisherExpectedFields':rows,
 'nativeTarget':'NOT_VERIFIED',
 'notBlind':'Publisher example is published and available in advance; not manufacturer blind holdout',
}
artifact=Path('scripts/poc/standard9PublisherW3cExample.pinned.json')
bytes_= (json.dumps(manifest,ensure_ascii=False,indent=2)+'\n').encode('utf8')
artifact.write_bytes(bytes_)
print('FROZEN_ONLY_PUBLISHER_ORACLE',str(artifact),
      'ORACLE_SHA256',sha(bytes_),'RAW_SHA256',sha(original),
      'ORIGINAL_BYTES',len(original),'EVENTS',len(rows),
      'FIELD_DIGEST_CLAIMS',sum(len(row) for row in rows))
print('PRIVATE_SOURCE',private_source,'MODE',oct(private_source.stat().st_mode & 0o777))
