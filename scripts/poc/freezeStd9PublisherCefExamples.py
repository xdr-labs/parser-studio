#!/usr/bin/env python3
"""Freeze genuine publisher-written CEF documentation examples before parser scoring.

Original publisher HTML/wire examples stay mode-0600 private; only source SHA,
field ordinal/byte interval/name and expected value hashes enter the repository.
"""
from html.parser import HTMLParser
from pathlib import Path
import hashlib
import json
import os
import re

PRIVATE=Path.home()/'.local/state/parserstudio-std9-publisher-cef-leef-20261018'
URL='https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm'
HTML_SHA='e5403a0362d8534af933c3038d15c4b847c70d9fab75a282f91097e27489a994'
html=(PRIVATE/'cef.publisher.html').read_bytes()
digest=lambda raw:hashlib.sha256(raw).hexdigest()
if digest(html)!=HTML_SHA:raise RuntimeError('Publisher-authored CEF HTML SHA changed; no parser success inferred')
os.chmod(PRIVATE,0o700)
class VisibleText(HTMLParser):
 def __init__(self):super().__init__(convert_charrefs=True);self.blocks=[]
 def handle_starttag(self,tag,attrs):
  if tag in ('br','p','li','tr','td','div','pre','h1','h2','h3'):self.blocks.append('\n')
 def handle_data(self,data):self.blocks.append(data)
p=VisibleText();p.feed(html.decode('utf8','strict'))
text=''.join(p.blocks)
examples=[]
for label,version in [('For CEF 0.x version', '0'),('For CEF 1.x version','1')]:
 at=text.find(label)
 if at<0 or text.find(label,at+1)>=0:
  raise RuntimeError('Publisher version-example heading missing or ambiguous')
 match=re.search(r'^Sep [0-9]{2} 08:26:10 host CEF:'+version+r'\|[^\r\n]+$',text[at:],re.M)
 if match is None:raise RuntimeError('Publisher version-example line missing')
 examples.append(match.group())
if len(examples)!=2:raise RuntimeError('Publisher version example denominator drift')

names=['version','deviceVendor','deviceProduct','deviceVersion','deviceEventClassId','name','severity']
extensionNames=['src','dst','spt']
oracle=[]
for index,line in enumerate(examples):
 raw=line.encode('utf8')
 name=f'cef-publisher-example-{index}.raw'
 source=PRIVATE/name
 source.write_bytes(raw);os.chmod(source,0o600)
 # The original publisher example specifies the BSD-style prefix and
 # begins its CEF header after the literal CEF: marker.
 cefAt=line.index('CEF:')
 prefix=line[:cefAt]
 assert prefix=='Sep '+('19' if index==0 else '29')+' 08:26:10 host '
 cursor=cefAt+4
 claims=[]
 for ordinal,key in enumerate(names):
  end=line.find('|',cursor)
  if end<0:raise RuntimeError('The official example lacks a required CEF header field')
  lexical=line[cursor:end]
  if not lexical:raise RuntimeError('Empty CEF header in official source')
  beginByte=len(line[:cursor].encode('utf8'))
  endByte=len(line[:end].encode('utf8'))
  assert raw[beginByte:endByte]==lexical.encode('utf8')
  claims.append({'name':key,'ordinal':ordinal,'category':'header',
    'startByte':beginByte,'endByte':endByte,
    'rawValueSha256':digest(lexical.encode('utf8')),
    'decodedValueSha256':digest(lexical.encode('utf8'))})
  cursor=end+1
 values=line[cursor:].split(' ')
 if len(values)!=3:raise RuntimeError('Published CEF extension token count drift')
 for ordinal,token in enumerate(values):
  if not token.startswith(extensionNames[ordinal]+'='):
   raise RuntimeError('Unexpected source extension key/order: publisher example changed')
  key,value=token.split('=',1)
  at=line.find(token,cursor)
  if at<cursor:raise RuntimeError('Token source interval cannot be recovered')
  begin=at+len(key)+1
  end=begin+len(value)
  beginByte=len(line[:begin].encode('utf8'))
  endByte=len(line[:end].encode('utf8'))
  assert raw[beginByte:endByte]==value.encode('utf8')
  claims.append({'name':key,'ordinal':len(names)+ordinal,'category':'extension',
    'startByte':beginByte,'endByte':endByte,
    'rawValueSha256':digest(value.encode('utf8')),
    'decodedValueSha256':digest(value.encode('utf8'))})
  cursor=at+len(token)
 if len(claims)!=10:raise RuntimeError('Independent header+extension truth denominator drift')
 oracle.append({'id':f'CEF-PUBLISHER-EXAMPLE-{index}','privateFile':name,
    'sourceSha256':digest(raw),'sourceBytes':len(raw),
    'cefBodyStartByte':len(prefix.encode('utf8')),
    'syslogPrefixSha256':digest(prefix.encode('utf8')),
    'syslogPrefixBytes':len(prefix.encode('utf8')),
    'claimCount':len(claims),'claims':claims})
manifest={'authorityClass':'ARCSIGHT_PUBLISHER_AUTHORED_CEF_STANDARD_ILLUSTRATIONS',
    'originalUri':URL,'htmlSha256':HTML_SHA,
    'canonicalization':'Exact published one-line example from HTML visible text; exclude layout-only surrounding whitespace.',
    'sourceScope':'Publisher manual illustrations, not independent device or native wire, nor blinded holdout.',
    'cases':oracle,'sourceOnly':True,'nativeVerified':False,'manufacturerOperationalSamples':0}
blob=(json.dumps(manifest,indent=2,ensure_ascii=False)+'\n').encode('utf8')
path=Path('scripts/poc/standard9PublisherCefExamples.pinned.json')
path.write_bytes(blob)
print('FROZEN',path,'SHA256',digest(blob),'publisher_examples',len(oracle),
      'source_field_claims',sum(x['claimCount'] for x in oracle))
for x in oracle:print('PRIVATE_SOURCE_SHA',x['id'],x['sourceSha256'],'BYTES',x['sourceBytes'],'FILE_MODE',
  oct((PRIVATE/x['privateFile']).stat().st_mode & 0o777))
