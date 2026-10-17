#!/usr/bin/env python3
"""Freeze authoritative standard references BEFORE executing candidate grammar.

These documents contain third-party material: bytes remain private (0700/0600).
Only stable source fingerprints, identities, classification and file sizes
are committed. A standard reference is not a publisher-origin log golden.
"""
from pathlib import Path
from urllib.request import Request, urlopen
from urllib.error import URLError
import hashlib
import json
import os
import re

PRIVATE=Path.home()/'.local/state/parserstudio-p0-standards-audit-20261018'
MANIFEST=Path(__file__).with_name('normativeGrammarSources.pinned.json')
SOURCES=(
 ('RFC3164','informational_historic','https://www.rfc-editor.org/rfc/rfc3164.txt','header/relay/legacy'),
 ('RFC5424','standards_track','https://www.rfc-editor.org/rfc/rfc5424.txt','section 6 header/SD/MSG'),
 ('RFC6587','informational_historic','https://www.rfc-editor.org/rfc/rfc6587.txt','3.4 framing'),
 ('RFC5425','standards_track','https://www.rfc-editor.org/rfc/rfc5425.txt','TLS/transport'),
 ('RFC8259','standards_track','https://www.rfc-editor.org/rfc/rfc8259.txt','JSON grammar'),
 ('RFC7464','standards_track','https://www.rfc-editor.org/rfc/rfc7464.txt','JSON text sequence'),
 ('RFC4180','informational','https://www.rfc-editor.org/rfc/rfc4180.txt','CSV baseline'),
 ('CEF26','industry_vendor_spec','https://www.microfocus.com/documentation/arcsight/arcsight-smartconnectors-8.3/cef-implementation-standard/Content/CEF/Chapter%201%20What%20is%20CEF.htm','header/extension/encoding'),
 ('LEEF20','industry_vendor_spec','https://www.ibm.com/docs/en/dsm?topic=overview-leef-event-components','header/attribute/delimiter'),
 ('W3CLOG','w3c_working_draft','https://www.w3.org/TR/WD-logfile.html','extended log format'),
 ('ZEEK','project_spec','https://raw.githubusercontent.com/zeek/zeek/63f863c6a4d5cc95a724863ab31237c02eda0eac/scripts/base/frameworks/logging/main.zeek','logger defaults / delimiter / empty / unset definitions'),
)
def sha(data):return hashlib.sha256(data).hexdigest()
def main():
 PRIVATE.mkdir(mode=0o700,parents=True,exist_ok=True)
 os.chmod(PRIVATE,0o700)
 refs=[];fail=[]
 for id_,kind,url,scope in SOURCES:
  file=PRIVATE/(id_+'.source')
  if file.exists():data=file.read_bytes()
  else:
   try:
    request=Request(url,headers={'User-Agent':'Mozilla/5.0 (Parser Studio standards conformance audit)','Accept':'text/html,text/plain'})
    with urlopen(request,timeout=23) as response:
     data=response.read(4_000_001)
    if len(data)>4_000_000:raise ValueError('oversize normative reference')
    fd=os.open(file,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
    with os.fdopen(fd,'wb') as output:output.write(data)
   except (OSError,URLError,ValueError) as e:
    fail.append({'id':id_,'error':type(e).__name__})
    continue
  if not data:raise ValueError('empty normative file: '+id_)
  if kind=='standards_track' and ('RFC' not in data.decode('utf8','ignore')[:3500]):
   raise ValueError('not an RFC source: '+id_)
  refs.append({'id':id_,'authorityClass':kind,'uri':url,'scope':scope,
      'privateSourceFile':file.name,'sha256':sha(data),'bytes':len(data),
      'sourceRedistributed':False})
 obj={'purpose':'AUTHORITATIVE_GRAMMAR_SOURCE_PIN_NOT_NATIVE_OR_PRODUCT_CERTIFICATION',
       'sources':refs,'unavailable':fail,'privateDirectory':'~/.local/state/parserstudio-p0-standards-audit-20261018',
       'noRawVendorFixturesCommitted':True}
 data=(json.dumps(obj,sort_keys=True,indent=2)+'\n').encode()
 if MANIFEST.exists() and MANIFEST.read_bytes()!=data:
  raise ValueError('Previously frozen normative source manifest drift')
 if not MANIFEST.exists():MANIFEST.write_bytes(data)
 print(json.dumps({'sourceReferences':len(refs),'unavailable':fail,
      'manifestSha256':sha(data),'privateValuesPrinted':False,
      'authorityTypes':sorted(set(x['authorityClass'] for x in refs))},sort_keys=True))
if __name__=='__main__':main()
