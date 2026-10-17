#!/usr/bin/env python3
"""Freeze publisher-authored CrowdsSec expected raw-stage source spans BEFORE scoring.

Third-party MIT upstream source revision, original input and expected assertions
are hashed and kept private. No generated candidate output is read by this file.
"""
import ast
import collections
import hashlib
import json
import pathlib
import re
import os

ROOT=pathlib.Path.home()/'.local/state/parserstudio-new-independent-security-20261017'
SOURCE_MANIFEST_SHA='383b53ecd5460406edb0157bfffc70fafd64dd798f09f9a9830327ef2cf3397c'
assert hashlib.sha256((ROOT/'source_manifest.json').read_bytes()).hexdigest()==SOURCE_MANIFEST_SHA
manifest=json.loads((ROOT/'source_manifest.json').read_text())
pairs=[(0,1),(2,3),(4,5),(6,7)]
mapping={'message':'message','program':'appname','logsource':'hostname',
         'timestamp':'timestamp','timestamp8601':'timestamp',
         'syslog_priority':'pri','syslog_version':'version','pid':'procid'}
pattern=re.compile(r'^results\["s00-raw"\]\["[^"]+"\]\[(?P<index>\d+)\]\.Evt\.Parsed\["(?P<name>[^"]+)"\]\s*==\s*(?P<literal>.+)$')
compiled=[]
excluded=collections.Counter()
totals=collections.Counter()
for num,(a,b) in enumerate(pairs):
 l=manifest[a]; exp=manifest[b]
 assert l['kind']=='upstream_original_log' and exp['kind']=='upstream_parser_assertion'
 raw_bytes=(ROOT/l['private_file']).read_bytes()
 assert hashlib.sha256(raw_bytes).hexdigest()==l['sha256']
 original=raw_bytes.decode('utf8').splitlines()
 expected=(ROOT/exp['private_file']).read_text('utf8')
 source={}
 for line in expected.splitlines():
  r=pattern.match(line)
  if not r:continue
  row=int(r['index']); name=r['name']
  try:value=ast.literal_eval(r['literal'])
  except (SyntaxError,ValueError):excluded['NOT_LITERAL_ASSERTION']+=1;continue
  if not isinstance(value,str):excluded['NONSTRING_ASSERTION']+=1;continue
  source.setdefault(row,[]).append((name,value))
 totals['original_physical_lines']+=len(original)
 totals['asserted_original_rows']+=len(source)
 for row,source_line in enumerate(original):
  record={'publisher':'crowdsecurity/hub','source_file':l['path'],
          'upstream_revision':l['revision'],'original_line_index':row,
          'raw':source_line,'fields':[],'status':'UNSCORABLE_NO_AUTHOR_EXPECTATION'}
  if row not in source:
   excluded['ROW_WITHOUT_ASSERTED_RAW_FIELDS']+=1
   compiled.append(record);continue
  for name,value in source[row]:
   if name not in mapping:excluded['UNSUPPORTED_PUBLISHER_FIELD']+=1;continue
   if not value:excluded['EMPTY_EXPECTED_NO_SOURCE_RANGE']+=1;continue
   text=source_line.encode('utf8');needle=value.encode('utf8')
   count=text.count(needle)
   if count!=1:
    excluded['NO_UNIQUE_EXACT_SOURCE_LITERAL']+=1;continue
   start=text.index(needle);end=start+len(needle)
   assert text[start:end].decode('utf8')==value
   record['fields'].append({'publisher_assertion':name,'canonical_field':mapping[name],
      'value':value,'startByte':start,'endByte':end,'type':'string',
      'qualification':'PUBLISHER_ASSERTED_RAW_STAGE_UNIQUE_SOURCE_VALUE'})
  record['status']='PARTIAL_SCORABLE' if record['fields'] else 'UNSCORABLE_NO_EXACT_SOURCE_SPAN'
  compiled.append(record)
  totals['partial_scored_source_triples']+=len(record['fields'])
totals['partial_scored_events']=sum(x['status']=='PARTIAL_SCORABLE' for x in compiled)
totals['explicitly_unscorable_events']=sum(x['status']!='PARTIAL_SCORABLE' for x in compiled)
totals['total_records']=len(compiled)
out=ROOT/'crowdsec-independent-raw-stage-expected.v1.json'
out.write_text(json.dumps(compiled,ensure_ascii=False,separators=(',',':')))
os.chmod(out,0o600)
print('FROZEN_UPSTREAM_EXPECTED_BEFORE_CANDIDATE',
 json.dumps({'totals':totals,'exclusions':excluded,
 'manifest_sha256':SOURCE_MANIFEST_SHA,
 'oracle_sha256':hashlib.sha256(out.read_bytes()).hexdigest(),
 'authored_source': 'crowdsecurity/hub@46df77d6739c41b4e808ef572188f950ba84fecd',
 'scope':'PUBLISHER_ASSERTED_RAW_STAGE_PARTIAL_SOURCE_ONLY_NOT_NATIVE',
 'raw_logs_or_asserted_values_printed':False}))
