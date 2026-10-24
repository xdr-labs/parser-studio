#!/usr/bin/env python3
"""Source-only Loghub benchmark. No raw logs in Git, no LLM egress.

Metrics are extraction/framing observations, NOT semantic precision/recall,
ParserRecipe quality, device-verified accuracy, or native/target certification.
"""
from __future__ import annotations
import collections
import hashlib
import json
import os
from pathlib import Path
import sys
import time

PROJECT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(PROJECT/'runtime/multipass'))
from multipass_adjudicator import parse_security_multipass
from source_parse import assert_source_accounting

STATE=Path(os.environ.get('PARSER_STUDIO_IRREGULAR_ROOT',
 '/home/aella/.local/state/parserstudio-irregular-20261024'))
DATASETS=STATE/'corpus'
REPORT_NAME=os.environ.get('LOGHUB_REPORT_NAME','baseline-multipass.json')
if REPORT_NAME not in ('baseline-multipass.json','candidate-multipass.json'):
 raise ValueError('UNSUPPORTED_REPORT_NAME')
OUTPUT=STATE/REPORT_NAME
GENERIC=('GENERIC','UNKNOWN','ATOM','LABEL','BSD_CONTENT')
DOCUMENTED_ENVELOPE_OPAQUE_MESSAGE={
 'ANDROID_LOGCAT_THREADTIME','BRACKETED_MONTH_DAY_APPLICATION_TARGET'}
def is_generic(syntax:str)->bool:
 return any(s in syntax.upper() for s in GENERIC)

def main():
 registry=json.loads((DATASETS/'UPSTREAM.json').read_text(encoding='utf8'))
 maxlines=int(os.environ.get('LOGHUB_MAX_LINES','2000'))
 if not 1<=maxlines<=2000:raise ValueError('LOGHUB_MAX_LINES_OUT_OF_RANGE')
 report={'contract':'parserstudio.loghub.source-benchmark.v0.1',
 'method':'offline_source_parse_security_multipass_not_full_web_preview',
 'gitRevision':os.popen('git -C '+str(PROJECT)+' rev-parse HEAD').read().strip(),
 'upstreamCommit':registry['commit'],'maxLinesPerDataset':maxlines,
 'scope':'source-only diagnostics with private unsanitized samples, no remote LLM',
 'statusMeaning':'SOURCE_PARSED only means syntax/source extraction, not native compiler ready or semantic roles correct',
 'datasets':[],'totals':{}}
 total=collections.Counter()
 for source in registry['datasets']:
  name=source['name']
  p=DATASETS/(name+'_2k.log')
  blob=p.read_bytes()
  if hashlib.sha256(blob).hexdigest()!=source['sha256']:
   raise RuntimeError('RAW_UPSTREAM_HASH_DRIFT '+name)
  lines=blob.split(b'\n')
  if lines[-1]==b'':lines.pop()
  assert len(lines)==source['physicalLines'],(name,len(lines),source['physicalLines'])
  stats=collections.Counter()
  syntaxes=collections.Counter()
  issues=collections.Counter()
  problems=[]
  start=time.monotonic()
  for i,rawbytes in enumerate(lines[:maxlines]):
   stats['physical_lines']+=1
   if rawbytes.endswith(b'\r'):
    rawbytes=rawbytes[:-1];stats['crlf_separator']+=1
   try:raw=rawbytes.decode('utf8','strict')
   except UnicodeDecodeError:
    stats['invalid_utf8']+=1
    continue
   if not raw.strip():
    stats['blank_lines']+=1
    continue
   try:
    event=parse_security_multipass(raw)
    assert_source_accounting(event)
   except Exception as error:
    stats['parse_or_accounting_exceptions']+=1
    if len(problems)<40:problems.append({'line':i+1,'code':'ENGINE_EXCEPTION','errorType':type(error).__name__,'sourceHash':hashlib.sha256(rawbytes).hexdigest()})
    continue
   stats['processed_events']+=1
   stats['status_'+event.status]+=1
   stats['byte_accounted_ok']+=1
   syntaxes[event.syntax]+=1
   issues.update(event.issues)
   if is_generic(event.syntax):stats['generic_or_unknown_syntax']+=1
   # A documented envelope can be source-complete while its free-text
   # message still has no independently validated semantic field roles.
   if (event.status!='SOURCE_PARSED' or is_generic(event.syntax)
           or event.syntax in DOCUMENTED_ENVELOPE_OPAQUE_MESSAGE):
    stats['needs_semantic_or_grammar_review']+=1
    if len(problems)<40:
     problems.append({'line':i+1,'code':event.issues[0] if event.issues else 'GENERIC_STRUCTURAL_ONLY',
      'syntax':event.syntax,'status':event.status,'sourceHash':hashlib.sha256(rawbytes).hexdigest(),
      'bytes':len(rawbytes),'spanCount':len(event.value_spans),'residualBytes':event.residual_bytes})
   stats['source_occurrence_spans']+=len(event.value_spans)
   stats['raw_source_bytes']+=len(rawbytes)
   stats['unparsed_residual_bytes']+=event.residual_bytes
  elapsed=round(time.monotonic()-start,3)
  record={'dataset':name,'sourceSha256':source['sha256'],'url':source['url'],
   'fileLines':len(lines),'elapsedSec':elapsed,'counts':dict(sorted(stats.items())),
   'syntaxTop':syntaxes.most_common(14),'issueTop':issues.most_common(14),
   'selectedCases':problems[:25],
   'measuredAccuracy':'UNSCORABLE_NO_INDEPENDENT_PER_FIELD_GOLDENS'}
  report['datasets'].append(record);total.update(stats)
  report['totals']=dict(sorted(total.items()))
  OUTPUT.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n',encoding='utf8')
  print('BENCHMARK_DATASET',json.dumps({'name':name,'seconds':elapsed,'counts':{k:stats[k] for k in
   ['physical_lines','processed_events','status_SOURCE_PARSED','status_PARTIAL','status_RAW_ONLY','status_STRUCTURED_EMPTY','generic_or_unknown_syntax','needs_semantic_or_grammar_review','parse_or_accounting_exceptions']}}),flush=True)
 print('BENCHMARK_COMPLETE',json.dumps({'totals':report['totals'],'output':str(OUTPUT)}),flush=True)

if __name__=='__main__':main()
