#!/usr/bin/env python3
"""Offline real-API-function source verification on pinned Loghub public input.

No external requests, no source text serialized to reports. This exercises
preview_batch(), the exact handler shared by the local/public Multi-Pass API.
"""
from __future__ import annotations
from collections import Counter
import hashlib,json,os,re,sys
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'runtime/multipass'))
from multipass_preview_api import preview_batch

STATE=Path(os.environ.get('PARSER_STUDIO_IRREGULAR_ROOT',
 '/home/aella/.local/state/parserstudio-irregular-20261024'))
CHUNK=100
CORPUS=STATE/'corpus'
PROXY=re.compile(
 r'^\[(?P<month_day>\d{2}\.\d{2}) (?P<clock>\d{2}:\d{2}:\d{2})\] '
 r'(?P<application>[A-Za-z0-9_.+\-]+(?: \*64)?) - '
 r'(?P<target_host>[A-Za-z0-9_][A-Za-z0-9_.-]{0,254}):(?P<target_port>\d{1,5}) '
 r'(?P<message>[^\r\n]+)$'
)
LOGCAT=re.compile(
 r'^(?P<month_day>\d{2}-\d{2}) (?P<clock>\d{2}:\d{2}:\d{2}\.\d{3})\s+'
 r'(?P<pid>\d{1,7})\s+(?P<tid>\d{1,7}) (?P<priority>[VDIWEFS]) '
 r'(?P<tag>[A-Za-z0-9_.$/\-]{1,96}): (?P<message>[^\r\n]+)$'
)
def sha(data:bytes)->str:return hashlib.sha256(data).hexdigest()

def run():
 sources=json.loads((CORPUS/'UPSTREAM.json').read_text())
 report={'contract':'parserstudio.loghub.batch-preview-audit.v0.1',
         'upstream':sources['commit'],'scope':'source fields and UTF-8 spans, not semantic full parser',
         'authenticated_device_captures':0,'external_ai_calls':0,'datasets':[]}
 for name,pattern in [('Proxifier',PROXY),('Android',LOGCAT)]:
  src=next(item for item in sources['datasets'] if item['name']==name)
  data=(CORPUS/(name+'_2k.log')).read_bytes()
  if sha(data)!=src['sha256']:raise RuntimeError('UPSTREAM_DRIFT')
  lines=[item[:-1] if item.endswith(b'\r') else item
         for item in data.split(b'\n') if item]
  if len(lines)!=2000:raise AssertionError('WRONG_2K_RECORD_COUNT')
  counter=Counter();bad=[]
  for off in range(0,len(lines),CHUNK):
   batch=lines[off:off+CHUNK]
   text='\n'.join(x.decode('utf8','strict') for x in batch)
   response=preview_batch(text)
   if response['sourceSha256']!=sha(text.encode('utf8')) or response['eventCount']!=len(batch):
    raise AssertionError('BATCH_SOURCE_OR_FRAMING_MISMATCH')
   for index,(original,frame) in enumerate(zip(batch,response['events'])):
    number=off+index+1
    preview=frame['preview']
    piece=text.encode('utf8')[frame['startByte']:frame['endByte']]
    if piece!=original or preview['sourceSha256']!=sha(original):
     raise AssertionError('SOURCE_VALUE_LOSS')
    if preview['nativeVerified'] or preview['targetVerified']:
     raise AssertionError('FALSE_NATIVE_OR_TARGET_CLAIM')
    counter['frame_and_sha_ok']+=1
    counter['status_'+preview['status']]+=1
    assert preview['sourceBytes']==len(original)
    if preview['syntax'] in ('BRACKETED_MONTH_DAY_APPLICATION_TARGET',
                              'ANDROID_LOGCAT_THREADTIME'):
     counter['documented_header_selected']+=1
     expected=pattern.fullmatch(original.decode('utf8'))
     if not expected:raise AssertionError('UNPROVEN_PATTERN_MATCH')
     fields=preview['fields']
     for key,value in expected.groupdict().items():
      expected_value=int(value) if key in ('target_port','pid','tid') else value
      if fields.get(key)!=expected_value:
       bad.append({'line':number,'field':key,'reason':'VALUE_MISMATCH','sourceHash':sha(original)})
       continue
      span=next((s for s in preview['spans'] if s['path']==key),None)
      if span is None:
       bad.append({'line':number,'field':key,'reason':'MISSING_SPAN','sourceHash':sha(original)})
       continue
      lexical=original[span['startByte']:span['endByte']].decode('utf8')
      if lexical!=value:
       bad.append({'line':number,'field':key,'reason':'LEXEME_MISMATCH','sourceHash':sha(original)})
       continue
      counter['independently_checked_field_occurrence']+=1
     if preview['status']!='PARTIAL' or 'FREE_TEXT_FIELD_ROLES_NEED_REVIEW' not in preview['issues']:
      bad.append({'line':number,'reason':'OVERSTATED_SOURCE_COMPLETENESS','sourceHash':sha(original)})
    elif name=='Android':
     counter['prior_parser_claims_preserved_without_new_header']+=1
    else:
     bad.append({'line':number,'reason':'QUALIFIED_HEADER_MISSED','sourceHash':sha(original)})
  outcome={'source':name,'fileSha256':src['sha256'],'events':len(lines),
           'counts':dict(counter),'mismatches':len(bad),'selectedErrors':bad[:20],
           'valid_statement':'Documented header extraction only; free-text messages need review'}
  report['datasets'].append(outcome)
  (STATE/'api-qualified.json').write_text(json.dumps(report,indent=2)+'\n')
  print('BATCH_API_'+name.upper(),json.dumps({k:outcome[k] for k in ('events','counts','mismatches')}),flush=True)
 print('BATCH_API_DONE',sum(x['events'] for x in report['datasets']))
 if any(x['mismatches'] for x in report['datasets']):raise SystemExit(1)

if __name__=='__main__':run()
