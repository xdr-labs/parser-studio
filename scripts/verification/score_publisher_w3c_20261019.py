#!/usr/bin/env python3
"""Private-source, public-digest-only W3C publisher oracle scoring.

Neither original publisher source bytes nor values are exported. This is a
published documentation example (not real device log wire provenance).
"""
from __future__ import annotations
from collections import Counter
import hashlib,json,pathlib,sys
ROOT=pathlib.Path(__file__).resolve().parents[2]
sys.path.insert(0,str(ROOT/'runtime/multipass'))
from multipass_preview_api import preview_batch

REFERENCE=pathlib.Path('/home/aella/parser-studio-std9-publisher-w3c-oracle-poc-20261018/scripts/poc/standard9PublisherW3cExample.pinned.json')
PRIVATE=pathlib.Path('/home/aella/.local/state/parserstudio-std9-publisher-w3c-20261018/w3c-efl-publisher-example.raw')
OUT=ROOT/'docs/verification/20261019-publisher-w3c-digest-only-score.json'
if not PRIVATE.is_file() or not REFERENCE.is_file():
    print('PUBLISHER_W3C_UNSCORABLE_MISSING_SOURCE_OR_ORACLE')
    sys.exit(2)
source=PRIVATE.read_bytes()
oracle_bytes=REFERENCE.read_bytes()
if hashlib.sha256(oracle_bytes).hexdigest()!='76b37af28dee2538121801320269b6152ff8199a169f458021d6d5762a5d64e5':
    raise ValueError('INDEPENDENT_ORACLE_PIN_MISMATCH')
gold=json.loads(oracle_bytes)
if hashlib.sha256(source).hexdigest()!=gold['canonicalSourceSha256'] or len(source)!=gold['canonicalSourceBytes']:
    raise ValueError('INDEPENDENT_SOURCE_DIGEST_MISMATCH')
raw=source.decode('utf8','strict')
preview=preview_batch(raw)
checks=[]
for row_index,claims in enumerate(gold['publisherExpectedFields']):
    frame=preview['events'][row_index] if row_index<len(preview['events']) else None
    spans={x['path']:x for x in (frame['preview']['spans'] if frame else [])}
    for claim in claims:
        key=claim['name']
        span=spans.get(key)
        if span is None or not frame:
            checks.append(False);continue
        start=span['startByte']+frame['startByte'];end=span['endByte']+frame['startByte']
        value=frame['preview']['fields'].get(key)
        claim_matches=(start==claim['startByte'] and end==claim['endByte']
           and hashlib.sha256(source[start:end]).hexdigest()==claim['lexemeSha256']
           and isinstance(value,str)
           and hashlib.sha256(value.encode('utf8')).hexdigest()==claim['decodedSha256'])
        checks.append(bool(claim_matches))
result={
  'contract':'parserstudio.publisher-w3c-private-original-score.v1',
  'source_class':'PUBLISHER_AUTHORED_STANDARDS_EXAMPLE_NOT_PRODUCTION_WIRE',
  'oracle_pin_verified':True,'source_sha256_verified':True,
  'event_rows_expected':gold['rows'],'event_rows_observed':preview['eventCount'],
  'field_claims':len(checks),'exact_name_value_utf8_span':sum(checks),
  'native_verified':False,'stellar_target_verified':False,
  'source_bytes':len(source),'source_reprinted':False,
  'full_vendor_f1':'UNSCORABLE','complete_original_stream_compilation':'NOT_VERIFIED',
  'source_status_counts':dict(Counter(x['preview']['status'] for x in preview['events'])),
  'all_source_bytes_accounted':sum(e['endByte']-e['startByte'] for e in preview['events'])+sum(s['endByte']-s['startByte'] for s in preview['separators'])==len(source)
}
OUT.write_text(json.dumps(result,indent=2,ensure_ascii=True)+'\n')
print(json.dumps(result,ensure_ascii=True))
if result['event_rows_expected']!=result['event_rows_observed'] or not all(checks) or not result['all_source_bytes_accounted']:
    sys.exit(1)
