#!/usr/bin/env python3
"""Correct source-field reference scope: raw pass-through is NOT a source field.

v1 independently frozen reference is immutable; v2 is a *post-baseline*
qualification correction, not a fresh/blind new holdout. This never reads
candidate outputs and does not change source literals.
"""
import hashlib,json,pathlib,os,collections
root=pathlib.Path.home()/'.local/state/parserstudio-new-independent-security-20261017'
first=root/'crowdsec-independent-raw-stage-expected.v1.json'
assert hashlib.sha256(first.read_bytes()).hexdigest()=='e147d816e5ff88f46476d3716e6fe61b10e48852eaa99b025cc0e83ec0d07dee'
data=json.loads(first.read_text('utf8'))
excluded=collections.Counter()
for rec in data:
 full=rec['raw'].encode('utf8')
 qualified=[]
 for f in rec['fields']:
  if f['canonical_field']=='message' and f['startByte']==0 and f['endByte']==len(full):
   excluded['AUTHOR_WRAPPER_RAW_PASS_THROUGH_NOT_SOURCE_FIELD']+=1
   continue
  qualified.append(f)
 rec['fields']=qualified
 rec['status']='PARTIAL_SCORABLE' if qualified else 'UNSCORABLE_SOURCE_FIELD_CONTRACT'
out=root/'crowdsec-source-only-corrected-expected.v2.json'
out.write_text(json.dumps(data,ensure_ascii=False,separators=(',',':')))
os.chmod(out,0o600)
print('QUALIFICATION_SCOPE_CORRECTION_NOT_NEW_HOLDOUT',json.dumps({
 'v1_original_sha':'e147d816e5ff88f46476d3716e6fe61b10e48852eaa99b025cc0e83ec0d07dee',
 'corrected_v2_sha':hashlib.sha256(out.read_bytes()).hexdigest(),
 'total_originals':len(data),'scorable_originals':sum(r['status']=='PARTIAL_SCORABLE' for r in data),
 'asserted_partial_triples':sum(len(r['fields']) for r in data),
 'excluded':excluded,'stage_only':True,'raw_data_printed':False}))
