#!/usr/bin/env python3
"""Compare identical authored source containers across pinned baselines without raw-value reporting."""
import hashlib
import json
import subprocess
import sys
from pathlib import Path

HERE=Path(__file__).resolve().parents[2]
BASE=Path('/home/aella/parser-studio-poc-coverage-audit-20261019')
EXPECTED_BASE='440183d5856cde630da7d647957ed4a64a91e0e0'
assert subprocess.check_output(['git','-C',str(BASE),'rev-parse','HEAD'],text=True).strip()==EXPECTED_BASE
assert not subprocess.run(['git','-C',str(BASE),'diff','--quiet','--','runtime/multipass']).returncode
A1='type=SYSCALL msg=audit(1760870000.123:12): arch=c000003e syscall=59 success=yes'
A2='type=PATH msg=audit(1760870000.123:12): name="/tmp/한글"'
B1='type=USER_LOGIN msg=audit(1760870000.125:13): res=failed acct="김민수"'
P='2026-10-19T08:20:00Z stdout P 안녕'
F='2026-10-19T08:20:01Z stdout F 하세요'
S='2026-10-19T08:20:02Z stderr F denied'
D1=json.dumps({'log':'user=김민수\n','stream':'stdout','time':'2026-10-19T08:20:00Z'},ensure_ascii=False)
D2=json.dumps({'log':'failed\n','stream':'stderr','time':'2026-10-19T08:20:01Z'},ensure_ascii=False)
CASES={
 'audit_same_serial':A1+'\n'+A2+'\n',
 'audit_separate_serials':A1+'\n'+A2+'\n'+B1+'\n',
 'audit_interleaved':A1+'\n'+B1+'\n'+A2+'\n',
 'cri_partial_final':P+'\n'+F+'\n',
 'cri_partial_final_stderr':P+'\n'+F+'\n'+S+'\n',
 'cri_truncated':P+'\n',
 'cri_interleaved':P+'\n'+S+'\n'+F+'\n',
 'docker_two':D1+'\n'+D2+'\n',
 'docker_missing_time':'{"log":"denied","stream":"stdout"}\n',
 'plain_json_control':'{"action":"deny","src_ip":"192.0.2.1"}\n',
 'plain_kv_control':'action=deny src_ip=192.0.2.1\n'
}
PROGRAM=r"""
import sys,json,hashlib
from multipass_preview_api import preview_batch
sources=json.load(sys.stdin)
results={}
for key,raw in sources.items():
    item={'sha256':hashlib.sha256(raw.encode()).hexdigest(),'sourceBytes':len(raw.encode())}
    try:
        response=preview_batch(raw)
        frames=response['events']
        slices=[(e['startByte'],e['endByte']) for e in frames]
        slices.extend((s['startByte'],s['endByte']) for s in response['separators'])
        cursor=0
        for start,end in sorted(slices):
            if start!=cursor or end<=start:raise AssertionError('SOURCE_PARTITION_INVALID')
            cursor=end
        if cursor!=len(raw.encode()):raise AssertionError('SOURCE_PARTITION_INCOMPLETE')
        item.update(eventCount=len(frames),status=[x['preview']['status'] for x in frames],
                syntax=[x['preview']['syntax'] for x in frames],
                issues=[x['preview']['issues'] for x in frames],
                accounted=True,
                nativeVerified=any(x['preview']['nativeVerified'] for x in frames),
                targetVerified=any(x['preview']['targetVerified'] for x in frames))
    except Exception as exc:
        item.update(error=type(exc).__name__+':'+str(exc)[:96],accounted=False)
    results[key]=item
json.dump(results,sys.stdout,ensure_ascii=False)
"""

def evaluate(path):
    proc=subprocess.run([sys.executable,'-c',PROGRAM],cwd=path/'runtime/multipass',
         input=json.dumps(CASES,ensure_ascii=False),encoding='utf8',capture_output=True,timeout=15,check=True)
    return json.loads(proc.stdout)

old=evaluate(BASE)
new=evaluate(HERE)
rows=[]
for key,raw in CASES.items():
    first=old[key]
    last=new[key]
    assert first['sha256']==last['sha256']==hashlib.sha256(raw.encode()).hexdigest()
    assert last['accounted'],key
    assert not last.get('nativeVerified') and not last.get('targetVerified')
    rows.append({
      'id':key,'sha256':first['sha256'],'bytes':len(raw.encode()),
      'before':{k:v for k,v in first.items() if k not in ('sha256','sourceBytes')},
      'after':{k:v for k,v in last.items() if k not in ('sha256','sourceBytes')},
    })
report={
 'contract':'parser-studio.source-container-before-after.v1',
 'source_kind':'authored synthetic security log structures (NOT device wire)',
 'source_count':len(rows),
 'baseline_sha':EXPECTED_BASE,
 'candidate_base_sha':subprocess.check_output(['git','-C',str(HERE),'rev-parse','HEAD'],text=True).strip(),
 'candidate_uncommitted_implementation':True,
 'source_integrity':'same exact SHA256 in old and new, all candidate bytes accounted',
 'normalization_semantics':'not independently certified',
 'native_fluentd':'NOT_VERIFIED','stellar_target':'NOT_VERIFIED',
 'rows':rows,
}
dest=HERE/'docs/verification/20261019-audit-cri-docker-before-after.json'
dest.write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
print('SAME_SOURCE_COMPARE_PASS',len(rows))
for row in rows:
    print(row['id'],'old',row['before'].get('eventCount'),row['before'].get('status'),
          'new',row['after'].get('eventCount'),row['after'].get('status'))
print('EVIDENCE',dest)
