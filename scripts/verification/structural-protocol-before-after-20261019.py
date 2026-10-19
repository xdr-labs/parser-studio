#!/usr/bin/env python3
"""Compare one immutable authored protocol corpus on deployed HEAD vs isolated candidate.

Raw fixtures never leave the process. Only metadata/status/spans are persisted.
Unqualified formats remain review-only; expected event counts are not vendor F1.
"""
import hashlib,json,pathlib,subprocess,sys
BASE=pathlib.Path('/home/aella/parser-studio-secure-domain-20261019')
NEW=pathlib.Path(__file__).resolve().parents[2]
D=NEW/'docs/verification'
sys.path.insert(0,str(NEW/'tests'))
from test_declared_schema_stream_20261019 import W3C,ZEEK

J='{"event_type":"threat","src_ip":"192.0.2.5","user":"김민수"}'
CEF='CEF:0|Acme|IDS|1|42|Alert|5|src=192.0.2.1 dst=198.51.100.3 act=deny'
LEEF='LEEF:2.0|Example|NSS|1.0|alert|\tusrName=alice\tsrc=192.0.2.1\taction=deny'
SYS='<134>1 2026-10-19T09:15:22.123Z host01 app 12 id [meta@12345 action="deny"] action=deny src=192.0.2.10'
K='action=allow action=deny src=192.0.2.3 user="김민수"'
# Private/original manufacturer logs are never encoded in this corpus.
CASES={
 'w3c_declared_two_rows':(W3C,2),
 'zeek_declared_two_rows':(ZEEK,2),
 'w3c_bad_row':('#Fields: date cs-method\n2026-10-19 GET EXTRA\n',None),
 'w3c_bom':('\ufeff'+W3C,2),
 'zeek_malformed':('#fields\tts\tuid\n#types\ttime\tstring\n1\tA\tEXTRA\n',None),
 'json_single_nested_utf8':(J,1),
 'json_ndjson':(J+'\n'+J.replace('threat','asset'),2),
 'json_array':('['+J+','+J+']',1),
 'json_prefix_syslog':('<134>Oct 19 08:22:00 host '+J,1),
 'rfc5424_sd_kv':(SYS,1),
 'rfc3164_cef':('<134>Oct 19 08:22:00 host '+CEF,1),
 'cef_extension':(CEF,1),
 'leef_implicit_tab':(LEEF,1),
 'duplicate_kv':(K,1),
 'utf8_bom_kv':('\ufeff'+K,1),
 'multiline_quoted_csv':('id,action,msg\n1,deny,"line one\nline two"\n2,allow,normal',None),
 'bad_csv_quote':('id,action,msg\n1,deny,"truncated\n',None),
 'invalid_pri':('<999>Oct 19 08:22:00 host '+CEF,1),
 'mixed_json_kv_cef':(J+'\n'+K+'\n'+CEF,3),
 'rfc6587_octet':(str(len(SYS.encode()))+' '+SYS+str(len(SYS.encode()))+' '+SYS,None),
 'rfc6587_nul':(SYS+'\0'+SYS+'\0',None),
 'rfc7464_json_seq':('\x1e'+J+'\n\x1e'+J+'\n',None),
 'gelf_tcp':('{"version":"1.1","host":"h","short_message":"deny"}\0',None),
 'journal_export':('MESSAGE=action=deny src=192.0.2.1\nPRIORITY=5\n\nMESSAGE=action=allow src=192.0.2.2\nPRIORITY=6\n',None),
 'linux_audit_group':('type=SYSCALL msg=audit(1760870000.123:12): arch=c000003e syscall=59 success=yes\ntype=PATH msg=audit(1760870000.123:12): name="/tmp/a"\n',None),
 'docker_json_file':('{"log":"'+K.replace('"','\\\"')+'\\n","stream":"stdout","time":"2026-10-19T08:22:00Z"}\n',None),
 'cri_multiline':('2026-10-19T08:20:00Z stdout P hello\n2026-10-19T08:20:01Z stdout F world\n',None),
 'unsupported_windows_xml':('<Event><System><EventID>4625</EventID></System></Event>',1),
}
payload=json.dumps({k:v[0] for k,v in CASES.items()},ensure_ascii=False)
PROGRAM='''import sys,json,hashlib
from multipass_preview_api import preview_batch
cases=json.load(sys.stdin)
out={}
for key,value in cases.items():
 try:
  r=preview_batch(value)
  frames=r['events']
  out[key]={'record_count':r['eventCount'],
       'status':[e['preview']['status'] for e in frames],
       'syntax':[e['preview']['syntax'] for e in frames],
       'issue_codes':[e['preview']['issues'][:3] for e in frames],
       'field_count':[len(e['preview']['spans']) for e in frames],
       'residual_bytes':[sum(x['endByte']-x['startByte'] for x in e['preview']['residuals']) for e in frames],
       'metadata_partitions':sum(x['kind']=='SOURCE_METADATA' for x in r['separators']),
       'byte_accounting':sum(x['endByte']-x['startByte'] for x in r['events'])+sum(x['endByte']-x['startByte'] for x in r['separators'])==r['sourceBytes']}
 except Exception as ex:out[key]={'error':type(ex).__name__+':'+str(ex)[:140]}
print(json.dumps(out,ensure_ascii=True))'''
def run(root):
    cp=subprocess.run(['python3','-c',PROGRAM],input=payload,capture_output=True,text=True,timeout=80,
        env=dict(__import__('os').environ,PYTHONPATH=str(root/'runtime/multipass')))
    if cp.returncode:raise RuntimeError(cp.stderr[-1200:])
    return json.loads(cp.stdout)
before=run(BASE);after=run(NEW)
ledger={}
for key,(raw,expected) in CASES.items():
    old=before[key];new=after[key]
    ledger[key]={'source_sha256':hashlib.sha256(raw.encode()).hexdigest(),'fixture_origin':'AUTHORED_SYNTHETIC',
       'expected_original_data_rows':expected,'before':old,'after':new,
       'record_count_changed':old.get('record_count')!=new.get('record_count'),
       'all_original_source_bytes_accounted':new.get('byte_accounting',False),
       'no_new_false_complete':not(len(new.get('status',[])) and
         sum(s=='SOURCE_PARSED' for s in new.get('status',[])) >
         sum(s=='SOURCE_PARSED' for s in old.get('status',[])) and
         key in {'w3c_bad_row','zeek_malformed','bad_csv_quote','invalid_pri','unsupported_windows_xml'})}
out={'contract':'parserstudio.protocol-before-after.v1',
 'baseline_head':subprocess.check_output(['git','-C',str(BASE),'rev-parse','HEAD'],text=True).strip(),
 'candidate_base_head':subprocess.check_output(['git','-C',str(NEW),'rev-parse','HEAD'],text=True).strip(),
 'case_count':len(CASES),'cases':ledger}
target=D/'20261019-protocol-before-after.json'
target.write_text(json.dumps(out,indent=2,ensure_ascii=True)+'\n')
print(json.dumps({'cases':len(CASES),'accounting_valid':sum(x['all_original_source_bytes_accounted'] for x in ledger.values()),'count_changes':[(k,x['before'].get('record_count'),x['after'].get('record_count')) for k,x in ledger.items() if x['record_count_changed']],'false_complete_alerts':[k for k,x in ledger.items() if not x['no_new_false_complete']],'output':str(target)}))
