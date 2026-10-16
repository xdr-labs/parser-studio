import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

const syslogA='<134>Oct 16 15:44:21 edge01 app: CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.1 dst=198.51.100.1';
const syslogB='<134>Oct 16 15:44:22 edge02 app: {"event":"alert","src":"192.0.2.2","dst":"198.51.100.2"}';
const frame=(message:string)=>new TextEncoder().encode(message).byteLength+' '+message;

describe('end-to-end security input pipeline PoC',()=>{
  it('keeps reviewed single-event families as the fallback after container detection',()=>{
    const samples=[
      '<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,allow',
      'CEF:1|Vendor|EDR|1.0|42|Threat|8|src=192.0.2.1 dst=198.51.100.1',
      'LEEF:2.0|Vendor|NDR|1.0|dns|x5E|src=192.0.2.1^dst=198.51.100.1^act=allow',
      '{"event":"alert","src":"192.0.2.1","dst":"198.51.100.1"}',
    ];
    const results=samples.map(raw=>parseSecurityInput(raw));
    expect(results.every(result=>result.ok)).toBe(true);
    for(const parsed of results){
      if(!parsed.ok)continue;
      expect(parsed.kind).toBe('single_event');
      expect(parsed.container).toBe(false);
      expect(parsed.events).toHaveLength(1);
    }
    const pan=results[0];
    if(pan.ok)expect((pan.events[0].fields.generic as {columns?:Record<string,string>}).columns?.column_3).toBe('TRAFFIC');
    const cef=results[1];
    if(cef.ok)expect(cef.events[0].fields).toMatchObject({cef_version:'1',src:'192.0.2.1'});
    const leef=results[2];
    if(leef.ok)expect(leef.events[0].fields).toMatchObject({leef_version:'2.0',src:'192.0.2.1'});
    const json=results[3];
    if(json.ok)expect(json.events[0].fields).toMatchObject({event:'alert',src:'192.0.2.1'});
  });

  it('breaks RFC6587 and structurally parses every resulting Syslog record',()=>{
    const parsed=parseSecurityInput(frame(syslogA)+frame(syslogB));
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.kind).toBe('rfc6587_syslog');
    expect(parsed.events).toHaveLength(2);
    expect(parsed.events[0].fields.syslog).toMatchObject({hostname:'edge01'});
    expect(parsed.events[1].fields.body).toMatchObject({event:'alert',src:'192.0.2.2'});
  });

  it('promotes schema/container records without inventing semantic field names',()=>{
    const batch=JSON.stringify({Records:[{eventName:'ConsoleLogin',sourceIPAddress:'192.0.2.1'},{eventName:'StartInstances',sourceIPAddress:'192.0.2.2'}]});
    const json=parseSecurityInput(batch);
    expect(json.ok).toBe(true);
    if(json.ok){
      expect(json.kind).toBe('json_batch');
      expect(json.events[0].fields.body).toMatchObject({eventName:'ConsoleLogin'});
    }

    const zeek=[
      '#separator \\x09','#path\tconn','#fields\tts\tuid\tid.orig_h','#types\ttime\tstring\taddr',
      '1764958704.1\tABCDEF12\t192.0.2.10','#close\t2026-10-16-15-45-00',
    ].join('\n')+'\n';
    const z=parseSecurityInput(zeek);
    expect(z.ok).toBe(true);
    if(z.ok)expect(z.events[0].fields.zeek).toMatchObject({'id.orig_h':'192.0.2.10'});

    const csv='timestamp,src_ip,action\n2026-10-16T15:44:21Z,192.0.2.1,deny\n';
    const c=parseSecurityInput(csv);
    expect(c.ok).toBe(true);
    if(c.ok)expect(c.events[0].fields.csv).toMatchObject({src_ip:'192.0.2.1',action:'deny'});
  });

  it('preserves journal metadata and reuses single-event family dispatch on MESSAGE',()=>{
    const raw=[
      '__REALTIME_TIMESTAMP=1792152261123456',
      '_SYSTEMD_UNIT=auditd.service',
      'SYSLOG_IDENTIFIER=auditd',
      'MESSAGE=type=SYSCALL msg=audit(1792152261.123:420): syscall=59 success=yes pid=200',
      '',
      '__REALTIME_TIMESTAMP=1792152262123456',
      '_SYSTEMD_UNIT=edr.service',
      'SYSLOG_IDENTIFIER=edr',
      'MESSAGE=CEF:1|Vendor|EDR|1.0|42|Threat|8|src=192.0.2.10 dst=198.51.100.20',
      '',
      '',
    ].join('\n');
    const parsed=parseSecurityInput(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.kind).toBe('journal_export_text');
    expect(parsed.events).toHaveLength(2);
    expect(parsed.events[0].fields).toMatchObject({
      journal:{SYSLOG_IDENTIFIER:'auditd'},
      message_structured:{linux_audit:{event_serial:'420'}},
    });
    expect(parsed.events[1].fields).toMatchObject({
      journal:{SYSLOG_IDENTIFIER:'edr'},
      message_structured:{cef_version:'1',src:'192.0.2.10',dst:'198.51.100.20'},
    });
  });

  it('returns correlated Linux Audit events rather than leaking individual records as unrelated events',()=>{
    const raw=
      'type=SYSCALL msg=audit(1792152261.123:420): syscall=59 success=yes pid=200\n'+
      'type=CWD msg=audit(1792152261.123:420): cwd="/tmp"\n'+
      'type=AVC msg=audit(1792152262.456:421): avc: denied { read } for pid=300 comm="httpd" tclass=file\n';
    const parsed=parseSecurityInput(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.kind).toBe('linux_audit');
    expect(parsed.events).toHaveLength(2);
    const first=parsed.events[0].fields.linux_audit_event as {event_id:string;record_types:string[]};
    expect(first.event_id).toBe('1792152261.123:420');
    expect(first.record_types).toEqual(['SYSCALL','CWD']);
  });

  it('does not downgrade a claimed malformed container into a single-event success',()=>{
    const invalid=[
      '#Version: 1.0\n#Fields: date time host\n2026-10-16 15:44:21\n',
      '\u001e{"event":"ok"}',
      JSON.stringify({version:'1.0',host:'x',short_message:'bad'})+'\0',
      '[{"event":"ok"},42]',
    ];
    const results=invalid.map(raw=>parseSecurityInput(raw));
    expect(results.every(result=>!result.ok)).toBe(true);
    console.log('SECURITY_PIPELINE_INVALID '+JSON.stringify({total:results.length,rejected:results.filter(result=>!result.ok).length}));
  });
});
