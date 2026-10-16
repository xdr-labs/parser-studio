import {describe,expect,it} from 'vitest';
import {breakSecurityInput} from './securityEventBreaker';

const syslogA='<134>Oct 16 15:44:21 edge01 app: CEF:1|Vendor|EDR|1|42|Threat|8|src=192.0.2.1';
const syslogB='<134>Oct 16 15:44:22 edge02 app: {"event":"alert","src":"192.0.2.2"}';
const frame=(message:string)=>new TextEncoder().encode(message).byteLength+' '+message;

const containers=[
  {kind:'rfc6587_syslog',count:2,raw:frame(syslogA)+frame(syslogB)},
  {kind:'json_batch',count:2,raw:JSON.stringify({Records:[{event:'a'},{event:'b'}]})},
  {kind:'json_seq',count:2,raw:'\u001e'+JSON.stringify({event:'a'})+'\n\u001e'+JSON.stringify({event:'b'})+'\n'},
  {kind:'gelf_tcp',count:2,raw:JSON.stringify({version:'1.1',host:'edr01',short_message:'alert',level:4})+'\0'+JSON.stringify({version:'1.1',host:'fw01',short_message:'deny',level:5})+'\0'},
  {kind:'ndjson',count:2,raw:JSON.stringify({event:'a'})+'\n'+JSON.stringify({event:'b'})+'\n'},
  {kind:'journal_export_text',count:2,raw:'__REALTIME_TIMESTAMP=1\nMESSAGE=one\n\n__REALTIME_TIMESTAMP=2\nMESSAGE=two\n\n'},
  {kind:'w3c_log',count:2,raw:'#Version: 1.0\n#Fields: date time c-ip cs-method sc-status\n2026-10-16 15:44:21 192.0.2.1 GET 403\n2026-10-16 15:44:22 192.0.2.2 POST 401\n'},
  {kind:'zeek_tsv',count:2,raw:[
    '#separator \\x09','#path\tconn','#fields\tts\tuid','#types\ttime\tstring',
    '1764958704.1\tABCDEF12','1764958705.1\tABCDEF13','#close\t2026-10-16-15-45-00',
  ].join('\n')+'\n'},
  {kind:'linux_audit',count:2,raw:
    'type=SYSCALL msg=audit(1792152261.123:420): syscall=59 success=yes\n'+
    'type=CWD msg=audit(1792152261.123:420): cwd="/tmp"\n'+
    'type=AVC msg=audit(1792152262.456:421): avc: denied { read } for pid=300 comm="httpd" tclass=file\n'},
  {kind:'rfc4180_csv',count:2,raw:'timestamp,src_ip,action\n2026-10-16T15:44:21Z,192.0.2.1,deny\n2026-10-16T15:44:22Z,192.0.2.2,allow\n'},
] as const;

describe('top-level bounded security event breaker PoC',()=>{
  it('dispatches distinct multi-event containers without caller-provided format hints',()=>{
    for(const sample of containers){
      const parsed=breakSecurityInput(sample.raw);
      expect(parsed.ok,sample.kind).toBe(true);
      if(!parsed.ok)continue;
      expect(parsed.kind,sample.kind).toBe(sample.kind);
      expect(parsed.count,sample.kind).toBe(sample.count);
    }
    console.log('SECURITY_EVENT_BREAKER '+JSON.stringify({kinds:containers.map(item=>item.kind),count:containers.length}));
  });

  it('keeps single-event parsing outside the multi-event breaker',()=>{
    const singles=[
      syslogA,
      JSON.stringify({event:'single'}),
      'type=SYSCALL msg=audit(1792152261.123:420): syscall=59 success=yes',
      'timestamp,src_ip,action',
      '[Mon Aug 31 16:27:04 2015] [error] [client 10.17.42.3] Premature end of script headers: example.com',
    ];
    expect(singles.filter(raw=>breakSecurityInput(raw).ok)).toEqual([]);
    const bracketed=breakSecurityInput(singles[4]!);
    expect(bracketed.ok).toBe(false);
    if(!bracketed.ok)expect(bracketed.claimed).toBe(false);
  });

  it('fails closed when a strong container signature is present but malformed',()=>{
    const invalid=[
      '10 '+syslogA,
      '#separator \\x09\n#fields\tts\tuid\n#types\ttime\n1\tABC\n',
      'type=SYSCALL msg=audit(bad:420): syscall=59\n',
      '__REALTIME_TIMESTAMP=1\nMESSAGE=one\n\nBAD BINARY MARKER\n\n',
      JSON.stringify({Records:[{event:'ok'},42]}),
    ];
    const accepted=invalid.filter(raw=>breakSecurityInput(raw).ok);
    console.log('SECURITY_EVENT_BREAKER_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
