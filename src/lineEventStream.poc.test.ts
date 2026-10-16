import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

const mixed=[
  '<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,allow',
  'CEF:1|Vendor|EDR|1.0|42|Threat|8|src=192.0.2.1 dst=198.51.100.1',
  '{"event":"alert","src":"192.0.2.2","dst":"198.51.100.2"}',
  '<134>Aug  6 12:03:36 f5qa ASM:unit_hostname="f5qa",management_ip_address="10.52.34.33",policy_name="/Common/asmpolicy",request_status="passed",ip_client="10.43.24.23",method="HEAD",protocol="HTTPS",src_port="50668",dest_port="443",dest_ip="10.30.4.56",uri="/repository/file.jar"',
  '2006-09-18 22:25:30 OPEN TCP 11.12.72.10 12.252.71.6 3311 445 - - - - - - - - -',
] as const;

describe('heterogeneous newline event stream PoC',()=>{
  it('parses a mixed LF file only when every line is a reviewed single event',()=>{
    const raw=mixed.join('\n')+'\n';
    const parsed=parseSecurityInput(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.kind).toBe('line_event_stream');
    expect(parsed.container).toBe(true);
    expect(parsed.context).toEqual({framing:'lf'});
    expect(parsed.events).toHaveLength(mixed.length);
    expect(parsed.events.map(event=>event.raw)).toEqual(mixed);
    expect(parsed.events[0].fields).toHaveProperty('generic');
    expect(parsed.events[1].fields).toMatchObject({cef_version:'1',src:'192.0.2.1'});
    expect(parsed.events[2].fields).toMatchObject({event:'alert',src:'192.0.2.2'});
    expect(parsed.events[3].fields).toHaveProperty('f5_bigip');
    expect(parsed.events[4].fields).toHaveProperty('windows_firewall');
  });

  it('supports uniform CRLF while preserving per-record content',()=>{
    const raw=mixed.slice(0,3).join('\r\n')+'\r\n';
    const parsed=parseSecurityInput(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.kind).toBe('line_event_stream');
    expect(parsed.context).toEqual({framing:'crlf'});
    expect(parsed.events.map(event=>event.raw)).toEqual(mixed.slice(0,3));
  });

  it('rejects the entire stream when any one line is not structurally reviewed',()=>{
    const raw=[mixed[0],'ordinary free text with no deterministic structure',mixed[1]].join('\n')+'\n';
    const parsed=parseSecurityInput(raw);
    expect(parsed.ok).toBe(false);
    if(!parsed.ok)expect(parsed.error).toContain('Line 2 failed reviewed single-event parsing');
  });

  it('rejects blank event boundaries and mixed line endings',()=>{
    const invalid=[
      mixed[0]+'\n\n'+mixed[1]+'\n',
      mixed[0]+'\r\n'+mixed[1]+'\n',
      mixed[0]+'\r'+mixed[1],
    ];
    expect(invalid.map(raw=>parseSecurityInput(raw).ok)).toEqual([false,false,false]);
  });

  it('does not steal stronger homogeneous container grammars',()=>{
    const ndjson='{"event":"a"}\n{"event":"b"}\n';
    const json=parseSecurityInput(ndjson);
    expect(json.ok).toBe(true);
    if(json.ok)expect(json.kind).toBe('ndjson');

    const syslogA='<134>Oct 16 15:44:21 edge01 app: CEF:1|Vendor|EDR|1|1|A|5|src=192.0.2.1';
    const syslogB='<134>Oct 16 15:44:22 edge02 app: CEF:1|Vendor|EDR|1|2|B|5|src=192.0.2.2';
    const syslog=parseSecurityInput(syslogA+'\n'+syslogB+'\n');
    expect(syslog.ok).toBe(true);
    if(syslog.ok)expect(syslog.kind).toBe('rfc6587_syslog');
  });
});
