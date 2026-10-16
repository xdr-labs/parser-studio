import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

const hardRejects=[
  ['pri-too-high','<192>Oct 16 15:44:21 EDGE01 app: hello',false],
  ['invalid-rfc3164-day','<14>Oct 32 15:44:21 EDGE01 app: hello',false],
  ['invalid-rfc3164-clock','<14>Oct 16 25:44:21 EDGE01 app: hello',false],
  ['invalid-rfc3339-date','<14>2026-02-30T15:44:21Z EDGE01 app: hello',false],
  ['invalid-space-zone','<14>2026-10-16 15:44:21 +2500 EDGE01 app: hello',false],
  ['invalid-rfc5424-version','<34>0 2026-10-16T15:44:21Z EDGE01 app 123 ID47 - hello',false],
  ['panos-unclosed-csv-quote','<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,"broken',true],
  ['asa-invalid-port','<166>2026-10-16T15:44:21Z ASA01 %ASA-6-302013: Built outbound TCP connection 1 for outside:203.0.113.1/70000 (203.0.113.1/443) to inside:10.0.0.1/443 (198.51.100.1/443)',true],
  ['asa-invalid-context','<166>Oct 16 15:44:21 ASA01 %ASA-4-106023: Deny udp src v9:outside:192.0.2.10/54864 dst v2:inside:198.51.100.3/53 by access-group "outside_acl" [0x0, 0x0]',true],
  ['asa-double-message-id','<166>Oct 16 15:44:21 ASA01 %ASA-6-302013: %ASA-6-302013: Built outbound TCP connection 1 for outside:203.0.113.1/443 (203.0.113.1/443) to inside:10.0.0.1/443 (198.51.100.1/443)',true],
  ['juniper-no-flow-tuple','<14>2026-10-16T15:44:21Z SRX01 RT_FLOW: RT_FLOW_SESSION_CREATE: session created without a network tuple',true],
  ['checkpoint-prototype-key','<134>Oct 16 15:44:21 CP01 CheckPoint[8363]: [action:"Accept"; constructor:"bad"; src:"192.0.2.1"]',true],
  ['checkpoint-unclosed-quote','<134>2026-10-16T15:44:21Z CP01 CheckPoint[8363]: [action:"Accept; src:"192.0.2.1"]',true],
  ['checkpoint-single-field','<134>Oct 16 15:44:21 CP01 CheckPoint[8363]: [action:"Accept"]',true],
  ['watchguard-bad-msg-id','<139>Oct 16 15:44:21 WG01 FVE6035FD3AE3 (2026-10-16T15:44:21) firewall: msg_id="bad-id" Allow 1-Trusted 0-External tcp 10.0.0.1 198.51.100.1 51514 443',true],
  ['watchguard-invalid-device-time','<139>Oct 16 15:44:21 WG01 FVE6035FD3AE3 (not-a-date) firewall: msg_id="1BFF-000F" Allow 1-Trusted 0-External tcp 10.0.0.1 198.51.100.1 51514 443',true],
  ['json-array-not-object','<134>Oct 16 15:44:21 IDS01 [1,2,3]',true],
  ['json-prototype-key','<134>Oct 16 15:44:21 IDS01 {"constructor":"bad","src":"10.0.0.1"}',true],
  ['json-truncated','<134>Oct 16 15:44:21 IDS01 {"src":"10.0.0.1"',true],
  ['cef-invalid-version','<134>Oct 16 15:44:21 EDR01 CEF:1|Vendor|Product|1|100|Name|5|src=10.0.0.1',true],
  ['cef-truncated-header','<134>Oct 16 15:44:21 EDR01 CEF:0|Vendor|Product|1|100',true],
  ['leef-missing-delimiter','<134>Oct 16 15:44:21 NDR01 LEEF:2.0|Vendor|NDR|1|event|src=10.0.0.1',true],
  ['kv-constructor','<134>Oct 16 15:44:21 FGT01 date=2026-10-16 time=15:44:21 constructor=bad type=traffic subtype=forward action=accept',true],
  ['kv-unclosed-quote','<134>Oct 16 15:44:21 FGT01 date=2026-10-16 time=15:44:21 devname="FGT01 type=traffic subtype=forward action=accept srcip=10.0.0.1',true],
  ['embedded-newline','<134>Oct 16 15:44:21 EDGE01 app: first\nsecond',false],
  ['embedded-nul','<134>Oct 16 15:44:21 EDGE01 app: bad\0nul',false],
] as const;

describe('syslog foundation R2 adversarial semantics',()=>{
  it.each(hardRejects)('hard rejects %s',(id,raw,envelopeExpected)=>{
    expect(parseSyslogEnvelope(raw)!==null,id).toBe(envelopeExpected);
    expect(extractGenericStructural(raw).errors.length,id).toBeGreaterThan(0);
  });

  it('downgrades PAN semantic mismatches to source-preserving generic CSV',()=>{
    const samples=[
      '<14>Oct 16 15:44:21 PA01 1,2026/02/30 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,allow',
      '<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,NOT_A_PAN_TYPE,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,allow',
    ];
    for(const raw of samples){
      const result=extractGenericStructural(raw);
      expect(result.errors).toEqual([]);
      const generic=result.fields.generic as {mode?:string;profile?:string}|undefined;
      expect(generic?.mode).toMatch(/positional_csv$/);
      expect(generic?.profile).not.toBe('panos');
    }
  });

  it('downgrades unsupported Juniper event semantics to generic tagged text',()=>{
    const raw='<14>Oct 16 15:44:21 SRX01 RT_FLOW: RT_FLOW_SESSION_UNKNOWN: 10.0.0.1/1->198.51.100.1/2';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields.juniper).toBeUndefined();
    expect(result.fields.generic).toMatchObject({mode:'bsd_tagged_message'});
  });

  it('downgrades incomplete WatchGuard traffic to preserved message fields',()=>{
    const raw='<139>Oct 16 15:44:21 WG01 FVE6035FD3AE3 (2026-10-16T15:44:21) firewall: msg_id="1BFF-000F" Allow 1-Trusted 0-External tcp 10.0.0.1 no-destination 51514 443';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields.watchguard).toBeUndefined();
    expect(result.fields.watchguard_message).toBeDefined();
  });

  it('keeps valid free-text syslog as envelope-only, not structured success',()=>{
    const raw='<134>2026-10-16T15:44:21Z IDS01 snort[771]: [1:1000001:1] TEST TCP scan from 10.0.0.1';
    expect(parseSyslogEnvelope(raw)).toMatchObject({pri:'134',hostname:'IDS01',appname:'snort',procid:'771'});
    expect(extractGenericStructural(raw).errors.length).toBeGreaterThan(0);
  });
});
