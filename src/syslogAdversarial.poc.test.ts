import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

interface HardRejectCase{
  id:string;
  raw:string;
  envelopeExpected:boolean;
}

const hardRejects:HardRejectCase[]=[
  {id:'pri-too-high',raw:'<192>Oct 16 15:44:21 EDGE01 app: hello',envelopeExpected:false},
  {id:'invalid-rfc3164-day',raw:'<14>Oct 32 15:44:21 EDGE01 app: hello',envelopeExpected:false},
  {id:'invalid-rfc3164-clock',raw:'<14>Oct 16 25:44:21 EDGE01 app: hello',envelopeExpected:false},
  {id:'invalid-rfc3339-date',raw:'<14>2026-02-30T15:44:21Z EDGE01 app: hello',envelopeExpected:false},
  {id:'invalid-space-zone',raw:'<14>2026-10-16 15:44:21 +2500 EDGE01 app: hello',envelopeExpected:false},
  {id:'invalid-rfc5424-version',raw:'<34>0 2026-10-16T15:44:21Z EDGE01 app 123 ID47 - hello',envelopeExpected:false},

  {id:'panos-invalid-receive-date',raw:'<14>Oct 16 15:44:21 PA01 1,2026/02/30 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,allow',envelopeExpected:true},
  {id:'panos-unknown-log-type',raw:'<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,NOT_A_PAN_TYPE,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,allow',envelopeExpected:true},
  {id:'panos-unclosed-csv-quote',raw:'<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,"broken',envelopeExpected:true},
  {id:'asa-invalid-port',raw:'<166>2026-10-16T15:44:21Z ASA01 %ASA-6-302013: Built outbound TCP connection 1 for outside:203.0.113.1/70000 (203.0.113.1/443) to inside:10.0.0.1/443 (198.51.100.1/443)',envelopeExpected:true},
  {id:'asa-invalid-context',raw:'<166>Oct 16 15:44:21 ASA01 %ASA-4-106023: Deny udp src v9:outside:192.0.2.10/54864 dst v2:inside:198.51.100.3/53 by access-group "outside_acl" [0x0, 0x0]',envelopeExpected:true},
  {id:'asa-double-message-id',raw:'<166>Oct 16 15:44:21 ASA01 %ASA-6-302013: %ASA-6-302013: Built outbound TCP connection 1 for outside:203.0.113.1/443 (203.0.113.1/443) to inside:10.0.0.1/443 (198.51.100.1/443)',envelopeExpected:true},
  {id:'juniper-no-flow-tuple',raw:'<14>2026-10-16T15:44:21Z SRX01 RT_FLOW: RT_FLOW_SESSION_CREATE: session created without a network tuple',envelopeExpected:true},
  {id:'juniper-invalid-event',raw:'<14>Oct 16 15:44:21 SRX01 RT_FLOW: RT_FLOW_SESSION_UNKNOWN: 10.0.0.1/1->198.51.100.1/2',envelopeExpected:true},

  {id:'checkpoint-prototype-key',raw:'<134>Oct 16 15:44:21 CP01 CheckPoint[8363]: [action:"Accept"; constructor:"bad"; src:"192.0.2.1"]',envelopeExpected:true},
  {id:'checkpoint-unclosed-quote',raw:'<134>2026-10-16T15:44:21Z CP01 CheckPoint[8363]: [action:"Accept; src:"192.0.2.1"]',envelopeExpected:true},
  {id:'checkpoint-single-field',raw:'<134>Oct 16 15:44:21 CP01 CheckPoint[8363]: [action:"Accept"]',envelopeExpected:true},

  {id:'watchguard-bad-msg-id',raw:'<139>Oct 16 15:44:21 WG01 FVE6035FD3AE3 (2026-10-16T15:44:21) firewall: msg_id="bad-id" Allow 1-Trusted 0-External tcp 10.0.0.1 198.51.100.1 51514 443',envelopeExpected:true},
  {id:'watchguard-invalid-device-time',raw:'<139>Oct 16 15:44:21 WG01 FVE6035FD3AE3 (not-a-date) firewall: msg_id="1BFF-000F" Allow 1-Trusted 0-External tcp 10.0.0.1 198.51.100.1 51514 443',envelopeExpected:true},

  {id:'json-array-not-object',raw:'<134>Oct 16 15:44:21 IDS01 [1,2,3]',envelopeExpected:true},
  {id:'json-prototype-key',raw:'<134>Oct 16 15:44:21 IDS01 {"constructor":"bad","src":"10.0.0.1"}',envelopeExpected:true},
  {id:'json-truncated',raw:'<134>Oct 16 15:44:21 IDS01 {"src":"10.0.0.1"',envelopeExpected:true},
  {id:'cef-invalid-version',raw:'<134>Oct 16 15:44:21 EDR01 CEF:2|Vendor|Product|1|100|Name|5|src=10.0.0.1',envelopeExpected:true},
  {id:'cef-truncated-header',raw:'<134>Oct 16 15:44:21 EDR01 CEF:0|Vendor|Product|1|100',envelopeExpected:true},
  {id:'leef-missing-delimiter',raw:'<134>Oct 16 15:44:21 NDR01 LEEF:2.0|Vendor|NDR|1|event|src=10.0.0.1',envelopeExpected:true},
  {id:'kv-constructor',raw:'<134>Oct 16 15:44:21 FGT01 date=2026-10-16 time=15:44:21 constructor=bad type=traffic subtype=forward action=accept',envelopeExpected:true},
  {id:'kv-unclosed-quote',raw:'<134>Oct 16 15:44:21 FGT01 date=2026-10-16 time=15:44:21 devname="FGT01 type=traffic subtype=forward action=accept srcip=10.0.0.1',envelopeExpected:true},

  {id:'embedded-newline',raw:'<134>Oct 16 15:44:21 EDGE01 app: first\nsecond',envelopeExpected:false},
  {id:'embedded-nul',raw:'<134>Oct 16 15:44:21 EDGE01 app: bad\0nul',envelopeExpected:false},
];

describe('syslog foundation adversarial PoC',()=>{
  it.each(hardRejects)('does not promote malformed structured input: $id',sample=>{
    expect(parseSyslogEnvelope(sample.raw)!==null,sample.id).toBe(sample.envelopeExpected);
    expect(extractGenericStructural(sample.raw).errors.length,sample.id).toBeGreaterThan(0);
  });

  it('downgrades incomplete WatchGuard traffic to message preservation instead of traffic fields',()=>{
    const raw='<139>Oct 16 15:44:21 WG01 FVE6035FD3AE3 (2026-10-16T15:44:21) firewall: msg_id="1BFF-000F" Allow 1-Trusted 0-External tcp 10.0.0.1 no-destination 51514 443';
    const result=extractGenericStructural(raw);
    expect(result.errors).toEqual([]);
    expect(result.fields.watchguard).toBeUndefined();
    expect(result.fields.watchguard_message).toBeDefined();
  });

  it('keeps syntactically valid free-text syslog as an envelope-only candidate, not a structured success',()=>{
    const raw='<134>2026-10-16T15:44:21Z IDS01 snort[771]: [1:1000001:1] TEST TCP scan from 10.0.0.1';
    expect(parseSyslogEnvelope(raw)).toMatchObject({
      pri:'134',hostname:'IDS01',appname:'snort',procid:'771',
    });
    expect(extractGenericStructural(raw).errors.length).toBeGreaterThan(0);
  });
});
