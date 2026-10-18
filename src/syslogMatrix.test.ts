import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

const bodies=[
  {
    id:'panos',
    text:'1,2026/10/07 01:02:03,012345678901,TRAFFIC,end,2561,2026/10/07 01:02:02,10.10.20.15,8.8.8.8,203.0.113.10,8.8.8.8,allow-web,,,ssl,vsys1,trust,untrust,ethernet1/1,ethernet1/2,forward-all,2026/10/07 01:02:03,123456,1,51234,443,45001,443,0x400000,tcp,allow,1480,720,760,12,2026/10/07 01:01:55,25,any,0,0x0,10.0.0.0-10.255.255.255,United States,,6,6,tcp-fin,0,0,0,0,,PA-FW01,from-policy',
  },
  {
    id:'fortinet',
    text:'date=2026-10-07 time=01:02:03 devname=FGT01 devid=FGT60FTK123456 type=traffic subtype=forward level=notice srcip=10.10.10.10 dstip=198.51.100.20 srcport=51514 dstport=443 proto=6 action=accept',
  },
  {
    id:'json',
    text:'{"timestamp":"2026-10-07T01:02:03.123456+0900","event_type":"alert","src_ip":"10.1.1.10","dest_ip":"198.51.100.20","alert":{"signature":"ET TEST"}}',
  },
  {
    id:'cef',
    text:'CEF:0|ExampleEDR|Endpoint|1.0|1001|Malware detected|8|src=10.1.1.10 dst=198.51.100.20 suser=alice',
  },
  {
    id:'leef',
    text:'LEEF:2.0|ExampleProxy|Cloud|1.0|blocked|0x09|src=10.1.1.10\tdst=198.51.100.20',
  },
  {
    id:'pfsense',
    text:'5,,,1000000103,igb1,match,block,in,4,0x0,,64,41301,0,none,6,tcp,60,10.1.1.10,198.51.100.20,51514,443,0,S,12345,,64240,,mss',
  },
] as const;

const pris=['0','14','34','134','191'] as const;

function wrappers(pri:string,body:string):string[]{
  return [
    `<${pri}>Oct  7 01:02:03 SEC01 ${body}`,
    `<${pri}>Oct 7 2026 01:02:03 SEC01 ${body}`,
    `<${pri}>Oct 7 01:02:03 2026 SEC01 ${body}`,
    `<${pri}>2026-10-07T01:02:03Z SEC01 ${body}`,
    `<${pri}>2026-10-07T01:02:03.123+09:00 SEC01 ${body}`,
    `<${pri}>2026-10-07 01:02:03.123 +0900 SEC01 ${body}`,
    `<${pri}>2026/10/07 01:02:03 SEC01 ${body}`,
  ];
}

describe('syslog deterministic matrix PoC',()=>{
  it('parses 210 timestamp/PRI/body combinations at the envelope and structured body layers',()=>{
    const rows=[] as Array<{id:string;raw:string;envelope:boolean;structured:boolean}>;
    for(const pri of pris){
      for(const body of bodies){
        wrappers(pri,body.text).forEach((raw,index)=>{
          rows.push({
            id:`${pri}-${body.id}-${index}`,
            raw,
            envelope:parseSyslogEnvelope(raw)!==null,
            structured:extractGenericStructural(raw).errors.length===0,
          });
        });
      }
    }
    const summary={
      total:rows.length,
      envelope:rows.filter(row=>row.envelope).length,
      structured:rows.filter(row=>row.structured).length,
      envelopeFailures:rows.filter(row=>!row.envelope).map(row=>row.id),
      structuredFailures:rows.filter(row=>!row.structured).map(row=>row.id),
    };
    console.log('SYSLOG_MATRIX '+JSON.stringify(summary));
    expect(summary.total).toBe(210);
    expect(summary.envelope).toBe(210);
    expect(summary.structured).toBe(210);
  });

  it('parses RFC5424 bodies after a strict header and structured-data boundary',()=>{
    const rfcBodies=bodies.filter(body=>['json','cef','leef'].includes(body.id));
    let count=0;
    for(const pri of pris){
      for(const body of rfcBodies){
        const raw=`<${pri}>1 2026-10-07T01:02:03.123Z SEC01 app 123 EVENT [meta@32473 tenant="lab"] ${body.text}`;
        const envelope=parseSyslogEnvelope(raw);
        expect(envelope,raw).not.toBeNull();
        expect(envelope?.structuredData).toBe('[meta@32473 tenant="lab"]');
        expect(extractGenericStructural(raw).errors,raw).toEqual([]);
        count++;
      }
    }
    expect(count).toBe(15);
  });

  it('keeps non-PRI loose RFC3164 variants available as lower-confidence envelopes',()=>{
    const samples=[
      'Oct  7 01:02:03 SEC01 '+bodies[1].text,
      'Oct 7 2026 01:02:03 SEC01 '+bodies[2].text,
      '2026-10-07T01:02:03+09:00 SEC01 '+bodies[3].text,
    ];
    for(const raw of samples){
      const parsed=parseSyslogEnvelope(raw);
      expect(parsed,raw).not.toBeNull();
      expect(parsed?.pri).toBeUndefined();
      expect(parsed?.hostname).toBe('SEC01');
    }
  });

  it('rejects boundary-invalid headers instead of falling into PRI-only mode',()=>{
    const invalid=[
      '<192>Oct 7 01:02:03 SEC01 app: bad pri',
      '<999>Oct 7 01:02:03 SEC01 app: bad pri',
      '<14>Oct 0 01:02:03 SEC01 app: bad day',
      '<14>Oct 32 01:02:03 SEC01 app: bad day',
      '<14>Oct 7 24:02:03 SEC01 app: bad hour',
      '<14>Oct 7 01:60:03 SEC01 app: bad minute',
      '<14>Oct 7 01:02:60 SEC01 app: bad second',
      '<14>2026-02-29T01:02:03Z SEC01 app: non leap',
      '<14>2024-02-30T01:02:03Z SEC01 app: invalid feb day',
      '<14>2026-10-07 01:02:03 +2400 SEC01 app: bad zone',
      '<14>2026/13/07 01:02:03 SEC01 app: bad month',
      '<14>0 2026-10-07T01:02:03Z SEC01 app 1 ID - bad version',
      '<14>1 2026-10-07T01:02:03Z SEC01 app 1 ID [meta@32473 k="unterminated] bad sd',
      '<14>1 2026-10-07T01:02:03Z SEC01 app 1 ID x bad structured data',
      '<14>Oct 7 01:02:03 SEC01 app: line1\nline2',
      '<14>Oct 7 01:02:03 SEC01 app: bad\0nul',
    ];
    const accepted=invalid.filter(raw=>parseSyslogEnvelope(raw)!==null);
    console.log('SYSLOG_MATRIX_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
