import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const records=[
  '<14>Oct 16 15:44:21 PA01 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,allow',
  '<134>2026-10-16T15:44:21Z FGT01 app: date=2026-10-16 time=15:44:21 devname=FGT01 type=traffic subtype=forward srcip=10.0.0.1 dstip=198.51.100.1 action=accept',
  '<134>Oct 16 15:44:21 EDR01 agent: CEF:0|Vendor|EDR|1.0|42|Malware|9|src=10.0.0.8 dst=198.51.100.8',
  '<134>1 2026-10-16T15:44:21Z NDR01 nss - EVENT - LEEF:2.0|Vendor|NDR|1.0|dns|0x09|src=10.0.0.9\tdst=198.51.100.53',
  '<134>2026-10-16T15:44:21Z CP01 app: action=Accept|src=192.0.2.10|dst=198.51.100.20|service=443|product=Firewall',
  '<134>Oct 16 15:44:21 IDS01 sensor: {"event_type":"alert","src_ip":"10.0.0.2","dest_ip":"198.51.100.2"}',
  '<166>2026-10-16T15:44:21Z ASA01 %ASA-6-302013: Built outbound TCP connection 1 for outside:203.0.113.1/443 (203.0.113.1/443) to inside:10.0.0.1/443 (198.51.100.1/443)',
  '<14>2026-10-16T15:44:21Z SRX01 RT_FLOW: RT_FLOW_SESSION_CREATE: session created 192.0.2.1/40275->198.51.100.1/161 None 192.0.2.1/40275->198.51.100.1/161 None None 17 allow-all trust untrust 23228 N/A(N/A) ge-0/0/0.0',
] as const;

function octetFrame(message:string):string{
  return new TextEncoder().encode(message).byteLength+' '+message;
}

describe('RFC6587 framing PoC',()=>{
  it('measures current octet-counted record coverage',()=>{
    const rows=records.map(raw=>({
      raw,
      framed:octetFrame(raw),
      plain:extractGenericStructural(raw).errors.length===0,
      framedOk:extractGenericStructural(octetFrame(raw)).errors.length===0,
    }));
    const summary={
      total:rows.length,
      plain:rows.filter(row=>row.plain).length,
      framed:rows.filter(row=>row.framedOk).length,
    };
    console.log('RFC6587_BASELINE '+JSON.stringify(summary));
    expect(summary.plain).toBe(records.length);
    expect(summary.framed).toBe(records.length);
  });

  it('does not accept invalid octet-counted prefixes as structured events',()=>{
    const message=records[1];
    const bytes=new TextEncoder().encode(message).byteLength;
    const invalid=[
      '0 '+message,
      String(bytes-1)+' '+message,
      String(bytes+1)+' '+message,
      '999999 '+message,
      String(bytes)+'X '+message,
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('RFC6587_INVALID_BASELINE '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });

  it('supports bounded non-transparent LF, CRLF, and NUL trailers',()=>{
    const message=records[2];
    for(const [suffix,mode] of [
      ['\n','rfc6587_non_transparent_lf'],
      ['\r\n','rfc6587_non_transparent_crlf'],
      ['\0','rfc6587_non_transparent_nul'],
    ] as const){
      const parsed=extractGenericStructural(message+suffix);
      expect(parsed.errors,mode).toEqual([]);
      expect(parsed.fields.framing,mode).toMatchObject({mode});
    }
    const embedded=extractGenericStructural(message+'\nsecond\n');
    expect(embedded.errors.length).toBeGreaterThan(0);
  });
});
