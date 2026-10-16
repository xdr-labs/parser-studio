import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const samples=[
  {
    id:'rfc3164-over-rfc3164-cef',
    raw:'<13>Oct 16 15:45:00 relay01 <134>Oct 16 15:44:21 edge01 CEF:1|Vendor|EDR|1.0|42|Malware|9|src=192.0.2.10 dst=198.51.100.20',
    innerHost:'edge01',outerHost:'relay01',
  },
  {
    id:'rfc3339-over-rfc5424-json',
    raw:'<13>2026-10-16T15:45:00Z relay01 <134>1 2026-10-16T15:44:21Z ids01 sensor 991 EVT - {"event_type":"alert","src_ip":"192.0.2.10","dest_ip":"198.51.100.20"}',
    innerHost:'ids01',outerHost:'relay01',
  },
  {
    id:'rfc3164-over-rfc3339-kv',
    raw:'<13>Oct 16 15:45:00 relay01 <134>2026-10-16T15:44:21Z fw01 date=2026-10-16 time=15:44:21 type=traffic srcip=192.0.2.10 dstip=198.51.100.20 action=allow',
    innerHost:'fw01',outerHost:'relay01',
  },
] as const;

describe('bounded nested Syslog relay PoC',()=>{
  it('preserves outer relay and inner source envelopes while parsing the inner structured body',()=>{
    for(const sample of samples){
      const parsed=extractGenericStructural(sample.raw);
      expect(parsed.errors,sample.id).toEqual([]);
      expect(parsed.fields.syslog,sample.id).toMatchObject({hostname:sample.innerHost});
      expect(parsed.fields.relay,sample.id).toMatchObject({
        depth:1,
        outer_syslog:{hostname:sample.outerHost},
        source_raw:sample.raw,
      });
      expect(JSON.stringify(parsed.fields),sample.id).not.toContain('source_raw\\":\\"<134>');
    }
  });

  it('does not recurse through a second nested Syslog layer',()=>{
    const double='<13>Oct 16 15:46:00 relay02 <13>Oct 16 15:45:00 relay01 <134>Oct 16 15:44:21 edge01 CEF:1|Vendor|EDR|1.0|42|Malware|9|src=192.0.2.10 dst=198.51.100.20';
    expect(extractGenericStructural(double).errors.length).toBeGreaterThan(0);
  });

  it('rejects malformed inner envelopes and malformed known inner bodies',()=>{
    const invalid=[
      '<13>Oct 16 15:45:00 relay01 <999>Oct 16 15:44:21 edge01 CEF:1|Vendor|EDR|1|42|Name|5|src=192.0.2.1',
      '<13>Oct 16 15:45:00 relay01 <134>Feb 30 15:44:21 edge01 CEF:1|Vendor|EDR|1|42|Name|5|src=192.0.2.1',
      '<13>Oct 16 15:45:00 relay01 <134>Oct 16 15:44:21 edge01 CEF:2|Vendor|EDR|1|42|Name|5|src=192.0.2.1',
      '<13>Oct 16 15:45:00 relay01 ordinary free text',
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('NESTED_SYSLOG_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
