import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const cases=[
  {id:'bsd-cef',raw:'<134>Oct 16 15:44:21 CEF:1|Vendor|EDR|1.0|42|Malware|9|src=192.0.2.10 dst=198.51.100.20'},
  {id:'bsd-year-kv',raw:'<134>Oct 16 2026 15:44:21 date=2026-10-16 time=15:44:21 type=traffic srcip=192.0.2.10 dstip=198.51.100.20 action=allow'},
  {id:'rfc3339-json',raw:'<134>2026-10-16T15:44:21Z {"event_type":"alert","src_ip":"192.0.2.10","dest_ip":"198.51.100.20"}'},
  {id:'iso-space-leef',raw:'<134>2026-10-16 15:44:21 +0900 LEEF:2.0|Vendor|NDR|1.0|dns|x5E|src=192.0.2.10^dst=198.51.100.20^act=allow'},
  {id:'slash-xml',raw:'<134>2026/10/16 15:44:21 <Event><System><EventID>4625</EventID><Computer>WIN01</Computer><Channel>Security</Channel></System><EventData><Data Name="TargetUserName">alice</Data><Data Name="IpAddress">192.0.2.10</Data><Data Name="IpPort">51514</Data></EventData></Event>'},
  {id:'bsd-panos',raw:'<14>Oct 16 15:44:21 1,2026/10/16 15:44:21,012345678901,TRAFFIC,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,allow'},
] as const;

describe('hostless structured Syslog PoC',()=>{
  it('accepts validated structured bodies without inventing a hostname',()=>{
    const rows=cases.map(sample=>({sample,result:extractGenericStructural(sample.raw)}));
    const failures=rows.filter(row=>row.result.errors.length);
    console.log('HOSTLESS_SYSLOG '+JSON.stringify({total:rows.length,parsed:rows.length-failures.length,failures:failures.map(row=>row.sample.id)}));
    expect(failures).toEqual([]);
    for(const {sample,result} of rows){
      const syslog=result.fields.syslog as Record<string,unknown>|undefined;
      expect(syslog,sample.id).toBeDefined();
      expect(syslog?.hostname,sample.id).toBeUndefined();
      expect(syslog?.hostname_missing,sample.id).toBe(true);
      const generic=result.fields.generic as Record<string,unknown>|undefined;
      if(generic)expect(generic.hostless_syslog,sample.id).toBe(true);
    }
  });

  it('preserves the original raw event instead of the synthetic validation hostname',()=>{
    const sample=cases[0];
    const parsed=extractGenericStructural(sample.raw);
    expect(JSON.stringify(parsed.fields)).not.toContain('__HOSTLESS__');
    const generic=parsed.fields.generic as {source_raw?:string}|undefined;
    expect(generic?.source_raw).toBe(sample.raw);
  });

  it('rejects ambiguous free text and malformed known structured bodies',()=>{
    const invalid=[
      '<134>Oct 16 15:44:21 ordinary free text without structure',
      '<134>Oct 16 15:44:21 action=deny src=192.0.2.1',
      '<134>Feb 30 15:44:21 CEF:1|Vendor|EDR|1|42|Name|5|src=192.0.2.1',
      '<134>2026-02-30T15:44:21Z {"event":"alert"}',
      '<134>Oct 16 15:44:21 CEF:2|Vendor|EDR|1|42|Name|5|src=192.0.2.1',
      '<134>Oct 16 15:44:21 LEEF:2.0|Vendor|NDR|1|evt|^|constructor=bad^dst=198.51.100.1^act=deny',
      'Oct 16 15:44:21 CEF:1|Vendor|EDR|1|42|Name|5|src=192.0.2.1',
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('HOSTLESS_SYSLOG_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
