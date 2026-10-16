import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {SYSLOG_POC_POSITIVE} from './syslogPocCorpus';

describe('Snort alert body expansion PoC',()=>{
  it('measures the five fixed-corpus wrapper variants',()=>{
    const samples=SYSLOG_POC_POSITIVE.filter(sample=>sample.family==='snort');
    const rows=samples.map(sample=>{
      const parsed=extractGenericStructural(sample.raw);
      return {
        id:sample.id,
        structured:parsed.errors.length===0&&parsed.fields.snort!==undefined,
      };
    });
    const summary={
      total:rows.length,
      structured:rows.filter(row=>row.structured).length,
      failures:rows.filter(row=>!row.structured).map(row=>row.id),
    };
    console.log('SNORT_BODY_EXPANSION '+JSON.stringify(summary));
    expect(samples).toHaveLength(5);
  });

  it('keeps bounded IPv4 and bracketed IPv6 alert endpoints parseable',()=>{
    const valid=[
      '<134>2026-10-16T15:44:21Z IDS01 snort[771]: [1:1000001:1] TEST TCP scan [Classification: Attempted Information Leak] [Priority: 2] {TCP} 10.1.1.10:51514 -> 198.51.100.20:443',
      '<134>2026-10-16T15:44:21Z IDS01 snort[772]: [1:1000002:3] TEST IPv6 scan [Classification: Network Scan] [Priority: 1] {TCP} [2001:db8:1::10]:51514 -> [2001:db8:2::20]:443',
    ];
    const failures=valid.filter(raw=>{
      const parsed=extractGenericStructural(raw);
      return parsed.errors.length>0||parsed.fields.snort===undefined;
    });
    expect(failures).toEqual([]);
  });

  it('rejects malformed Snort alerts instead of downgrading',()=>{
    const invalid=[
      '[1:x:1] Bad [Classification: Test] [Priority: 2] {TCP} 10.0.0.1:1 -> 10.0.0.2:2',
      '[1:100:1] Bad [Classification: Test] [Priority: 2] {TCP} 999.1.1.1:1 -> 10.0.0.2:2',
      '[1:100:1] Bad [Classification: Test] [Priority: 2] {TCP} 10.0.0.1:70000 -> 10.0.0.2:2',
      '[1:100:1] Bad [Classification: Test] [Priority: xx] {TCP} 10.0.0.1:1 -> 10.0.0.2:2',
      '[1:100:1] Bad [Classification: Test] [Priority: 2] {TCP} 10.0.0.1:1 -> 10.0.0.2:2 {"event":"alert"}',
    ];
    const accepted=invalid.filter(body=>{
      const raw='<134>2026-10-16T15:44:21Z IDS01 snort[771]: '+body;
      return extractGenericStructural(raw).errors.length===0;
    });
    console.log('SNORT_BODY_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
