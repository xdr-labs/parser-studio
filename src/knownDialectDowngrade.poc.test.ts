import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const samples=[
  {
    id:'asa-invalid-with-json',
    raw:'<166>2026-10-16T15:44:21Z ASA01 %ASA-6-302013: malformed vendor payload {"event":"alert"}',
  },
  {
    id:'rt-flow-invalid-with-json',
    raw:'<14>2026-10-16T15:44:21Z SRX01 RT_FLOW: RT_FLOW_SESSION_UNKNOWN: malformed {"event":"alert"}',
  },
  {
    id:'watchguard-invalid-with-json',
    raw:'<139>2026-10-16T15:44:21Z WG01 FVE6035FD3AE3 (2026-10-16T15:44:21) firewall: msg_id="BAD" malformed {"event":"alert"}',
  },
  {
    id:'pan-invalid-type-with-json',
    raw:'<14>2026-10-16T15:44:21Z PA01 1,2026/10/16 15:44:21,012345678901,NOT_A_PAN_TYPE,end,2561,2026/10/16 15:44:20,10.0.0.1,198.51.100.1,203.0.113.1,198.51.100.1,{"event":"alert"}',
  },
] as const;

describe('known dialect downgrade guard PoC',()=>{
  it('does not let an inner generic JSON rescue malformed known-vendor structure',()=>{
    const accepted=samples.filter(sample=>extractGenericStructural(sample.raw).errors.length===0);
    console.log('KNOWN_DIALECT_DOWNGRADE '+JSON.stringify({
      total:samples.length,accepted:accepted.map(sample=>sample.id),
    }));
    expect(accepted).toEqual([]);
  });
});
