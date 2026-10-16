import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const asaBody='%ASA-6-302013: Built outbound TCP connection 18745213 for outside:203.0.113.50/443 (203.0.113.50/443) to inside:10.1.15.27/51822 (198.51.100.15/51822)';
const ftdBody='%FTD-6-302013: Built inbound TCP connection 42 for outside:203.0.113.60/443 (203.0.113.60/443) to inside:10.1.15.28/51823 (198.51.100.16/51823)';

describe('vendor full-line header calendar PoC',()=>{
  it('keeps leap-day ASA/FTD year-bearing headers valid',()=>{
    const valid=[
      '<166>Feb 29 2024 00:05:03 ASA-EDGE01 : '+asaBody,
      '<166>Feb 29 2024 00:05:03 FTD-EDGE01 : '+ftdBody,
    ];
    const failures=valid.filter(raw=>extractGenericStructural(raw).errors.length>0);
    expect(failures).toEqual([]);
  });

  it('rejects impossible year-aware dates before vendor parsing can bypass the common envelope',()=>{
    const invalid=[
      '<166>Feb 29 2026 00:05:03 ASA-EDGE01 : '+asaBody,
      '<166>Apr 31 2026 00:05:03 ASA-EDGE01 : '+asaBody,
      '<166>Feb 29 2026 00:05:03 FTD-EDGE01 : '+ftdBody,
      '<166>Apr 31 2026 00:05:03 FTD-EDGE01 : '+ftdBody,
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('VENDOR_HEADER_CALENDAR_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
