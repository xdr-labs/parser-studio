import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const bom='\uFEFF';
const bodies=[
  bom+'{"event":"alert","src":"192.0.2.1","dst":"198.51.100.1"}',
  bom+'CEF:0|Vendor|EDR|1.0|42|Malware|9|src=192.0.2.1 dst=198.51.100.1',
  bom+'LEEF:2.0|Vendor|NDR|1.0|dns|0x09|src=192.0.2.1\tdst=198.51.100.1',
  bom+'action=block|src=192.0.2.1|dst=198.51.100.1|rule=web',
] as const;

function event(body:string):string{
  return '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT - '+body;
}

describe('RFC5424 BOM body PoC',()=>{
  it('measures UTF-8 BOM-prefixed structured body coverage',()=>{
    const expectedModes=[
      'syslog_envelope_json',
      'syslog_envelope_cef',
      'syslog_envelope_leef',
      'syslog_envelope_delimited_kv',
    ];
    const rows=bodies.map((body,index)=>{
      const parsed=extractGenericStructural(event(body));
      const generic=parsed.fields.generic as {mode?:string;message_raw?:string}|undefined;
      return {
        ok:parsed.errors.length===0&&generic?.mode===expectedModes[index],
        rawPreserved:generic?.message_raw?.startsWith(bom)===true,
      };
    });
    const summary={
      total:rows.length,
      parsed:rows.filter(row=>row.ok).length,
      rawPreserved:rows.filter(row=>row.rawPreserved).length,
    };
    console.log('RFC5424_BOM_BODY '+JSON.stringify(summary));
    expect(summary.parsed).toBe(bodies.length);
    expect(summary.rawPreserved).toBe(bodies.length);
  });

  it('does not treat BOM-only or duplicated BOM as structured body',()=>{
    const invalid=[
      event(bom),
      event(bom+bom+'{"event":"alert"}'),
    ];
    const accepted=invalid.filter(raw=>extractGenericStructural(raw).errors.length===0);
    console.log('RFC5424_BOM_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
