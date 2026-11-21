import {readFileSync,readdirSync} from 'node:fs';
import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {accountLosslessSource} from './losslessAccounting';

const HOLDOUT='tests/fixtures/vendor-holdout-20261116';
const vendorCases=readdirSync(HOLDOUT).sort().map(id=>({
  id,provenance:'VENDOR_DERIVED_FIXTURE_NOT_LIVE_ORIGINAL',
  raw:readFileSync(`${HOLDOUT}/${id}/raw.log`,'utf8').replace(/\n+$/u,''),format:'auto' as const,
}));
const manyFields=Object.fromEntries(Array.from({length:128},(_,index)=>[`field_${index}`,`value-${index}`]));
const deep={a:{b:{c:{d:{e:{f:{g:{h:{i:{j:'depth-limit'}}}}}}}}}};
const syntheticCases=[
  {id:'utf8-json-array-null-dotted',raw:JSON.stringify({message:'診断ログ 🔎',items:[{id:1},{id:2}],nullable:null,'literal.dot':'kept'}),format:'json' as const},
  {id:'cef-quoted',raw:'CEF:0|Acme|Sensor|1|100|"blocked login"|7|src=192.0.2.1 msg="user said \\"no\\""',format:'cef' as const},
  {id:'leef',raw:'LEEF:2.0|Acme|Sensor|1|cat=auth\tusrName=δοκιμή\tsrc=192.0.2.5',format:'leef' as const},
  {id:'quoted-csv',raw:'name,message\n"Doe, Jane","said ""hello"""\n"診断","quoted, UTF-8"',format:'csv' as const},
  {id:'json',raw:'{"ok":true,"n":12,"nil":null}',format:'json' as const},
  {id:'kv',raw:'user="Jane Doe" action=login message="hello world"',format:'kv' as const},
  {id:'deep-depth',raw:JSON.stringify(deep),format:'json' as const},
  {id:'over-100-fields',raw:JSON.stringify(manyFields),format:'json' as const},
  {id:'mixed-multievent',raw:'{"kind":"json","value":"α"}\nuser=bob action=login\nCEF:0|A|B|1|2|event|3|src=192.0.2.2',format:'mixed' as const},
];

describe('LF-0 deterministic adversarial source accounting corpus',()=>{
  it('runs every repository holdout plus authored adversarial formats through preview and accounting',async()=>{
    const results=[];
    for(const sample of [...vendorCases,...syntheticCases]){
      const draft={...createDraft(),format:sample.format};
      const suite=preview(sample.raw,draft);
      const accounting=await accountLosslessSource(sample.raw,suite.events.map(event=>({event})),draft);
      results.push({sample,suite,accounting});
    }
    expect(results).toHaveLength(vendorCases.length+syntheticCases.length);
    for(const {sample,suite,accounting} of results){
      expect(accounting.sourceBytes,sample.id).toBe(new TextEncoder().encode(sample.raw).length);
      expect(accounting.sourceSha256,sample.id).toMatch(/^[a-f0-9]{64}$/u);
      expect(accounting.eventCount,sample.id).toBe(suite.events.length);
      expect(accounting.events.reduce((sum,event)=>sum+event.structuralLeafCount,0),sample.id).toBeGreaterThanOrEqual(0);
      expect(Object.values(accounting.structuralCounts).reduce((sum,count)=>sum+count,0),sample.id).toBe(suite.events.length);
      expect(accounting.events.every(event=>['FULL','PARTIAL','UNKNOWN','ERROR'].includes(event.structuralStatus)),sample.id).toBe(true);
      expect(accounting.events.length,sample.id).toBeLessThanOrEqual(400);
      // This corpus runner has no native Multi-Pass residual receipt. It must never infer FULL accounting.
      expect(accounting.proof,sample.id).toBe('UNKNOWN');
      expect(accounting.events.every(event=>event.residuals===null),sample.id).toBe(true);
    }
    expect(vendorCases.every(sample=>sample.provenance==='VENDOR_DERIVED_FIXTURE_NOT_LIVE_ORIGINAL')).toBe(true);
  });
  it('keeps browser preview and native Ruby / DP verification separate',async()=>{
    const raw='{"x":"browser only"}';
    const draft={...createDraft(),format:'json' as const};
    const suite=preview(raw,draft);
    const result=await accountLosslessSource(raw,suite.events.map(event=>({event})),draft);
    expect(result.events[0]?.outputEvidence).toBe('PRESENT_BROWSER_PREVIEW');
    expect(result.proof).toBe('UNKNOWN');
  });
});
