import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,expect,it} from 'vitest';
import {extractStructuredFamily} from '../structuredFamilies';
import {arbitrateIndependentLeef} from './independentLeefSource';

type SourceField={name:string;value:string;startByte:number;endByte:number};
type Case={id:string;wire:string;valid:boolean;fields:SourceField[];
 sourceBytes:number;delimiterToken?:string|null;delimiter?:string};
const frozen=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardsLeefDelimiterParity.pinned.json'));
const sha='4a30628234e4c5c681fdc73ed2f4215f810d2bf5d094d76503a3af0d65ddb00a';
if(createHash('sha256').update(frozen).digest('hex')!==sha)
  throw Error('Frozen independently authored IBM LEEF grammar answer changed');
const {cases}=JSON.parse(frozen.toString('utf8')) as {cases:Case[]};
const decoder=new TextDecoder('utf8',{fatal:true});
const keys:Record<string,string>={
  version:'leef_version',vendor:'leef_vendor',product:'leef_product',
  product_version:'leef_product_version',event_id:'leef_event_id',
};

describe('P0-STD-4 independent LEEF 2.0 declared-delimiter/source-span parity',()=>{
  it('pins all normative synthetic denominators before source scoring',()=>{
    expect(cases).toHaveLength(14);
    expect(cases.filter(x=>x.valid)).toHaveLength(8);
    expect(cases.filter(x=>!x.valid)).toHaveLength(6);
  });
  it.each(cases)('keeps IBM LEEF source fields and raw byte offsets: $id',t=>{
    const raw=new TextEncoder().encode(t.wire);
    expect(raw.length).toBe(t.sourceBytes);
    const browser=extractStructuredFamily(t.wire,'leef');
    const source=arbitrateIndependentLeef(t.wire);
    expect(browser.errors.length===0).toBe(t.valid);
    expect(source.autoPromoted).toBe(false);
    expect(source.independentOracleCertified).toBe(false);
    expect(source.nativeVerified).toBe(false);
    if(!t.valid){
      expect(source.disposition).toBe('ABSTAIN_UNSAFE');
      expect(source.bodyClaims).toEqual([]);
      return;
    }
    expect(source.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(source.selectedBodyGrammar).toBe('leef');
    expect(source.bodyClaims).toHaveLength(t.fields.length);
    t.fields.forEach((claim,i)=>{
      const original=source.bodyClaims[i]!;
      expect({name:original.name,value:original.value,
        startByte:original.startByte,endByte:original.endByte})
        .toEqual(claim);
      expect(decoder.decode(raw.subarray(claim.startByte,claim.endByte))).toBe(claim.value);
      if(claim.name!=='delimiter')
        expect(browser.fields[keys[claim.name]??claim.name]).toBe(claim.value);
    });
    expect(source.reason).toBe('LEEF_SYNTAX_ONLY_NOT_SOURCE_CERTIFIED');
  });
});
