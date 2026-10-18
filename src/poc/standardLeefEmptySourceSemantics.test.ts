import {createHash} from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import {describe,it,expect} from 'vitest';
import {extractStructuredFamily} from '../structuredFamilies';
import {arbitrateIndependentLeef} from './independentLeefSource';

type Case={
  id:string;wire:string;sha256:string;browserAccepted:boolean;
  sourceLexical:boolean;headerOnly:boolean;
  expectedExtensionClaims:Array<{
    name:string;value:string;occurrence:number;startByte:number;endByte:number;
  }>;
};
const frozen=fs.readFileSync(path.join(__dirname,
  '../../scripts/poc/standardLeefEmptySourceSemantics.pinned.json'));
const digest='e6b0c14dddb51a67833009e9336c0351dc0558c0306c8b9f7cb69eb9d065918a';
const hash=(buffer:Uint8Array)=>createHash('sha256').update(buffer).digest('hex');
if(hash(frozen)!==digest)throw Error('IBM LEEF independent source oracle SHA changed');
const cases=(JSON.parse(frozen.toString('utf8')) as {cases:Case[]}).cases;
const decoder=new TextDecoder('utf8',{fatal:true});

describe('P0-STD LEEF lexical empty vs absent and duplicate occurrence policies',()=>{
  it('freezes original synthetic keys, raw bytes and empty value proof boundaries',()=>{
    expect(cases).toHaveLength(15);
    expect(cases.filter(c=>c.sourceLexical)).toHaveLength(9);
    expect(cases.flatMap(c=>c.expectedExtensionClaims)
      .filter(x=>x.value==='')).toHaveLength(9);
  });

  it.each(cases)('does not misclassify missing, empty, repeated key source: $id',t=>{
    const raw=Buffer.from(t.wire,'utf8');
    expect(hash(raw)).toBe(t.sha256);
    const browser=extractStructuredFamily(t.wire,'leef');
    expect(browser.errors.length===0).toBe(t.browserAccepted);
    const source=arbitrateIndependentLeef(t.wire);
    const extension=source.bodyClaims.filter(c=>c.path.includes('/extension/'));
    expect(source.autoPromoted).toBe(false);
    expect(source.independentOracleCertified).toBe(false);
    expect(source.nativeVerified).toBe(false);
    if(!t.sourceLexical){
      expect(source.disposition==='ABSTAIN_UNSAFE'||
        source.disposition==='REVIEW_ONLY_UNFRAMED').toBe(true);
      expect(extension).toEqual([]);
      return;
    }
    expect(source.disposition).toBe('REVIEW_ONLY_STRUCTURED_BODY');
    expect(source.bodyReviewEvidence).toBe('LEXICALLY_REPLAYED');
    expect(extension).toHaveLength(t.expectedExtensionClaims.length);
    for(let i=0;i<extension.length;i++){
      const claim=extension[i]!;
      const expected=t.expectedExtensionClaims[i]!;
      expect({
        name:claim.name,value:claim.value,occurrence:claim.occurrence,
        startByte:claim.startByte,endByte:claim.endByte,
      }).toEqual(expected);
      expect(decoder.decode(raw.subarray(claim.startByte,claim.endByte)))
        .toBe(expected.value);
      if(expected.value==='')expect(claim.startByte).toBe(claim.endByte);
    }
    if(t.browserAccepted){
      for(const expected of t.expectedExtensionClaims)
        if(expected.occurrence===0)
          expect(browser.fields[expected.name]).toBe(expected.value);
    }
    expect(source.reason).toBe('LEEF_SYNTAX_ONLY_NOT_SOURCE_CERTIFIED');
  });

  it('does not infer that repeated LEEF keys map to a deterministic native value',()=>{
    for(const c of cases.filter(x=>x.id.includes('DUPLICATE'))){
      const browser=extractStructuredFamily(c.wire,'leef');
      const source=arbitrateIndependentLeef(c.wire);
      expect(browser.errors.length).toBeGreaterThan(0);
      const claims=source.bodyClaims.filter(c=>c.path.includes('/extension/'));
      expect(claims.map(c=>c.occurrence)).toEqual([0,1]);
      expect(source.autoPromoted).toBe(false);
      expect(source.nativeVerified).toBe(false);
    }
  });
});
