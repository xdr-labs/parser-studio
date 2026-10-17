import {describe,expect,it} from 'vitest';
import {sha256Utf8Hex} from '../sha256';
import {scanKeyValues,scanPrefixedKeyValues,scanDelimitedRow} from './losslessLexer';
import {reviewSourceEvidence,type IndependentSourceReference} from './sourceEvidence';

const revision='ee918d03f4a90dacd32673546c64a633308796ef';
async function makeReference(
  raw:string,orderedFields:Array<readonly [string,string]>,prefix?:string,
):Promise<IndependentSourceReference>{
  return {
    originalSha256:await sha256Utf8Hex(raw),
    upstreamRevision:revision,
    fixtureId:'independent-fixture-1',
    authority:'independent_source_oracle',orderedFields,
    ...(prefix===undefined?{}:{expectedPrefix:prefix}),
  };
}

describe('independent field-value source evidence certificate',()=>{
  it('accepts only exact bytes and ordered independent field values; never promotes to native or mapped status',async()=>{
    const raw='src=192.0.2.1 dst=198.51.100.2 action="drop"';
    const fields=[['src','192.0.2.1'],['dst','198.51.100.2'],['action','drop']] as const;
    const decision=await reviewSourceEvidence(
      scanKeyValues(raw,0,'space')!,
      await makeReference(raw,fields.map(pair=>[pair[0],pair[1]])),
    );
    expect(decision).toMatchObject({
      status:'source_value_exact',sourceRawPreserved:true,reviewedFieldCount:3,
      mappingVerified:false,nativeRuntimeVerified:false,
      productPromotionAllowed:false,requiresHumanReview:true,
    });
  });

  it('rejects a wrong source hash and any single field-value or ordering mismatch',async()=>{
    const raw='source=192.0.2.10 dest=198.51.100.4 action=deny';
    const candidate=scanKeyValues(raw,0,'space')!;
    const expected=await makeReference(raw,[
      ['source','192.0.2.10'],['dest','198.51.100.4'],['action','deny'],
    ]);
    expect((await reviewSourceEvidence(candidate,{...expected,originalSha256:'a'.repeat(64)})).status)
      .toBe('source_mismatch');
    expect((await reviewSourceEvidence(candidate,{...expected,orderedFields:[
      ['source','192.0.2.10'],['dest','198.51.100.9'],['action','deny'],
    ]})).status).toBe('source_mismatch');
    expect((await reviewSourceEvidence(candidate,{...expected,orderedFields:[
      ['dest','198.51.100.4'],['source','192.0.2.10'],['action','deny'],
    ]})).status).toBe('source_mismatch');
  });

  it('permits source-exact prefix/repeated occurrences but retains the partial classification',async()=>{
    const raw='192.0.2.10 msg="first" msg="second" action=allow';
    const lexical=scanPrefixedKeyValues(raw,0)!;
    const expected=await makeReference(raw,[
      ['msg','first'],['msg','second'],['action','allow'],
    ],'192.0.2.10 ');
    const approved=await reviewSourceEvidence(lexical,expected);
    expect(approved).toMatchObject({status:'source_value_exact',reviewedFieldCount:3,
      requiresHumanReview:true,productPromotionAllowed:false});
    expect(approved.reason).toContain('partial');
    expect((await reviewSourceEvidence(lexical,{...expected,expectedPrefix:'192.0.2.11 '})).status)
      .toBe('source_mismatch');
  });

  it('rejects source certification when no independent fixture reference is provided',async()=>{
    const candidate=scanKeyValues('x=1 y=2',0,'space')!;
    expect(await reviewSourceEvidence(candidate)).toMatchObject({
      status:'unverified',sourceRawPreserved:false,reviewedFieldCount:0,
      productPromotionAllowed:false,
    });
  });

  it('rejects positional CSV, unsupported provenance, and tampered candidate values',async()=>{
    const csv='a,b,c';
    const reference=await makeReference(csv,[['column_1','a'],['column_2','b'],['column_3','c']]);
    expect((await reviewSourceEvidence(scanDelimitedRow(csv,0,'comma')!,reference)).status)
      .toBe('unverified');
    const original='x=1 y=2';
    const lexical=scanKeyValues(original,0,'space')!;
    const fields=await makeReference(original,[['x','1'],['y','2']]);
    expect((await reviewSourceEvidence(lexical,{...fields,upstreamRevision:'unreviewed'})).status)
      .toBe('unverified');
    const forged=structuredClone(lexical);
    forged.fields[0]!.value='manipulated';
    expect((await reviewSourceEvidence(forged,fields)).status).toBe('unverified');
  });
});
