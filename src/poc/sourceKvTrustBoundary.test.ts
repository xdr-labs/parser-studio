import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import type {SecurityPipelineResult} from '../securityInputPipeline';
import {evaluateSourceKvTrust} from './sourceKvTrustBoundary';

const raw='a=1 b="two words" c=3 d=4 e=5';
const sha=createHash('sha256').update(raw).digest('hex');
const expected=new Map([['a','1'],['b','two words'],['c','3'],['d','4'],['e','5']]);
const parsed=(kv:Record<string,unknown>,source=raw):SecurityPipelineResult=>({
  ok:true,kind:'single_event',container:false,source_raw:source,
  events:[{index:0,raw:source,fields:{generic:{mode:'space_kv',kv}}}],
});
const exact={a:'1',b:'two words',c:'3',d:'4',e:'5'};
const compare=(result:SecurityPipelineResult,proof:ReadonlyMap<string,string>|null=expected,
  sourceSha256:string|null=sha)=>{
  return evaluateSourceKvTrust({raw,result,expected:proof,sourceSha256,
    fixedContract:'generic.kv'});
};
describe('source-only independent KV trust decision',()=>{
  it('requires original names, values, source hash and both raw retention checks',()=>{
    const output=compare(parsed(exact));
    expect(output.qualification).toBe('SOURCE_FIELD_EXACT');
    expect(output.score?.exact).toBe(5);
    expect(output.score?.exactEvent).toBe(true);
    expect(output.productApproval).toBe(false);
    expect(output.nativeParser).toBe('NOT_VERIFIED');
    expect(output.semanticMapping).toBe('NOT_SCORED');
  });
  it('never upgrades structural parser success without an independent source oracle',()=>{
    const outcome=compare(parsed(exact),null,null);
    expect(outcome.qualification).toBe('SOURCE_UNSCORABLE');
    expect(outcome.structurallyAccepted).toBe(true);
    expect(outcome.score).toBe(null);
    expect(outcome.independentSourceFields).toBe(0);
  });
  it('classifies one wrong value as source disagreement, not complete success',()=>{
    const outcome=compare(parsed({...exact,b:'wrong'}));
    expect(outcome.qualification).toBe('SOURCE_FIELD_MISMATCH');
    expect(outcome.score?.wrongValue).toBe(1);
    expect(outcome.score?.exact).toBe(4);
    expect(outcome.score!.extracted-outcome.score!.exact).toBe(1);
    expect(outcome.score!.expected-outcome.score!.exact).toBe(1);
  });
  it('counts missing and unexpected paths without guessing map locations',()=>{
    const {b,...missingB}=exact;
    const outcome=compare(parsed({...missingB,unknown:'extra'}));
    expect(outcome.qualification).toBe('SOURCE_FIELD_MISMATCH');
    expect(outcome.score?.missing).toBe(1);
    expect(outcome.score?.unexpected).toBe(1);
  });
  it('does not count numeric coercion as an exact original value',()=>{
    const outcome=compare(parsed({...exact,c:3}));
    expect(outcome.qualification).toBe('SOURCE_FIELD_MISMATCH');
    expect(outcome.score?.wrongValue).toBe(1);
  });
  it('rejects missing expected fixed contract tree even with ok:true',()=>{
    const output=compare(parsed({a:'1'}));
    expect(output.qualification).toBe('SOURCE_FIELD_MISMATCH');
    expect(output.score?.missing).toBe(4);
  });
  it('rejects oracle SHA drift even if fields would be exact',()=>{
    const output=compare(parsed(exact),expected,'0'.repeat(64));
    expect(output.qualification).toBe('ORACLE_SOURCE_DRIFT');
    expect(output.score).toBe(null);
  });
  it('rejects both pipeline raw and event raw drift',()=>{
    const output=compare(parsed(exact,'changed'));
    expect(output.qualification).toBe('RAW_NOT_PRESERVED');
    const eventOnly={...parsed(exact)} as Extract<SecurityPipelineResult,{ok:true}>;
    eventOnly.events=[{index:0,raw:'changed',fields:{generic:{kv:exact}}}];
    expect(compare(eventOnly).qualification).toBe('RAW_NOT_PRESERVED');
  });
  it('does not count failed parsing as source-complete',()=>{
    const output=compare({ok:false,error:'unsupported'});
    expect(output.qualification).toBe('PARSER_NOT_SINGLE_EVENT');
    expect(output.score?.missing).toBe(5);
  });
  it('requires exactly one event per qualified original source record',()=>{
    const result=parsed(exact) as Extract<SecurityPipelineResult,{ok:true}>;
    result.events.push({...result.events[0]!,index:1});
    expect(compare(result).qualification).toBe('PARSER_NOT_SINGLE_EVENT');
  });
  it('does not replace Fortinet contract with generic inferred KV fields',()=>{
    const result=parsed(exact);
    const verdict=evaluateSourceKvTrust({raw,result,expected,sourceSha256:sha,
      fixedContract:'fortinet.fields'});
    expect(verdict.qualification).toBe('SOURCE_FIELD_MISMATCH');
    expect(verdict.score?.missing).toBe(5);
  });
});
