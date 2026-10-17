import {describe,expect,it} from 'vitest';
import {judgeSourceKvSpans,type IndependentSourceSpan} from './sourceKvSpanReviewGate';
import type {LocatedKvField} from './conservativeKvUtf8Span';

const reference:IndependentSourceSpan={
  name:'message',referenceValue:'price',referenceStatus:'SOURCE_QUALIFIED',
  rawStart:4,rawEnd:20,nameStart:4,nameEnd:11,valueStart:12,valueEnd:20,
};
const candidate:LocatedKvField={
  name:'message',value:'price',rawStart:4,rawEnd:20,
  nameStart:4,nameEnd:11,valueStart:12,valueEnd:20,
};
const classify=(expected:IndependentSourceSpan[]|null=[reference],
  actual:LocatedKvField[]|null=[candidate],
  sourceShaMatches=true,exactRawRetained=true)=>
  judgeSourceKvSpans({sourceShaMatches,exactRawRetained,expected,actual});
describe('independent source-byte and source-value qualification gate',()=>{
  it('requires manufacturer review even for exact name, span and value',()=>{
    const result=classify();
    expect(result.disposition).toBe('REVIEW_ONLY_SOURCE_EXACT');
    expect(result.exactOriginalFields).toBe(1);
    expect(result.canAutoPromote).toBe(false);
    expect(result.manufacturerSemantics).toBe('NOT_CERTIFIED');
  });
  it('rejects off-by-one UTF-8 byte position regardless of value',()=>{
    const result=classify([reference],[{...candidate,valueEnd:19}]);
    expect(result.disposition).toBe('PARTIAL_SOURCE_MISMATCH');
    expect(result.spanMismatches).toBe(1);
    expect(result.falsePositiveFields).toBe(1);
    expect(result.falseNegativeFields).toBe(1);
  });
  it('rejects matching location with a wrong decoded value',()=>{
    const result=classify([reference],[{...candidate,value:'wrong'}]);
    expect(result.valueMismatches).toBe(1);
    expect(result.disposition).toBe('PARTIAL_SOURCE_MISMATCH');
  });
  it('rejects additional candidate fields and missing source fields',()=>{
    expect(classify([reference],[candidate,{...candidate,name:'extra'}])
      .falsePositiveFields).toBe(1);
    expect(classify([reference],[]).falseNegativeFields).toBe(1);
  });
  it('does not compare unreliable, conflicting or unpinned references',()=>{
    expect(classify([{...reference,referenceStatus:'VALUE_AMBIGUOUS'}])
      .disposition).toBe('UNSCORABLE_SOURCE');
    expect(classify(null).disposition).toBe('UNSCORABLE_SOURCE');
    expect(classify([reference],[candidate],false).disposition).toBe('UNSCORABLE_SOURCE');
    expect(classify([reference],[candidate],true,false).disposition).toBe('UNSCORABLE_SOURCE');
  });
  it('rejects duplicate names and never promotes to source success',()=>{
    const o=classify([reference,reference],[candidate,candidate]);
    expect(o.disposition).toBe('PARTIAL_SOURCE_MISMATCH');
    expect(o.canAutoPromote).toBe(false);
  });
});
