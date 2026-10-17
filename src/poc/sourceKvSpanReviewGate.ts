/** PoC-only fail-closed adjudication of independently located original KV bytes.
 * Not a manufacturer/transport/native parser certification.
 */
import type {LocatedKvField} from './conservativeKvUtf8Span';

type SpanCoordinates=Pick<LocatedKvField,
  'rawStart'|'rawEnd'|'nameStart'|'nameEnd'|'valueStart'|'valueEnd'>;
export type IndependentSourceSpan=SpanCoordinates&{
  name:string;
  referenceValue:string;
  referenceStatus:'SOURCE_QUALIFIED'|'VALUE_AMBIGUOUS';
};
export type SourceSpanVerdict='REVIEW_ONLY_SOURCE_EXACT'|
  'PARTIAL_SOURCE_MISMATCH'|'UNSCORABLE_SOURCE';
export type SourceSpanReview={
  disposition:SourceSpanVerdict;
  exactOriginalFields:number;
  falsePositiveFields:number;
  falseNegativeFields:number;
  spanMismatches:number;
  valueMismatches:number;
  manufacturerSemantics:'NOT_CERTIFIED';
  nativeParser:'NOT_VERIFIED';
  canAutoPromote:false;
};

export function judgeSourceKvSpans(input:{
  sourceShaMatches:boolean;
  exactRawRetained:boolean;
  expected:IndependentSourceSpan[]|null;
  actual:LocatedKvField[]|null;
}):SourceSpanReview{
  const make=(disposition:SourceSpanVerdict,exactOriginalFields=0,
    falsePositiveFields=0,falseNegativeFields=0,spanMismatches=0,
    valueMismatches=0):SourceSpanReview=>({
      disposition,exactOriginalFields,falsePositiveFields,falseNegativeFields,
      spanMismatches,valueMismatches,manufacturerSemantics:'NOT_CERTIFIED',
      nativeParser:'NOT_VERIFIED',canAutoPromote:false,
    });
  if(!input.sourceShaMatches||!input.exactRawRetained||
     !input.expected||input.expected.some(x=>x.referenceStatus!=='SOURCE_QUALIFIED'))
    return make('UNSCORABLE_SOURCE');
  const expected=input.expected;
  const actual=input.actual??[];
  let exact=0,spanErrors=0,valueErrors=0;
  const expectedByName=new Map(expected.map(field=>[field.name,field]));
  const actualByName=new Map(actual.map(field=>[field.name,field]));
  if(expectedByName.size!==expected.length||actualByName.size!==actual.length)
    return make('PARTIAL_SOURCE_MISMATCH',0,actual.length,expected.length,
      actual.length+expected.length,0);
  for(const field of expected){
    const found=actualByName.get(field.name);
    if(!found)continue;
    const spanEqual=(
      field.rawStart===found.rawStart&&field.rawEnd===found.rawEnd&&
      field.nameStart===found.nameStart&&field.nameEnd===found.nameEnd&&
      field.valueStart===found.valueStart&&field.valueEnd===found.valueEnd);
    const valueEqual=field.referenceValue===found.value;
    if(!spanEqual)spanErrors++;
    if(!valueEqual)valueErrors++;
    if(spanEqual&&valueEqual)exact++;
  }
  const fp=actual.length-exact;
  const fn=expected.length-exact;
  return make(fp===0&&fn===0?'REVIEW_ONLY_SOURCE_EXACT':
    'PARTIAL_SOURCE_MISMATCH',exact,fp,fn,spanErrors,valueErrors);
}
