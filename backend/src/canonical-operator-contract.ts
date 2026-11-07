/**
 * Canonical execution semantics for ParserProject v0.1 classification rules.
 * Pure, browser-safe code intentionally reused by both the browser hint and
 * backend validation. Emitted Ruby uses the same strict type contract and is
 * independently checked by the generated-native differential tests.
 *
 * This is a versioned operator contract, not evidence that the generated
 * parser was actually executed in Ruby or accepted by a Stellar Cyber DP.
 */
export const CANONICAL_OPERATOR_CONTRACT_V1 = Object.freeze({
  contract:'parser-studio.operator-semantics.v1',
  classification:Object.freeze({
    equals:Object.freeze({
      operandType:'string',comparison:'strict',nullMatches:false,
      coercesRawValue:false,
    }),
    exists:Object.freeze({
      operandType:'any-mapped',nullMatches:false,missingMatches:false,
      falseAndZeroCountAsPresent:true,
    }),
  }),
  enrichment:Object.freeze({
    application:'ordered-after-typed-normalization',
    skippedAfterPreviousError:true,
    failure:'rollback-entire-enrichment-transaction',
    failureStage:'enrichment',
    retainedOnFailure:'validated-pre-enrichment-fields-only',
  }),
  sourcePaths:Object.freeze({
    syntax:'safe-dotted-or-at-timestamp',
    maxCharacters:128,maxSegments:8,
    lookup:'all-partitions-own-keys',ambiguous:'reject',
    explicitSelectorMustBeUnambiguous:true,
    arraysTraversable:false,missingAndNullIneligible:true,
  }),
  executionOrder:Object.freeze([
    'extract-source','normalize-typed-fields','apply-enrichment','classify',
  ]),
  verification:Object.freeze({
    sourcePreviewIsNativeEvidence:false,nativeRubyIsTargetEvidence:false,
  }),
});

export type CanonicalClassificationOperator='equals'|'exists';

/** The v0.1 IR serializes equals constants as strings. Refuse typed equality
 * rather than converting a numeric/boolean source value into a false promise. */
export function supportsCanonicalClassificationOperator(
 operator:CanonicalClassificationOperator,normalizedType:string|undefined,
):boolean{
  if(normalizedType===undefined)return false;
  return operator==='exists'||normalizedType==='string';
}

/** Ruby native uses `value == rule['value']` (strict typed equality) and
 * `!value.nil?` for existence; do not call String(value) on a raw field. */
export function evaluateCanonicalClassificationPredicate(
  operator:CanonicalClassificationOperator,value:unknown,expected?:string,
):boolean{
  if(operator==='exists')return value!==null&&value!==undefined;
  return typeof value==='string'&&typeof expected==='string'&&value===expected;
}


/** Shared browser/backend projection of Ruby parserstudio_lookup's bounded
 * dotted-path partition semantics. Every segment combination is considered,
 * including an intermediate literal key containing dots. More than one
 * matching interpretation must fail closed, even with an explicit selector.
 * No inherited keys, array indices or prototype segments are traversed.
 */
const CANONICAL_PATH=/^[A-Za-z_][A-Za-z0-9_-]*(?:\.[A-Za-z_][A-Za-z0-9_-]*)*$/;
const FORBIDDEN_PATH_SEGMENTS=new Set(['__proto__','constructor','prototype']);

export function validCanonicalSourcePath(path:string):boolean{
  return path.length>0&&path.length<=128&&
    (path==='@timestamp'||CANONICAL_PATH.test(path))&&
    path.split('.').length<=8&&
    path.split('.').every(segment=>!FORBIDDEN_PATH_SEGMENTS.has(segment));
}

type SourcePathKind='literal_root'|'nested';
export type CanonicalPathResolution=
  |{status:'missing'}|{status:'ambiguous'}|{status:'unique';value:unknown};

function canonicalPathObject(value:unknown):value is Record<string,unknown>{
  return value!==null&&typeof value==='object'&&!Array.isArray(value);
}

export function resolveCanonicalSourcePath(
  record:Record<string,unknown>,path:string,kind?:SourcePathKind,
):CanonicalPathResolution{
  if(!validCanonicalSourcePath(path))return {status:'missing'};
  const parts=path.split('.');
  let count=0,value:unknown;
  const visit=(current:unknown,index:number):void=>{
    if(!canonicalPathObject(current)||count>1)return;
    for(let end=index+1;end<=parts.length;end++){
      const key=parts.slice(index,end).join('.');
      if(!Object.prototype.hasOwnProperty.call(current,key))continue;
      if(end===parts.length){count++;value=current[key];}
      else visit(current[key],end);
      if(count>1)return;
    }
  };
  visit(record,0);
  if(count>1)return {status:'ambiguous'};
  if(count===0)return {status:'missing'};
  if(kind==='literal_root'){
    return Object.prototype.hasOwnProperty.call(record,path)
      ?{status:'unique',value:record[path]}:{status:'missing'};
  }
  if(kind==='nested'){
    let cursor:unknown=record;
    for(const part of parts){
      if(!canonicalPathObject(cursor)||!Object.prototype.hasOwnProperty.call(cursor,part))
        return {status:'missing'};
      cursor=cursor[part];
    }
    return {status:'unique',value:cursor};
  }
  return {status:'unique',value};
}
