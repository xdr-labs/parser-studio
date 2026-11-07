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
