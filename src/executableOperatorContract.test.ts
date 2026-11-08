import {describe,it,expect} from 'vitest';
import {OPERATOR_GOLDENS,operatorGoldenFixture} from '../contracts/operator-conformance';
import {preview} from './parser';
import {toBackendProject} from './guided/backendAdapter';
import {canonicalCaseTransform} from '../backend/src/canonical-operator-contract';

describe('independent executable operator contract',()=>{
 for(const item of OPERATOR_GOLDENS){
  for(const family of item.format==='regex'?[false]:[false,true]){
   it(item.id+(family?' family':' ordinary'),()=>{
    const {draft,raw,expected}=operatorGoldenFixture(item,family);
    const result=toBackendProject(draft);
    if(item.rejected){expect(result.ok).toBe(false);return;}
    expect(result.ok).toBe(true);
    const event=preview(raw,draft).events[0]!;
    expect(event.raw).toBe(raw);
    expect(event.normalized).toEqual(expected);
    const errors=event.diagnostics.filter(issue=>issue.severity==='error');
    expect(errors.length>0).toBe(Boolean(item.stage));
    if(item.stage)expect(errors.some(issue=>issue.stage===item.stage)).toBe(true);
    else expect(event.normalizedOk).toBe(Object.keys(expected).length>0);
   });
  }
 }
 it('uses pinned full per-codepoint casing instead of host context or ICU',()=>{
  expect(canonicalCaseTransform('ΟΣ İ','lowercase')).toBe('οσ i\u0307');
  expect(canonicalCaseTransform('straße','uppercase')).toBe('STRASSE');
  expect(canonicalCaseTransform('\u1c89','lowercase')).toBe('\u1c89');
 });
});
