/**
 * Independently authored normalized destination goldens. This is NOT a
 * comparison of the two production engines to a policy-derived expected
 * value. Do not regenerate the fixture from either source implementation.
 */
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import {suggestNormalizationCandidates,
  suggestNormalizationCandidatesFromSuite} from '../../src/guided/normalizationCandidates';
import {suggestFieldMappings} from '../../backend/src/mapping-suggestions';
import policy from '../../runtime/multipass/semantic-policy.v1.json' with {type:'json'};
import type {SuiteResult} from '../../src/model';

interface Golden{
  id:string;source:string;value:unknown;target:string|null;
  confidence?:'HIGH'|'REVIEW';hint:'REVIEW_REQUIRED'|'DESTINATION_CONFLICT'|'EXISTING_MAPPING'|null;
  hintTarget?:string;safeForBulk:boolean;
  context?:Record<string,unknown>;existingDestinations?:string[];
}
type Truth={
  contract:string;oracleOrigin:string;notDerivedFrom:string[];cases:Golden[];
  competingSources:{
    sources:string[];expectedTarget:string;expectedBrowserConfidence:string;
    expectedSafeForBulk:boolean;expectedBackendStatus:string;
  };
  sparseEvent:{
    source:string;valueFirst:string;expectedTarget:string;
    expectedBrowserConfidence:string;expectedSafeForBulk:boolean;expectedBackendStatus:string;
  };
  targetIndexedProof:boolean;
};
const truth=JSON.parse(readFileSync(
  'contracts/semantic-identity-independent-goldens.v1.json','utf8')) as Truth;
assert.equal(truth.contract,'parser-studio.semantic-identity-independent-goldens.v1');
assert.equal(truth.oracleOrigin,'INDEPENDENTLY_AUTHORED_EXPECTED_TARGETS');
assert.equal(truth.targetIndexedProof,false);
assert.ok(truth.cases.length>=25);
assert.equal(new Set(truth.cases.map(x=>x.id)).size,truth.cases.length);
function pathRecord(path:string,value:unknown):Record<string,unknown>{
  const nodes=path.split('.');
  const root:Record<string,unknown>={};
  let cursor=root;
  for(const segment of nodes.slice(0,-1)){
    const nested:Record<string,unknown>={};
    cursor[segment]=nested;cursor=nested;
  }
  cursor[nodes.at(-1)!]=value;
  return root;
}
function cloneExpectedDestination(caseItem:Golden):string|undefined{
  if(!caseItem.target)return undefined;
  const parts=caseItem.source.split('.');
  // Official root field identities and documented leaf aliases use
  // different paths, but both must match the independently recorded target.
  return policy.normalizationAliases[
    caseItem.source as keyof typeof policy.normalizationAliases] ??
    policy.normalizationAliases[
      parts.at(-1)! as keyof typeof policy.normalizationAliases];
}
let positive=0,negative=0;
for(const row of truth.cases){
  const fields={...pathRecord(row.source,row.value),...(row.context??{})};
  const existing=(row.existingDestinations??[]).map((target,i)=>({
    id:'occupied-'+i,source:'other_'+i,target,type:'string' as const,
  }));
  const browser=suggestNormalizationCandidates(fields,existing);
  const browserMatch=browser.find(x=>x.source===row.source);
  if(row.target===null){
    assert.equal(browserMatch,undefined,
      row.id+': browser must refuse unsupported or conflicting official target');
    negative++;
  }else{
    assert.equal(browserMatch?.target,row.target,row.id+': independent browser destination');
    assert.equal(browserMatch?.confidence,row.confidence,row.id+': browser confidence');
    assert.equal(browserMatch?.safeForBulk,row.safeForBulk,row.id+': browser auto safety');
    if(row.id!=='ordinary-non-nat-prefix' &&
       !row.source.startsWith('syslog_sd.') && row.source!=='srcport' &&
       row.source!=='dstport' && row.source!=='action' &&
       row.source!=='username' && row.source!=='url'){
      assert.equal(cloneExpectedDestination(row),row.target,
        row.id+': canonical semantic policy changed from independent truth');
    }
    positive++;
  }
  const hint=suggestFieldMappings({
    fieldNames:[row.source],existingDestinations:row.existingDestinations??[],
  });
  assert.equal(hint.autoApplied,false,row.id);
  assert.equal(hint.nativeVerified,false,row.id);
  assert.equal(hint.targetImportVerified,false,row.id);
  if(row.hint===null){
    assert.deepEqual(hint.unknownFields,[row.source],row.id+': unsupported name');
    assert.deepEqual(hint.suggestions,[],row.id+': no unverified hint');
  }else{
    assert.deepEqual(hint.unknownFields,[],row.id+': advisory candidate');
    assert.equal(hint.suggestions[0]?.proposedDestination,
      row.hintTarget??row.target??row.source,row.id+': independent backend destination');
    assert.equal(hint.suggestions[0]?.status,row.hint,row.id+': backend review state');
  }
}
// No policy computed expectation: independent expected destination is literal.
for(const sourcePair of [truth.competingSources.sources,
  [...truth.competingSources.sources].reverse()]){
  const hint=suggestFieldMappings({fieldNames:sourcePair});
  assert.equal(hint.suggestions.length,sourcePair.length);
  assert.ok(hint.suggestions.every(x=>
    x.proposedDestination===truth.competingSources.expectedTarget&&
    x.status===truth.competingSources.expectedBackendStatus));
  const rows=sourcePair.map(source=>({
    fields:pathRecord(source,'192.0.2.5'),
  }));
  const browser=suggestNormalizationCandidatesFromSuite(
    {events:rows} as unknown as SuiteResult,[]);
  assert.equal(browser.length,sourcePair.length);
  assert.ok(browser.every(x=>
    x.target===truth.competingSources.expectedTarget&&
    x.confidence===truth.competingSources.expectedBrowserConfidence&&
    x.safeForBulk===truth.competingSources.expectedSafeForBulk));
}
const sparse=truth.sparseEvent;
const events=[{fields:pathRecord(sparse.source,sparse.valueFirst)},
  {fields:{other_record:'ignored'}}];
const sparseBrowser=suggestNormalizationCandidatesFromSuite(
  {events} as unknown as SuiteResult,[]);
const sparseMatch=sparseBrowser.find(x=>x.source===sparse.source);
assert.equal(sparseMatch?.target,sparse.expectedTarget);
assert.equal(sparseMatch?.confidence,sparse.expectedBrowserConfidence);
assert.equal(sparseMatch?.safeForBulk,sparse.expectedSafeForBulk);
const sparseHint=suggestFieldMappings({fieldNames:[sparse.source]});
assert.equal(sparseHint.suggestions[0]?.status,sparse.expectedBackendStatus);
console.log('INDEPENDENT_SEMANTIC_ORACLE_PASS golden='+truth.cases.length+
  ' recognized='+positive+' refused='+negative+
  ' reversed_competitors=2 sparse_event=1 targetIndexedProof=false');
