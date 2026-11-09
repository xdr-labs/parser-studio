/**
 * Independent outcome comparison across the real browser candidate engine and
 * the backend read-only name-hints API. Human-review-only hints can intentionally
 * be weaker than value-evidenced auto candidates; they must never disagree on
 * reviewed source identity, or bypass target conflict/NAT rules.
 */
import assert from 'node:assert/strict';
import {suggestNormalizationCandidates} from '../../src/guided/normalizationCandidates';
import {suggestNormalizationCandidatesFromSuite} from '../../src/guided/normalizationCandidates';
import {suggestFieldMappings} from '../../backend/src/mapping-suggestions';
import policy from '../../runtime/multipass/semantic-policy.v1.json' with {type:'json'};
import type {SuiteResult} from '../../src/model';

const values:Readonly<Record<string,unknown>>={
  srcip:'192.0.2.12',dstip:'198.51.100.21',
  srcport:'594',dstport:'10400',action:'allow',
  username:'test-user',url:'https://example.test/safe',
};
function pathRecord(path:string,value:unknown):Record<string,unknown>{
  const parts=path.split('.');
  const root:Record<string,unknown>={};
  let node=root;
  for(const segment of parts.slice(0,-1)){
    const next:Record<string,unknown>={};
    node[segment]=next;node=next;
  }
  node[parts.at(-1)!]=value;
  return root;
}
let checked=0;
for(const source of policy.advisoryNameOnlySources){
  const canonical=policy.normalizationAliases[
    source as keyof typeof policy.normalizationAliases];
  // Advisory-only extensions are deliberately NOT asserted as browser
  // evidence. They remain weaker than the official browser source policy.
  if(!canonical)continue;
  const value=values[canonical];
  assert.notEqual(value,undefined,source);
  const browser=suggestNormalizationCandidates(pathRecord(source,value),[]);
  const advisory=suggestFieldMappings({fieldNames:[source]});
  const browserMatch=browser.find(x=>x.source===source);
  assert.ok(browserMatch,'browser source identity missing: '+source);
  assert.equal(browserMatch.target,canonical,'browser approved target: '+source);
  assert.equal(advisory.unknownFields.length,0,'backend identity dropped: '+source);
  assert.equal(advisory.suggestions[0]?.proposedDestination,canonical,
    'backend source identity diverged: '+source);
  assert.equal(advisory.suggestions[0]?.status,'REVIEW_REQUIRED',
    'backend hint must never auto-apply: '+source);
  assert.equal(advisory.autoApplied,false);
  checked++;
}
assert.ok(checked>=20,'shared semantic positive coverage regressed: '+checked);

const nestedPort='syslog_sd.element_1.params.source-port';
const nestedDest='syslog_sd.element_1.params.destination-port';
const multiEvents={events:[
  {fields:{syslog_sd:{element_1:{params:{
    'source-port':'594','destination-port':'10400'}}}}},
  {fields:{syslog_sd:{element_1:{params:{
    'source-port':'37233','destination-port':'161'}}}}},
]} as unknown as SuiteResult;
const multi=suggestNormalizationCandidatesFromSuite(multiEvents,[]);
for(const [source,target] of [[nestedPort,'srcport'],[nestedDest,'dstport']] as const){
  assert.equal(multi.find(x=>x.source===source)?.target,target);
  const hint=suggestFieldMappings({fieldNames:[source]});
  assert.equal(hint.suggestions[0]?.proposedDestination,target);
  assert.equal(hint.suggestions[0]?.status,'REVIEW_REQUIRED');
}
// Null/invalid values never allow bulk approval in the browser, regardless
// of the backend's deliberately value-free human-only hint.
const invalid=suggestNormalizationCandidates({'source-port':'65536'},[]);
assert.equal(invalid.find(x=>x.source==='source-port')?.safeForBulk,false);
assert.equal(suggestFieldMappings({fieldNames:['source-port']}).autoApplied,false);

for(const source of [
  'nat.source-port','post_nat.source-port','translated.destination-port',
  'syslog_sd.nat.destination-port','syslog_sd.pre-nat.source-port',
]){
  assert.equal(suggestNormalizationCandidates(pathRecord(source,'594'),[])
    .some(x=>x.source===source),false,'browser NAT semantics '+source);
  const hint=suggestFieldMappings({fieldNames:[source]});
  assert.deepEqual(hint.suggestions,[],'backend NAT semantics '+source);
  assert.deepEqual(hint.unknownFields,[source]);
}
for(const existing of ['srcip','srcip.vendor','srcip.system.subfield']){
  const hint=suggestFieldMappings({fieldNames:['src_ip'],existingDestinations:[existing]});
  assert.equal(hint.suggestions[0]?.status,existing==='srcip'
    ?'EXISTING_MAPPING':'DESTINATION_CONFLICT');
  assert.equal(suggestNormalizationCandidates({src_ip:'192.0.2.1'},[
    {id:'existing',source:'other',target:existing,type:'ip'},
  ]).length,0);
}
// Same destination from two independent event fields never silently picks a
// winner, even when their event order is reversed.
for(const sourcePair of [['src_ip','source.ip'],['source.ip','src_ip']]){
  const hint=suggestFieldMappings({fieldNames:sourcePair});
  assert.equal(hint.suggestions.every(h=>h.status==='DESTINATION_CONFLICT'),true);
  const events=sourcePair.map(src=>({fields:pathRecord(src,'192.0.2.1')}));
  const result=suggestNormalizationCandidatesFromSuite(
    {events} as unknown as SuiteResult,[]);
  assert.equal(result.every(x=>!x.safeForBulk),true);
}
console.log('MAPPING_CROSS_CONSUMER_PARITY_PASS canonical='+checked+
  ' nested=2 nat=5 collisions=3 multi_event=2 review_only=true');
