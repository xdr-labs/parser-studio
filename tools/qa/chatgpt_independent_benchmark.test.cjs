'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {sha,cases,score,providerReceipt,flatten}=require('./chatgpt_independent_benchmark.cjs');
const input=cases();

test('all ten single-log security cases have source fidelity, provenance and declared class',()=>{
 assert.equal(input.length,10);
 assert.equal(input.filter(c=>c.sampleClass==='VENDOR_DOCUMENTED').length,5);
 assert.equal(input.filter(c=>c.sampleClass==='VENDOR_DOCUMENTED_COMPACTED').length,2);
 assert.equal(input.filter(c=>c.sampleClass==='PROJECT_SYNTHETIC').length,3);
 assert.ok(input.some(c=>c.family==='EDR'));
 assert.ok(input.some(c=>c.family==='VPN'));
 assert.ok(input.some(c=>c.family==='WAF'));
 assert.ok(input.some(c=>c.family==='PROXY'));
 input.forEach(c=>{
  assert.equal(sha(c.rawSample),c.originalSha256);
  assert.equal(c.sampleCount,1);
  assert.equal(c.rawSample.trim().split(/\r?\n/).length,1);
  if(c.sampleClass==='VENDOR_DOCUMENTED_COMPACTED'){
   assert.equal(c.sourceTransformation,'DOCUMENTATION_JSON_PRETTY_PRINT_WHITESPACE_REMOVED');
   assert.equal(JSON.stringify(JSON.parse(c.rawSample)),c.rawSample);
   assert.match(c.publishedSourceSha256,/^[a-f0-9]{64}$/);
  }
  assert.ok(c.goldenSourceValues.every(g=>c.rawSample.includes(g.sourceValue)));
 });
});

test('no provider results means all model rates are unmeasured, not zero',()=>{
 const s=score(input,{});
 assert.equal(s.provenanceLevel,'NO_COMPLETE_INDEPENDENT_PROVIDER_EVIDENCE');
 assert.equal(s.completeCases,0);
 assert.equal(s.firstResponseSuccessRate,null);
 assert.equal(s.secondCumulativeSuccessRate,null);
 assert.equal(s.thirdCumulativeSuccessRate,null);
 assert.equal(s.sourceValueRecall,null);
 assert.equal(s.semanticAccuracy,null);
 assert.equal(s.nativeDraftCreationRate,null);
});

test('partially completed cases do not create an inflated success-rate denominator',()=>{
 const s=score(input,{[input[0].id]:{state:'SUCCESS',attemptsConsumed:1,independentProviderReceipts:1,
  nativeDraftCreated:true,nativeRubyPassed:true,successAttempt:1,goldenSourceValueMatches:2,sourcePreserved:true}});
 assert.equal(s.completeCases,1);
 assert.equal(s.firstResponseSuccessRate,null);
});

test('genuine bounded complete receipts allow cumulative first/second/third rates',()=>{
 const results={};
 input.forEach((c,i)=>{
  const success=i<6;
  const n=success?(i<2?1:i<4?2:3):3;
  results[c.id]={state:success?'SUCCESS':'FAIL_AFTER_3',
   attemptsConsumed:n,independentProviderReceipts:n,successAttempt:success?n:null,
   nativeDraftCreated:success,nativeRubyPassed:success,sourcePreserved:true,regressions:0,
   goldenSourceValueMatches:success?c.goldenSourceValues.length:0};
 });
 const s=score(input,results);
 assert.equal(s.completeCases,10);
 assert.equal(s.firstResponseSuccessRate,0.2);
 assert.equal(s.secondCumulativeSuccessRate,0.4);
 assert.equal(s.thirdCumulativeSuccessRate,0.6);
 assert.equal(s.nativeDraftCreationRate,0.6);
 assert.equal(s.originalPreservedRate,1);
 assert.equal(s.semanticAccuracy,null);
 const expected=input.reduce((n,c)=>n+c.goldenSourceValues.length,0);
 const matched=input.slice(0,6).reduce((n,c)=>n+c.goldenSourceValues.length,0);
 assert.equal(s.sourceValueRecall,matched/expected);
});

test('a success without real generated files is never model-quality PASS',()=>{
 const results=Object.fromEntries(input.map(c=>[c.id,{state:'SUCCESS',
  attemptsConsumed:1,independentProviderReceipts:1,nativeDraftCreated:false,successAttempt:1}]));
 const s=score(input,results);
 assert.equal(s.firstResponseSuccessRate,null);
});

test('web and API provider receipt require consistent immutable response/prompt hashes',()=>{
 const prompt='a source-locked prompt';
 const response='{"candidate":"model output"}';
 const base={origin:'CHATGPT_WEB_SIGNED_IN',recordedAt:'2026-10-25T00:00:00Z',
  model:'GPT-6',operatorAttestation:'Used signed-in ChatGPT directly',
  conversationUrl:'https://chatgpt.com/c/f7aa1234-aaaa-aaaa-aaaa-aaaaaaaaaaaa',
  promptSha256:sha(prompt),responseSha256:sha(response)};
 assert.equal(providerReceipt(base,response,prompt),true);
 assert.equal(providerReceipt({...base,responseSha256:'0'},response,prompt),false);
 assert.equal(providerReceipt({...base,conversationUrl:'https://evil.example/chat'},response,prompt),false);
 assert.equal(providerReceipt({...base,origin:'UNKNOWN'},response,prompt),false);
 assert.equal(providerReceipt({...base,origin:'OPENAI_API',completionId:'resp_abc'},response,prompt),true);
 assert.equal(providerReceipt({...base,origin:'OPENAI_API'},response,prompt),false);
});

test('golden extraction must not score the original source string as a parsed field',()=>{
 const preview=[{sourceLine:'allow src=192.0.2.1',extracted:{action:'allow'},normalized:{'custom.action':'allow'}}];
 const parsed=flatten(preview.flatMap(x=>[x.extracted,x.normalized]));
 assert.ok(parsed.includes('allow'));
 assert.ok(!parsed.includes('192.0.2.1'));
});

test('explicit semantic adjudication is required before reporting semantic accuracy',()=>{
 const results={};
 input.forEach(c=>results[c.id]={state:'SUCCESS',attemptsConsumed:1,
  independentProviderReceipts:1,nativeDraftCreated:true,nativeRubyPassed:true,successAttempt:1,
  sourcePreserved:true,goldenSourceValueMatches:c.goldenSourceValues.length,
  humanValidatedSemanticCorrect:c.goldenSourceValues.length,
  humanValidatedSemanticTotal:c.goldenSourceValues.length});
 const s=score(input,results);
 assert.equal(s.semanticAccuracy,1);
 assert.equal(s.sourceValueRecall,1);
});