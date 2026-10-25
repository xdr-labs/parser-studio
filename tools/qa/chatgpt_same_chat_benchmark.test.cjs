'use strict';
const test=require('node:test');
const assert=require('node:assert/strict');
const {sha,cases,score,captureReceipt}=require('./chatgpt_same_chat_benchmark.cjs');
const prepared=cases();

test('simulated ChatGPT response evidence never accepts external provider provenance',()=>{
 const prompt='one public sample only',response='{"contract":"parser-studio.recipe.v0.2"}';
 const capture={origin:'SAME_CHAT_GPT6',model:'GPT-6',recordedAt:'2026-10-25T19:00:00+09:00',
  replyMode:'MODEL_AUTHORED_NEW_GRAMMAR',promptSha256:sha(prompt),
  responseSha256:sha(response),
  operatorAttestation:'Selected or authored in current ChatGPT conversation; not independent provider inference'};
 assert.equal(captureReceipt(capture,response,prompt),true);
 assert.equal(captureReceipt({...capture,origin:'OPENAI_API'},response,prompt),false);
 assert.equal(captureReceipt({...capture,model:'chat-latest'},response,prompt),false);
 assert.equal(captureReceipt({...capture,replyMode:'BASELINE_REPRODUCED'},response,prompt),true);
 assert.equal(captureReceipt({...capture,replyMode:'INDEPENDENT_PROVIDER'},response,prompt),false);
 assert.equal(captureReceipt(capture,response+' ',prompt),false);
});

test('same-conversation scorer separates eight embedded baselines from two authored grammars',()=>{
 assert.equal(prepared.length,10);
 const result=Object.fromEntries(prepared.map(c=>[c.id,{
  state:'SUCCESS',attemptsConsumed:1,successAttempt:1,nativeDraftCreated:true,
  nativeRubyPassed:true,goldenSourceValueMatches:c.goldenSourceValues.length}]));
 result['aws_cloudtrail_consolelogin']={state:'PARTIAL_NATIVE_VALUES',
  attemptsConsumed:1,nativeDraftCreated:true,nativeRubyPassed:false,
  goldenSourceValueMatches:7};
 result['f5-064']={...result['f5-064'],attemptsConsumed:2,successAttempt:2};
 const s=score(prepared,result);
 assert.equal(s.evidence,'SAME_CONVERSATION_GPT6_WITH_EIGHT_BASELINE_REPRODUCTIONS');
 assert.equal(s.externalIndependentChatGPTVerified,false);
 assert.equal(s.providerCompletionCount,0);
 assert.equal(s.planned,10);
 assert.equal(s.completed,10);
 assert.equal(s.nativeDrafts,10);
 assert.equal(s.baselineReproduced,8);
 assert.equal(s.newGrammarCases,2);
 assert.equal(s.firstCount,8);
 assert.equal(s.secondCumulativeCount,9);
 assert.equal(s.thirdCumulativeCount,9);
 assert.equal(s.lexicalSourceMatches,76);
 assert.equal(s.lexicalSourceTotal,77);
});

test('simulation rate is null if a case lacks finished source-verified native outcome',()=>{
 const s=score(prepared,{});
 assert.equal(s.completed,0);
 assert.equal(s.firstRate,null);
 assert.equal(s.secondCumulativeRate,null);
 assert.equal(s.thirdCumulativeRate,null);
 assert.equal(s.providerCompletionCount,0);
});
