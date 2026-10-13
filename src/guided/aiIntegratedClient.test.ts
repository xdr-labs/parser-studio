import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildReviewableRecipe} from './parserRecipeV2';
import {probeAIReviewAvailability,deriveAIMetadata,
 requestAIReviewedCandidate,type AIProviderCapability} from './aiIntegratedClient';

const raw=[
 '{"action":"deny","src_ip":"192.0.2.15","dst_port":443,"user":"PRIVATE_ALICE"}',
 '{"action":"allow","src_ip":"203.0.113.6","dst_port":22,"user":"SECRET_BOB"}',
].join('\n');
const draft={...createDraft(),format:'json' as const};
const cap:AIProviderCapability={
 contract:'parser-studio.ai-capabilities.v0.1',
 available:true,providerId:'synthetic-test-provider',modelId:'safe-simulated-model',
 externalTransfer:'METADATA_ONLY',noRawLogs:true,
 requiresExplicitConfirmation:true,requiresBudgetConfirmation:true,
 auditBeforeProvider:true,requiresServerBudgetReservation:true,
 maxOutputTokens:512,userApprovalRequired:true,
 nativeParserVerified:false,targetImportVerified:false,
};
const response=(value:unknown,status=200)=>new Response(JSON.stringify(value),{
 status,headers:{'content-type':'application/json'},
});
describe('P1-AP6 explicitly opted-in private integrated AI proposal',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('probes data-free capability only and rejects false native claims',async()=>{
  const requester=vi.fn(async(url:RequestInfo|URL,init?:RequestInit)=>{
   expect(String(url)).toBe('/api/v1/parser-pairs/ai/v0.1/capabilities');
   expect(init?.method).toBe('GET');
   expect(init?.body).toBeUndefined();
   return response(cap);
  });
  expect(await probeAIReviewAvailability(requester as typeof fetch))
   .toMatchObject({status:'AVAILABLE',capability:{maxOutputTokens:512}});
  expect(requester).toHaveBeenCalledTimes(1);
  expect(await probeAIReviewAvailability((vi.fn(async()=>response({error:'DISABLED'},403))) as typeof fetch))
   .toEqual({status:'DISABLED'});
  for(const change of [
   {...cap,nativeParserVerified:true},
   {...cap,noRawLogs:false},
   {...cap,maxOutputTokens:2500},
   {...cap,apiKey:'DO_NOT_ECHO'},
  ])await expect(probeAIReviewAvailability(vi.fn(async()=>response(change)) as typeof fetch))
   .rejects.toThrow('not be verified');
 });
 it('generates only verified metadata census, SHA and benign draft ID without original source values',async()=>{
  const sample=preview(raw,draft);
  const meta=await deriveAIMetadata(raw,draft,sample);
  expect(meta).toMatchObject({
   contract:'parser-studio.ai-metadata.v0.1',
   projectId:'draft-demo_firewall',sampleEvents:2,
   sourceFormat:'json',bodyFormat:'json',unsupported:0,
   families:[{envelope:'none',body:'json',count:2}],
  });
  expect(meta.sampleSha256).toMatch(/^[0-9a-f]{64}$/);
  for(const sensitive of ['PRIVATE_ALICE','SECRET_BOB','192.0.2.15','src_ip','user'])
   expect(JSON.stringify(meta)).not.toContain(sensitive);
 });
 it('requires two explicit user consents and validates every returned recipe field before display',async()=>{
  const sample=preview(raw,draft);
  const recipe=await buildReviewableRecipe(raw,draft,sample);
  if(!recipe.ok)throw Error('Expected safe v0.2 draft');
  const payload={
   contract:'parser-studio.ai-reviewed-candidate.v0.1',
   recipe:recipe.recipe,externalTransfer:'METADATA_ONLY',
   usage:{outputTokens:215,reservedOutputTokens:512},
   userApprovalRequired:true,nativeParserVerified:false,
   targetImportVerified:false,rawLogsIncluded:false,
   providerId:cap.providerId,modelId:cap.modelId,
  };
  const requester=vi.fn(async(url:RequestInfo|URL,init?:RequestInit)=>{
   expect(String(url)).toBe('/api/v1/parser-pairs/ai/v0.1/review');
   expect(init?.method).toBe('POST');
   expect(init?.credentials).toBe('same-origin');
   const body=String(init?.body??'');
   expect(body).toContain('confirmedExternalTransfer');
   expect(body).not.toContain('192.0.2.15');
   expect(body).not.toContain('PRIVATE_ALICE');
   expect(body).not.toContain('SECRET_BOB');
   expect(body).not.toContain('apiKey');
   return response(payload);
  });
  await expect(requestAIReviewedCandidate(raw,draft,sample,cap,false,true,requester as typeof fetch))
   .rejects.toThrow('Separate external metadata');
  await expect(requestAIReviewedCandidate(raw,draft,sample,cap,true,false,requester as typeof fetch))
   .rejects.toThrow('Separate external metadata');
  expect(requester).not.toHaveBeenCalled();
  const accepted=await requestAIReviewedCandidate(raw,draft,sample,cap,true,true,requester as typeof fetch);
  expect(accepted).toEqual(payload);
  expect(accepted.nativeParserVerified).toBe(false);
  expect(accepted.targetImportVerified).toBe(false);
  expect(requester).toHaveBeenCalledTimes(1);
  for(const change of [
   {...payload,nativeParserVerified:true},
   {...payload,rawLogsIncluded:true},
   {...payload,providerId:'forged'},
   {...payload,recipe:{...recipe.recipe,nativeVerified:true}},
   {...payload,recipe:{...recipe.recipe,sample:{...recipe.recipe.sample,sha256:'a'.repeat(64)}}},
   {...payload,usage:{outputTokens:513,reservedOutputTokens:512}},
   {...payload,rawEvent:'PRIVATE_SECRET'},
  ])await expect(requestAIReviewedCandidate(raw,draft,sample,cap,true,true,
    vi.fn(async()=>response(change)) as typeof fetch)).rejects.toThrow('not be verified');
 });
 it('stale browser event identity and unsupported source do not produce AI requests',async()=>{
  const sample=preview(raw,draft);
  const requester=vi.fn(async()=>response({ok:true}));
  await expect(requestAIReviewedCandidate(raw+'\nPRIVATE_OTHER_EVENT',draft,sample,
   cap,true,true,requester as typeof fetch)).rejects.toThrow('not be verified');
  const unknownDraft=createDraft();
  await expect(requestAIReviewedCandidate('PRIVATE_OTHER_EVENT',unknownDraft,
   preview('PRIVATE_OTHER_EVENT',unknownDraft),cap,true,true,requester as typeof fetch))
   .rejects.toThrow('not be verified');
  expect(requester).not.toHaveBeenCalled();
 });
});
