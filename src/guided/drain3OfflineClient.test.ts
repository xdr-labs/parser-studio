import {describe,it,expect,vi} from 'vitest';
import {checkPrivateDrain3Availability,runPrivateDrain3Review} from './drain3OfflineClient';

const raw=[
 'ERROR LOGIN from 192.0.2.11 user PRIVATE_ALICE',
 'ERROR LOGIN from 192.0.2.12 user PRIVATE_BOB',
];
const held=['ERROR LOGIN from 192.0.2.15 user PRIVATE_CAROL'];
const capability={
 contract:'parser-studio.drain3-capabilities.v0.1',
 available:true,requiresExplicitConfirmation:true,engine:'Drain3 0.9.11',
 sameOriginRawSourceTransfer:true,noPersistence:true,maxTrainingEvents:500,
 maxHoldoutEvents:500,nativeParserVerified:false,targetImportVerified:false,
 noExternalLlmCalls:true,
};
const result={
 contract:'parser-studio.drain3-reviewed-hints.v0.1',
 engine:'Drain3 0.9.11',sourceCount:2,accounted:2,holdoutCount:1,
 holdoutMatched:1,groupCount:1,
 groups:[{clusterId:'cluster-1',shape:'ERROR LOGIN <WORD> <VAR> USER <VAR>',
  trainingCount:2,trainingLineNumbers:[1,2],holdoutMatches:1,reviewOnly:true}],
 persisted:false,sourceValuesIncluded:false,nativeParserVerified:false,
 targetImportVerified:false,
};
const stub=(data:unknown,status=200)=>vi.fn(async()=>new Response(JSON.stringify(data),{
 status,headers:{'content-type':'application/json'},
})) as unknown as typeof fetch;
describe('P1 AP5 explicit offline server Drain3 client',()=>{
 it('checks capability with GET only, no raw source transmitted before consent',async()=>{
  const fetcher=stub(capability);
  expect(await checkPrivateDrain3Availability(fetcher)).toBe('AVAILABLE');
  const [url,opts]=(fetcher as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
  expect(url).toBe('/api/v1/parser-pairs/patterns/drain3/capabilities');
  expect(opts).toMatchObject({method:'GET',credentials:'same-origin',cache:'no-store'});
  expect(opts.body).toBeUndefined();
  expect(await checkPrivateDrain3Availability(stub({error:'DRAIN3_DISABLED'},403)))
   .toBe('DISABLED');
 });
 it('requires checked consent and refuses input before any POST',async()=>{
  const never=stub(result);
  await expect(runPrivateDrain3Review(raw,held,false,never))
   .rejects.toThrow('Explicit consent');
  await expect(runPrivateDrain3Review(['PRIVATE\nSECRET'],held,true,never))
   .rejects.toThrow('not verified');
  await expect(runPrivateDrain3Review(Array(501).fill('PRIVATE'),held,true,never))
   .rejects.toThrow('not verified');
  await expect(runPrivateDrain3Review(raw,['x'.repeat(2100)],true,never))
   .rejects.toThrow('not verified');
  expect(never).not.toHaveBeenCalled();
 });
 it('runs only user-confirmed same-origin bounded raw transfer; verifies redacted result',async()=>{
  const fetcher=stub(result);
  const data=await runPrivateDrain3Review(raw,held,true,fetcher);
  expect(data).toEqual(result);
  const [uri,options]=(fetcher as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
  expect(uri).toBe('/api/v1/parser-pairs/patterns/drain3');
  expect(options.method).toBe('POST');
  expect(options.credentials).toBe('same-origin');
  const payload=JSON.parse(options.body as string);
  expect(payload.confirmed).toBe(true);
  expect(payload.training).toEqual(raw);
  expect(payload.holdout).toEqual(held);
  expect(options.body).not.toContain('apiKey');
  for(const sensitive of ['PRIVATE_ALICE','PRIVATE_BOB','PRIVATE_CAROL','192.0.2.11'])
   expect(JSON.stringify(data)).not.toContain(sensitive);
  expect(data.nativeParserVerified).toBe(false);
  expect(data.targetImportVerified).toBe(false);
 });
 it('refuses forged capabilities and returned raw customer values even from a 200 backend',async()=>{
  for(const bad of [
   {...capability,nativeParserVerified:true},
   {...capability,available:false},
   {...capability,noPersistence:false},
   {...capability,privateCredential:'SECRET'},
  ])await expect(checkPrivateDrain3Availability(stub(bad)))
   .rejects.toThrow('not verified');
  for(const bad of [
    {...result,nativeParserVerified:true},
    {...result,groups:[{...result.groups[0],shape:'PRIVATE_ALICE'}]},
    {...result,groups:[{...result.groups[0],trainingLineNumbers:[1,1]}]},
    {...result,groups:[{...result.groups[0],raw:'PRIVATE_CAROL'}]},
    {...result,holdoutMatched:9},
  ])await expect(runPrivateDrain3Review(raw,held,true,stub(bad)))
   .rejects.toThrow('not verified');
  await expect(runPrivateDrain3Review(raw,held,true,stub({error:'DENIED'},403)))
   .rejects.toThrow('unavailable or unauthorized');
 });
});
