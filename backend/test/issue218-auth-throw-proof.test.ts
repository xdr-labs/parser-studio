import test from 'node:test';
import assert from 'node:assert/strict';
import type {AddressInfo} from 'node:net';
import {createBackendServer} from '../src/http.js';
import {AIReviewGateway} from '../src/ai-review-gateway.js';
import {TargetApplyMockGateway} from '../src/target-apply-bff.js';

test('Issue #218 actual HTTP: provider outage denies without crashing; unexpected gateway failure is contained', async()=>{
  const secret='PRIVATE_AUTH_PROVIDER_OUTAGE';
  const fail=async()=>{throw Error(secret)};
  const ai=new AIReviewGateway({
    providerId:'synthetic-local',modelId:'test-review',maxOutputTokens:100,
    authorize:fail,ledger:{reserve:async()=> 'synthetic',settle:async()=>{}},
    audit:async()=>{},provider:async()=>{throw Error('UNEXPECTED_AI_EGRESS')},
  });
  const mock=new TargetApplyMockGateway({
    mode:'MOCK_ONLY',authorize:fail,
    resolveRevision:async()=>null,getCoordinator:async()=>null,audit:async()=>{},
  });
  const server=createBackendServer({aiReviewGateway:ai,targetApplyMockGateway:mock});
  await new Promise<void>(resolve=>server.listen(0,'127.0.0.1',resolve));
  try{
    const base='http://127.0.0.1:'+(server.address() as AddressInfo).port;
    for(const [path,method] of [
      ['/api/v1/parser-pairs/ai/v0.1/capabilities','GET'],
      ['/api/v1/parser-pairs/ai/v0.1/review','POST'],
      ['/api/v1/parser-pairs/target/apply/status','GET'],
      ['/api/v1/parser-pairs/target/apply','POST'],
    ] as const){
      const response=await fetch(base+path,{method,headers:method==='POST'?{'content-type':'application/json'}:undefined,body:method==='POST'?'{}':undefined});
      // The existing gateway adapters intentionally catch underlying provider
      // errors and return a null actor; keep that stable 403 behavior.
      assert.equal(response.status,403,path);
      assert.equal((await response.text()).includes(secret),false,path);
    }
    // A future gateway implementation may reject its public method directly.
    // The HTTP boundary must still respond and keep serving other requests.
    ai.authorize=fail;
    mock.authenticate=fail;
    for(const [path,method] of [
      ['/api/v1/parser-pairs/ai/v0.1/capabilities','GET'],
      ['/api/v1/parser-pairs/ai/v0.1/review','POST'],
      ['/api/v1/parser-pairs/target/apply/status','GET'],
      ['/api/v1/parser-pairs/target/apply','POST'],
    ] as const){
      const response=await fetch(base+path,{method,
        headers:method==='POST'?{'content-type':'application/json'}:undefined,
        body:method==='POST'?'{}':undefined});
      assert.equal(response.status,503,path);
      const result=await response.text();
      assert.equal(result.includes(secret),false,path);
    }
    ai.authorize=async()=>({tenant:'synthetic_tenant',actorId:'synthetic_owner'});
    ai.capabilities=()=>{throw Error(secret)};
    const unexpected=await fetch(base+'/api/v1/parser-pairs/ai/v0.1/capabilities');
    assert.equal(unexpected.status,503);
    assert.equal((await unexpected.text()).includes(secret),false);
    const health=await fetch(base+'/health');
    assert.equal(health.status,200);
    assert.equal((await health.json() as {status:string}).status,'ok');
  }finally{
    await new Promise<void>(resolve=>server.close(()=>resolve()));
  }
});
