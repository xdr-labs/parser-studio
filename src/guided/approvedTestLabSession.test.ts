import { describe, expect, it, vi } from 'vitest';
import type { BackendCapabilities } from './backendCapabilities';
import {
  assertApprovedSessionReady, startApprovedSyntheticSession,
  fetchApprovedSessionStatus, controlApprovedSession, renewApprovedSession,
  changeApprovedSessionRate,extendApprovedSessionQuota,reconcileApprovedSession,
} from './approvedTestLabSession';

const testLab = {
  offlineJsonPreview:true,requiresBackendPreviewAuthorization:true,
  liveSensorSenderEnabled:true,
  trustedSinkSessionControlAvailable:true,
  sessionControlRequiresBackendAuthorization:true,
  sessionMaxRatePerSecond:5,sessionMaxLeaseMs:900000,
  sessionMaxAdditionalEventsPerRenewal:3000,sessionMaxCumulativeEvents:300000,
  sessionRenewalRequiresSeparateApproval:true,
  sessionDurableAcrossRestart:false,
  serverInjectedUdpTcpSinkAvailable:true,
  sinkRequiresIpLiteralAllowlist:true,
  sinkRequiresPerDeliveryPolicyAndAudit:true,
  sensorIngestVerified:false,runtimeParsingVerified:false,
};
const ready={testLab} as unknown as BackendCapabilities;
const runId='test_run_'+'a'.repeat(32);
const status={
  runId,state:'RUNNING',sentCount:0,nextSequence:0,
  replayMode:'single',sampleFamilyCount:1,ratePerSecond:2,
  maxEvents:100,leaseExpiresAt:'2026-10-12T05:01:00.000Z',
  lastSentAt:null,errorCode:null,
  parserLifecycleNotModified:true,realSensorVerified:false,
  runtimeParsingVerified:false,sensorIngestVerified:false,
};
const fake=(value:unknown,httpStatus=200)=>vi.fn(async()=>({
  status:httpStatus,json:async()=>value,
})) as unknown as typeof fetch;

describe('explicit owner-approved Test Lab session UI client, never default sensor start',()=>{
  it('refuses default disabled backend or missing trusted authorization and audit policy',()=>{
    expect(()=>assertApprovedSessionReady(ready)).not.toThrow();
    for(const value of [
      {...testLab,liveSensorSenderEnabled:false},
      {...testLab,sessionControlRequiresBackendAuthorization:false},
      {...testLab,serverInjectedUdpTcpSinkAvailable:false},
      {...testLab,sinkRequiresIpLiteralAllowlist:false},
      {...testLab,sinkRequiresPerDeliveryPolicyAndAudit:false},
      {...testLab,sessionRenewalRequiresSeparateApproval:false},
      {...testLab,sessionDurableAcrossRestart:true},
      {...testLab,sensorIngestVerified:true},
      {...testLab,sessionMaxRatePerSecond:100},
    ])expect(()=>assertApprovedSessionReady({testLab:value} as BackendCapabilities)).toThrow();
  });

  it('starts only a fixed synthetic event after approval; exact bounded lease and marker, no DP keys/real sample',async()=>{
    const request=fake(status);
    const returned=await startApprovedSyntheticSession('approved-test-session',2,ready,request);
    expect(returned).toMatchObject({runId,state:'RUNNING',sentCount:0,realSensorVerified:false});
    const [url,init]=(request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/sessions/start');
    expect(init).toMatchObject({method:'POST',cache:'no-store',credentials:'same-origin'});
    const body=JSON.parse(init.body);
    expect(body.approvalId).toBe('approved-test-session');
    expect(body).toMatchObject({
      ratePerSecond:2,leaseMs:60000,maxEvents:100,
      sample:{
        format:'json',seed:42,sequence:0,timestampField:'time',
        runMarkerField:'test.run_id',
        variableFields:[{path:'src_ip',kind:'ipv4'},{path:'username',kind:'username'},{path:'url',kind:'url'}],
      },
    });
    expect(body.sample.source).toContain('192.0.2.10');
    expect(body.sample.source).toContain('https://example.invalid/synthetic');
    for(const sensitive of ['198.51.100.21','API_KEY','PRIVATE_USER','sensorIp','dpUrl','tenant','targetHost']){
      expect(JSON.stringify(body)).not.toContain(sensitive);
    }
  });

  it('only safe status GET uses one authenticated runId, no sample in URL',async()=>{
    const request=fake({...status,state:'PAUSED',sentCount:7,nextSequence:7});
    const s=await fetchApprovedSessionStatus(runId,request);
    expect(s).toMatchObject({state:'PAUSED',sentCount:7});
    const [url,init]=(request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/sessions/status?runId='+runId);
    expect(init).toMatchObject({method:'GET',credentials:'same-origin'});
    expect(init.body).toBeUndefined();
  });

  it.each(['pause','resume','stop'] as const)('uses only the runId for %s, no automatic start or renewal',async action=>{
    const response={...status,state:action==='pause'?'PAUSED':action==='stop'?'STOPPED':'RUNNING'};
    const request=fake(response);
    expect((await controlApprovedSession(runId,action,request)).state).toBe(response.state);
    const [url,init]=(request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/sessions/'+action);
    expect(JSON.parse(init.body)).toEqual({runId});
  });

  it('rate adjustment requires independent approval and posts metadata only to an existing run',async()=>{
    const request=fake({...status,ratePerSecond:0.2});
    const applied=await changeApprovedSessionRate(
      status as import('./approvedTestLabSession').ApprovedTestLabStatus,
      'rate-approved-2026',0.2,request);
    expect(applied.ratePerSecond).toBe(0.2);
    expect(applied.maxEvents).toBe(100);
    expect(applied.realSensorVerified).toBe(false);
    const [url,init]=(request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/sessions/rate');
    expect(init).toMatchObject({method:'POST',cache:'no-store',credentials:'same-origin'});
    const data=JSON.parse(init.body);
    expect(data).toEqual({runId,approvalId:'rate-approved-2026',ratePerSecond:0.2});
    for(const privateValue of ['sample','apiKey','sensorIp','dpUrl','rawLog','PRIVATE_USER']){
      expect(init.body).not.toContain(privateValue);
    }
  });

  it('denies unchanged, unsupported, unapproved, stopped and original-gaps rate changes locally',async()=>{
    const request=fake({...status,ratePerSecond:5});
    const active=status as import('./approvedTestLabSession').ApprovedTestLabStatus;
    for(const attempt of [
      {row:active,approval:'bad',rate:5},
      {row:active,approval:'rate-approved-2026',rate:2},
      {row:active,approval:'rate-approved-2026',rate:7},
      {row:{...active,state:'STOPPED'},approval:'rate-approved-2026',rate:5},
      {row:{...active,replayMode:'original-gaps'},approval:'rate-approved-2026',rate:5},
    ]){
      await expect(changeApprovedSessionRate(
        attempt.row as typeof active,attempt.approval,attempt.rate as 5,request)).rejects.toThrow();
    }
    expect(request).not.toHaveBeenCalled();
  });

  it('rejects rate-change replies that are altered, unverified, change quota or reference other sessions',async()=>{
    const active=status as import('./approvedTestLabSession').ApprovedTestLabStatus;
    const expected={...status,ratePerSecond:5};
    for(const response of [
      {...expected,ratePerSecond:1},
      {...expected,runId:'test_run_'+'f'.repeat(32)},
      {...expected,realSensorVerified:true},
      {...expected,maxEvents:999},
      {...expected,leaseExpiresAt:'2026-10-12T05:02:00.000Z'},
      {...expected,token:'CUSTOMER_SECRET'},
    ]){
      await expect(changeApprovedSessionRate(active,'rate-approved-2026',5,fake(response))).rejects.toThrow();
    }
  });

  it('does not treat 403 or 409 as an authorized rate change or claim a new run',async()=>{
    const active=status as import('./approvedTestLabSession').ApprovedTestLabStatus;
    for(const code of [403,409,422,503]){
      const request=fake({error:'TESTLAB_RATE_CHANGE_DENIED',rawEvent:'CUSTOMER_SECRET'},code);
      await expect(changeApprovedSessionRate(active,'rate-approved-2026',5,request))
        .rejects.toThrow(String(code));
      expect((request as unknown as ReturnType<typeof vi.fn>).mock.calls).toHaveLength(1);
    }
  });

  it('never reactivates a server-confirmed terminal run after a delayed older update',()=>{
    const old=status as import('./approvedTestLabSession').ApprovedTestLabStatus;
    const stopped={...old,state:'STOPPED' as const};
    const expired={...old,state:'EXPIRED' as const};
    const unrelated={...old,runId:'test_run_'+'b'.repeat(32)};
    expect(reconcileApprovedSession(stopped,old)).toBe(stopped);
    expect(reconcileApprovedSession(expired,old)).toBe(expired);
    expect(reconcileApprovedSession(old,stopped)).toBe(stopped);
    expect(reconcileApprovedSession(stopped,unrelated)).toBe(unrelated);
  });

  it('extends only a separately approved live owned run by exactly 60 seconds and 20 events',async()=>{
    const active={...status,state:'RUNNING',
      leaseExpiresAt:'2099-01-01T00:00:00.000Z'};
    const expected={...active,maxEvents:120,
      leaseExpiresAt:'2099-01-01T00:01:00.000Z'};
    const requester=fake(expected);
    const done=await extendApprovedSessionQuota(
      active as import('./approvedTestLabSession').ApprovedTestLabStatus,
      'new-approval-extension',requester,
      ()=>Date.parse('2098-01-01T00:00:00.000Z'));
    expect(done.maxEvents).toBe(120);
    const [url,options]=(requester as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/sessions/renew');
    expect(JSON.parse(options.body)).toEqual({
      runId,approvalId:'new-approval-extension',leaseMs:60000,additionalEvents:20,
    });
    expect(options.body).not.toContain('rawLog');
    expect(options.body).not.toContain('sensorIp');
  });

  it('blocks expired, stopped, quota-exhausted or manipulated renewals before showing quota success',async()=>{
    const live={...status,state:'RUNNING',leaseExpiresAt:'2099-01-01T00:00:00.000Z'};
    const now=()=>Date.parse('2098-01-01T00:00:00.000Z');
    const requester=fake({...live,maxEvents:120,leaseExpiresAt:'2099-01-01T00:01:00.000Z'});
    for(const value of [
      {...live,state:'EXPIRED'}, {...live,leaseExpiresAt:'2097-01-01T00:00:00.000Z'},
      {...live,maxEvents:300000},
    ]){
      await expect(extendApprovedSessionQuota(
        value as import('./approvedTestLabSession').ApprovedTestLabStatus,'fresh-renewal',requester,now)).rejects.toThrow();
    }
    expect(requester).not.toHaveBeenCalled();
    const unsafe=[
      {...live,maxEvents:119,leaseExpiresAt:'2099-01-01T00:01:00.000Z'},
      {...live,maxEvents:120,leaseExpiresAt:live.leaseExpiresAt},
      {...live,maxEvents:120,leaseExpiresAt:'2099-01-01T00:01:00.000Z',
        ratePerSecond:5},
      {...live,maxEvents:120,leaseExpiresAt:'2099-01-01T00:01:00.000Z',
        state:'STOPPED'},
      {...live,maxEvents:120,leaseExpiresAt:'2099-01-01T00:01:00.000Z',
        rawLog:'PRIVATE_NOT_ALLOWED'},
    ];
    for(const response of unsafe){
      await expect(extendApprovedSessionQuota(
        live as import('./approvedTestLabSession').ApprovedTestLabStatus,'fresh-renewal',fake(response),now)).rejects.toThrow();
    }
  });

  it('requires a separate new owner approval for any additional time or event quota',async()=>{
    const request=fake({...status,maxEvents:120});
    await renewApprovedSession(runId,'renewal-approved',60000,20,request);
    const [url,init]=(request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/sessions/renew');
    expect(JSON.parse(init.body)).toEqual({
      runId,approvalId:'renewal-approved',leaseMs:60000,additionalEvents:20,
    });
  });

  it.each([
    '', '../evil', 'password@unsafe','short',' '.repeat(10),
  ])('cannot submit unsafe approval id %s',async approval=>{
    const req=fake(status);
    await expect(startApprovedSyntheticSession(approval,1,ready,req)).rejects.toThrow();
    expect(req).not.toHaveBeenCalled();
  });
  it('rejects out-of-bound rates/renew quotas and malformed runIDs without any backend calls',async()=>{
    const req=fake(status);
    await expect(startApprovedSyntheticSession('approval-ready',10 as 1,ready,req)).rejects.toThrow();
    await expect(fetchApprovedSessionStatus('not-a-run-id',req)).rejects.toThrow();
    await expect(controlApprovedSession('wrong','stop',req)).rejects.toThrow();
    await expect(renewApprovedSession(runId,'approval-ready',900001,10,req)).rejects.toThrow();
    await expect(renewApprovedSession(runId,'approval-ready',60000,3001,req)).rejects.toThrow();
    expect(req).not.toHaveBeenCalled();
  });
  it.each([
    {...status,realSensorVerified:true},
    {...status,runtimeParsingVerified:true},
    {...status,sensorIngestVerified:true},
    {...status,parserLifecycleNotModified:false},
    {...status,runId:'test_run_'+'b'.repeat(32)},
    {...status,state:'OWNED_BY_ATTACKER'},
    {...status,rawEvent:'private customer data'},
    {...status,sentCount:200},
    {...status,sampleFamilyCount:0},
    {...status,leaseExpiresAt:'not-a-date'},
  ])('refuses dangerous or inconsistent backend session status claims',async body=>{
    await expect(fetchApprovedSessionStatus(runId,fake(body))).rejects.toThrow();
  });
  it.each([401,403,404,409,422,429,503])('denied server status %s cannot be presented as session success',async code=>{
    await expect(fetchApprovedSessionStatus(runId,fake({error:'DENIED'},code))).rejects.toThrow(String(code));
  });
});
