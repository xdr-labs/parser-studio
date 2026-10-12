import { describe, expect, it, vi } from 'vitest';
import type { BackendCapabilities } from './backendCapabilities';
import {
  assertApprovedSessionReady, startApprovedSyntheticSession,
  fetchApprovedSessionStatus, controlApprovedSession, renewApprovedSession,
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
