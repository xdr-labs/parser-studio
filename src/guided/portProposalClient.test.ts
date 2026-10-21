import { describe, expect, it, vi } from 'vitest';
import { fetchParserPortProposal } from './portProposalClient';

const candidate={
  contract:'stellar-parser-listener-port-proposal.v0.1',
  recommendedPort:20000,source:'SUGGESTED',
  status:'INCOMPLETE_EVIDENCE',
  missingEvidence:['sensorBindings','localReservations'],
  occupiedPorts:[514,6801,20001],
  candidateOnly:true,deployableNow:false,
  verifiedIngestPort:false,sensorIngestPort:20000,needsFinalRecheck:true,
};
const fake=(body:unknown,status=200)=>vi.fn(async()=>({
  status,json:async()=>body,
})) as unknown as typeof fetch;

describe('backend-authorized, read-only provisional parser listener port proposals',()=>{
  it('fetches only safe metadata; never sends a DP URL, key or sample',async()=>{
    const request=fake(candidate);
    const result=await fetchParserPortProposal(undefined,request);
    expect(result).toMatchObject({
      recommendedPort:20000,candidateOnly:true,deployableNow:false,
      verifiedIngestPort:false,needsFinalRecheck:true,
      missingEvidence:['sensorBindings','localReservations'],
    });
    const [url,init]=(request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/stellar/legacy/port-proposal');
    expect(init).toMatchObject({method:'GET',cache:'no-store',credentials:'same-origin'});
    expect(init.body).toBeUndefined();
  });
  it('checks the explicitly typed receiver port without modifying a parser',async()=>{
    const response={...candidate,recommendedPort:6801,source:'USER_OVERRIDE',occupiedPorts:[514,20001],sensorIngestPort:6801};
    const request=fake(response);
    const result=await fetchParserPortProposal(6801,request);
    expect(result.recommendedPort).toBe(6801);
    const [url]=(request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/stellar/legacy/port-proposal?port=6801');
  });
  it('refuses occupied ports, false deployment readiness and forged completeness claims',async()=>{
    for(const broken of [
      {...candidate,recommendedPort:6801},
      {...candidate,deployableNow:true},
      {...candidate,candidateOnly:false},
      {...candidate,verifiedIngestPort:true},
      {...candidate,sensorIngestPort:514},
      {...candidate,sensorIngestPort:null},
      {...candidate,needsFinalRecheck:false},
      {...candidate,status:'CANDIDATE_REQUIRES_DEPLOY_RECHECK'},
      {...candidate,missingEvidence:['privateTenantSecret']},
      {...candidate,occupiedPorts:[514,514]},
      {...candidate,occupiedPorts:['unknown']},
      {...candidate,source:'UNVERIFIED'},
    ]) await expect(fetchParserPortProposal(undefined,fake(broken))).rejects.toThrow();
  });
  it('allows reviewed complete inventory but still never marks a port deployable',async()=>{
    const response={...candidate,status:'CANDIDATE_REQUIRES_DEPLOY_RECHECK',missingEvidence:[]};
    expect(await fetchParserPortProposal(undefined,fake(response))).toMatchObject({
      recommendedPort:20000,deployableNow:false,candidateOnly:true,needsFinalRecheck:true,
    });
  });
  it('Syslog RFC5424 chooses the same sensor and CONF port at or above 6800',async()=>{
    const response={...candidate,recommendedPort:6800,sensorIngestPort:6800};
    const request=fake(response);
    const result=await fetchParserPortProposal(undefined,request,'syslog_rfc5424');
    expect(result.recommendedPort).toBe(result.sensorIngestPort);
    expect(result.recommendedPort).toBe(6800);
    expect(result.deployableNow).toBe(false);
    const [url]=(request as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/stellar/legacy/port-proposal?format=syslog_rfc5424');
    const fakeRequest=fake(response);
    await expect(fetchParserPortProposal(6799,fakeRequest,'syslog_rfc5424')).rejects.toThrow('6800');
    expect(fakeRequest).not.toHaveBeenCalled();
    const manual={...response,source:'USER_OVERRIDE'};
    const req=fake(manual);
    await fetchParserPortProposal(6800,req,'syslog_rfc5424');
    expect((req as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0])
      .toBe('/api/v1/stellar/legacy/port-proposal?format=syslog_rfc5424&port=6800');
  });
  it('RFC3164 candidate must use identical >=6800 sensor and CONF port',async()=>{
    const forbidden=fake(candidate);
    await expect(fetchParserPortProposal(6799,forbidden,'syslog_rfc3164'))
      .rejects.toThrow('6800');
    expect(forbidden).not.toHaveBeenCalled();
    const answer={...candidate,recommendedPort:6801,sensorIngestPort:6801,
      source:'USER_OVERRIDE',occupiedPorts:[514,20001]};
    const request=fake(answer);
    const result=await fetchParserPortProposal(6801,request,'syslog_rfc3164');
    expect(result.sensorIngestPort).toBe(6801);
    expect((request as unknown as ReturnType<typeof vi.fn>).mock.calls[0][0])
      .toBe('/api/v1/stellar/legacy/port-proposal?format=syslog_rfc3164&port=6801');
    expect(result.deployableNow).toBe(false);
  });
  it('rejects invalid manual overrides without a request',async()=>{
    for(const bad of [0,80,65536,1.5,NaN,-3]){
      const request=fake(candidate);
      await expect(fetchParserPortProposal(bad,request)).rejects.toThrow();
      expect(request).not.toHaveBeenCalled();
    }
  });
  it('does not treat unauthenticated or unconfigured backend as confirmed availability',async()=>{
    await expect(fetchParserPortProposal(undefined,fake({error:'LEGACY_READ_DENIED'},403))).rejects.toThrow(/403/);
    await expect(fetchParserPortProposal(undefined,fake({error:'LEGACY_NOT_CONFIGURED'},503))).rejects.toThrow(/503/);
    await expect(fetchParserPortProposal(undefined,fake({error:'INVALID'},422))).rejects.toThrow(/422/);
    await expect(fetchParserPortProposal(undefined,vi.fn(async()=>({
      status:200,json:async()=>{throw Error('bad');},
    })) as unknown as typeof fetch)).rejects.toThrow();
  });
});
