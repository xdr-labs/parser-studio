import { describe, expect, it, vi } from 'vitest';
import type { BackendCapabilities } from './backendCapabilities';
import {
  assertInterflowReadbackCapability, queryApprovedInterflowReadback,
  type InterflowReadbackRequest,
} from './approvedInterflowReadback';

const cap={testLab:{
  interflowReadClientAvailable:true,
  interflowBoundedPollingAvailable:true,
  interflowMaxPollAttempts:6,
  interflowMaxPollWindowMs:15000,
  interflowCursorVerified:false,
  interflowSearchPermissionsVerified:false,
  interflowRealTargetVerified:false,
  sensorIngestVerified:false,
  runtimeParsingVerified:false,
}} as BackendCapabilities;
const runId='test_run_'+'a'.repeat(32);
const request:InterflowReadbackRequest={
  runId,index:'syslog',markerField:'test.run_id',
  expectedField:'action',expectedValue:'allow',lookbackMinutes:5,
};
const proof={
  state:'MATCHED_RESPONSE_FIELDS',matchCount:1,
  fields:[{field:'action',status:'MATCH'}],
  sensorReceivedVerified:false,endToEndVerified:false,
  runtimeParsingVerified:false,targetImportVerified:false,
};
const fake=(json:unknown,status=200)=>vi.fn(async()=>({
  status,json:async()=>json,
})) as unknown as typeof fetch;

describe('owner-bound, audited Interflow field comparison, not native or target E2E evidence',()=>{
  it('does not treat advertised query code as a current target permission grant',()=>{
    expect(()=>assertInterflowReadbackCapability(cap)).not.toThrow();
    for(const bad of [
      {interflowReadClientAvailable:false},
      {interflowBoundedPollingAvailable:false},
      {interflowMaxPollAttempts:100},
      {interflowMaxPollWindowMs:0},
      {interflowCursorVerified:true},
      {interflowSearchPermissionsVerified:true},
      {interflowRealTargetVerified:true},
      {sensorIngestVerified:true},
      {runtimeParsingVerified:true},
    ]) {
      expect(()=>assertInterflowReadbackCapability({
        testLab:{...cap.testLab,...bad},
      } as BackendCapabilities)).toThrow();
    }
  });

  it('sends only bounded run marker, index, one public synthetic expected field and time range',async()=>{
    const send=fake(proof);
    const now=Date.parse('2026-10-12T02:30:00Z');
    expect(await queryApprovedInterflowReadback(cap,request,send,()=>now)).toEqual(proof);
    const [url,init]=(send as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/interflow/search');
    expect(init).toMatchObject({method:'POST',credentials:'same-origin',cache:'no-store'});
    const body=JSON.parse(init.body);
    expect(Object.keys(body).sort()).toEqual([
      'endMs','expectedFields','index','limit','markerField','runId','startMs',
    ]);
    expect(body).toEqual({
      index:'syslog',runId,markerField:'test.run_id',
      expectedFields:{action:'allow'},limit:20,
      startMs:now-300000,endMs:now,
    });
    expect(JSON.stringify(body)).not.toMatch(/tenant|apiKey|sensorIp|rawLog|dpUrl|PRIVATE/);
    expect(JSON.stringify(proof)).not.toContain('allow');
  });

  it('allows NO_MATCH or field mismatch without falsely claiming verified target ingestion',async()=>{
    const noMatch={...proof,state:'NO_MATCH',matchCount:0,
      fields:[{field:'action',status:'MISSING'}]};
    expect(await queryApprovedInterflowReadback(cap,request,fake(noMatch))).toMatchObject({
      state:'NO_MATCH',endToEndVerified:false,
    });
    const wrong={...proof,state:'FIELD_MISMATCH',fields:[{field:'action',status:'MISMATCH'}]};
    expect(await queryApprovedInterflowReadback(cap,request,fake(wrong))).toMatchObject({
      state:'FIELD_MISMATCH',sensorReceivedVerified:false,
    });
  });

  it('never calls backend with untrusted run IDs, marker names, sensitive values or unbounded requests',async()=>{
    const send=fake(proof);
    const cases:InterflowReadbackRequest[]=[
      {...request,runId:'someone-else'},
      {...request,markerField:'constructor'},
      {...request,markerField:'test.__proto__'},
      {...request,expectedField:'system..secret'},
      {...request,expectedValue:'PRIVATE_KEY\nTOKEN'},
      {...request,expectedValue:''},
      {...request,expectedValue:'x'.repeat(129)},
      {...request,lookbackMinutes:30 as 5},
      {...request,index:'all' as 'syslog'},
    ];
    for(const bad of cases) await expect(
      queryApprovedInterflowReadback(cap,bad,send),
    ).rejects.toThrow();
    expect(send).not.toHaveBeenCalled();
    await expect(queryApprovedInterflowReadback(
      cap,request,send,()=>1200,
    )).rejects.toThrow();
    expect(send).not.toHaveBeenCalled();
  });

  it.each([401,403,404,413,422,429,503])('denied/read-restricted HTTP %s never means no hits or verified parsing',async status=>{
    await expect(queryApprovedInterflowReadback(cap,request,fake({error:'DENIED'},status)))
      .rejects.toThrow(String(status));
  });

  it.each([
    {...proof,sensorReceivedVerified:true},
    {...proof,endToEndVerified:true},
    {...proof,runtimeParsingVerified:true},
    {...proof,targetImportVerified:true},
    {...proof,raw_log:'REDACTED_PRIVATE'},
    {...proof,fields:[{field:'action',status:'MATCH',actualValue:'private'}]},
    {...proof,state:'DETECTED'},
    {...proof,state:'NO_MATCH'},
    {...proof,fields:[{field:'api_key',status:'MATCH'}]},
    {...proof,fields:[{field:'action',status:'MISSING'}]},
    {...proof,matchCount:-1},
    {...proof,matchCount:101},
    {...proof,fields:[]},
  ])('rejects misleading status, unrequested fields and unexpected sensitive response keys',async malformed=>{
    await expect(queryApprovedInterflowReadback(cap,request,fake(malformed))).rejects.toThrow();
  });
});
