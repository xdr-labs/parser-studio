import {afterEach,beforeEach,describe,expect,it,vi} from 'vitest';
import {createHash,webcrypto} from 'node:crypto';
import {loadTestLabEvidenceSummary,downloadTestLabEvidence} from './testLabEvidenceClient';

const runId='test_run_'+'a'.repeat(32);
const revision='b'.repeat(64);
const hash=(input:string|Uint8Array)=>createHash('sha256').update(input).digest('hex');
const counts={generated:2,sendAttempted:2,sinkAccepted:1,sensorObserved:0,dpIndexed:1,fieldCompared:1};
const summary={
  contract:'testlab-redacted-summary.v0.1',mode:'OFFLINE_CONTRACT',
  runId,artifactRevisionId:revision,expiresAt:'2026-10-12T12:15:00.000Z',
  comparisonStatus:'OFFLINE_EVIDENCE_ONLY',counts,
  failureGroups:[{errorCode:'SEND_TIMEOUT',events:1}],
  fieldCoverage:[{field:'action',comparedEvents:1,matched:1,mismatched:0,
    missing:0,coveragePercent:100,matchPercent:100}],
  realSensorVerified:false,runtimeParsingVerified:false,liveE2eVerified:false,
};
const report={contract:'testlab-redacted-evidence.v0.1',mode:'OFFLINE_CONTRACT',
  runId,artifactRevisionId:revision,expiresAt:summary.expiresAt,counts,
  events:[
    {sequence:0,generated:true,sendAttempted:true,sinkAccepted:true,
      sensorObserved:false,dpIndexed:true,fieldComparison:'FIELDS_MATCHED',
      fields:[{field:'action',status:'MATCH'}],errorCode:null},
    {sequence:1,generated:true,sendAttempted:true,sinkAccepted:false,
      sensorObserved:false,dpIndexed:false,fieldComparison:'NOT_VERIFIED',
      fields:[],errorCode:'SEND_TIMEOUT'},
  ],realSensorVerified:false,runtimeParsingVerified:false,liveE2eVerified:false,
};
const json=(value:unknown,status=200)=>({
  status,headers:new Headers({'content-type':'application/json; charset=utf-8'}),
  json:async()=>value,
}) as Response;
const binary=(value:unknown=report,opts:{
  body?:string;hash?:string;status?:number;filename?:string;
  length?:number;mime?:string;
}={})=>{
  const source=opts.body??JSON.stringify(value)+'\n';
  const bytes=new TextEncoder().encode(source);
  return {status:opts.status??200,headers:new Headers({
    'content-type':opts.mime??'application/json; charset=utf-8',
    'content-disposition':opts.filename??'attachment; filename="testlab-evidence-'+runId+'.json"',
    'content-length':String(opts.length??bytes.byteLength),
    'x-parser-evidence-sha256':opts.hash??hash(bytes),
    'cache-control':'no-store',
  }),arrayBuffer:async()=>new Uint8Array(bytes).buffer} as Response;
};

describe('opt-in owner-only Test Lab evidence readback',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());
  it('reads only bounded, allowlisted metadata from the owned run and no event values',async()=>{
    const requester=vi.fn(async()=>json(summary)) as unknown as typeof fetch;
    const result=await loadTestLabEvidenceSummary(runId,requester);
    expect(result).toEqual(summary);
    const [url,options]=vi.mocked(requester).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/sessions/evidence-summary?runId='+runId);
    expect(options).toMatchObject({method:'GET',credentials:'same-origin',cache:'no-store'});
    expect(JSON.stringify(options)).not.toContain('apiKey');
    expect(JSON.stringify(result)).not.toContain('198.51.100.10');
  });
  it('accepts backend-rounded fractional coverage percentages without false PASS claims',async()=>{
    const rounded={...summary,counts:{generated:3,sendAttempted:3,sinkAccepted:3,
      sensorObserved:0,dpIndexed:3,fieldCompared:3},
      failureGroups:[],fieldCoverage:[{field:'action',comparedEvents:3,
        matched:2,mismatched:1,missing:0,coveragePercent:100,matchPercent:66.67}]};
    const requester=vi.fn(async()=>json(rounded)) as unknown as typeof fetch;
    const result=await loadTestLabEvidenceSummary(runId,requester);
    expect(result.fieldCoverage[0].matchPercent).toBe(66.67);
    expect(result.realSensorVerified).toBe(false);
  });
  it('rejects missing authorization and does not treat unsupported endpoint as verified',async()=>{
    const requester=vi.fn(async()=>json({error:'TESTLAB_SESSION_DENIED'},403)) as unknown as typeof fetch;
    await expect(loadTestLabEvidenceSummary(runId,requester)).rejects.toThrow(/denied|unavailable/i);
    await expect(downloadTestLabEvidence(runId,requester)).rejects.toThrow(/denied|unavailable/i);
    expect(vi.mocked(requester).mock.calls).toHaveLength(2);
  });
  it('refuses foreign run, forged real verification, extra source, unsafe field and inconsistent counts',async()=>{
    const modified=[
      {...summary,runId:'test_run_'+'f'.repeat(32)},
      {...summary,realSensorVerified:true},
      {...summary,dpUrl:'https://customer-private.example'},
      {...summary,fieldCoverage:[{...summary.fieldCoverage[0],field:'constructor.user'}]},
      {...summary,counts:{...counts,fieldCompared:4}},
      {...summary,fieldCoverage:[{...summary.fieldCoverage[0],matchPercent:50}]},
      {...summary,comparisonStatus:'VERIFIED'},
      {...summary,failureGroups:[{errorCode:'UNTRUSTED_CUSTOMER_DATA',events:1}]},
      {...summary,counts:{...counts,generated:0}},
      {...summary,fieldCoverage:[{...summary.fieldCoverage[0],privateValue:'CUSTOMER_SECRET'}]},
    ];
    for(const fake of modified){
      const requester=vi.fn(async()=>json(fake)) as unknown as typeof fetch;
      await expect(loadTestLabEvidenceSummary(runId,requester)).rejects.toThrow();
    }
  });
  it('downloads verified canonical UTF-8 JSON exactly as received, never raw event fields',async()=>{
    const requester=vi.fn(async()=>binary()) as unknown as typeof fetch;
    const downloaded=await downloadTestLabEvidence(runId,requester);
    expect(downloaded.filename).toBe('testlab-evidence-'+runId+'.json');
    expect(downloaded.sha256).toBe(hash(new TextEncoder().encode(downloaded.content)));
    expect(JSON.parse(downloaded.content)).toEqual(report);
    expect(downloaded.content).not.toContain('CUSTOMER_SECRET');
    const [url,options]=vi.mocked(requester).mock.calls[0];
    expect(url).toBe('/api/v1/test-lab/sessions/evidence-export?runId='+runId);
    expect(options).toMatchObject({method:'GET',credentials:'same-origin',cache:'no-store'});
  });
  it('blocks altered SHA, binary headers, malformed JSON, extra privacy fields and forged flags',async()=>{
    const mutated=[
      binary(report,{hash:'0'.repeat(64)}),
      binary(report,{length:1}),
      binary(report,{filename:'attachment; filename="customer-logs.json"'}),
      binary(report,{mime:'text/plain'}),
      binary(report,{body:'not-json\n'}),
      binary({...report,secret:'198.51.100.10'}),
      binary({...report,realSensorVerified:true}),
      binary({...report,events:[{...report.events[0],raw:'CUSTOMER_SECRET'},report.events[1]]}),
      binary({...report,events:[{...report.events[0],fields:[{field:'__proto__.key',status:'MATCH'}]},report.events[1]]}),
      binary({...report,events:[report.events[0],report.events[0]]}),
      binary({...report,counts:{...counts,generated:22}}),
      binary({...report,events:[{...report.events[0],fieldComparison:'NO_FIELDS'},report.events[1]]}),
    ];
    for(const answer of mutated){
      const requester=vi.fn(async()=>answer) as unknown as typeof fetch;
      await expect(downloadTestLabEvidence(runId,requester)).rejects.toThrow();
    }
  });
  it('rejects malformed IDs locally and absent secure WebCrypto without network',async()=>{
    const requester=vi.fn(async()=>binary()) as unknown as typeof fetch;
    await expect(downloadTestLabEvidence('test_run_../private',requester)).rejects.toThrow();
    await expect(loadTestLabEvidenceSummary('test_run_../private',requester)).rejects.toThrow();
    expect(requester).not.toHaveBeenCalled();
    vi.stubGlobal('crypto',null);
    await expect(downloadTestLabEvidence(runId,requester)).rejects.toThrow(/WebCrypto|secure/i);
    expect(requester).not.toHaveBeenCalled();
  });
});
