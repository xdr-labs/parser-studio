import {describe,expect,it,vi} from 'vitest';
import type {BackendCapabilities} from './backendCapabilities';
import {
  assertOfflineSyntheticScenarioCapability,requestOfflineSyntheticScenarioPreview,
  validateOfflineSyntheticScenarioResponse,
} from './syntheticScenarioPreview';

const capabilities={testLab:{
  scenarioOfflinePreviewAvailable:true,multiSampleReplayAvailable:true,
  constantRateScenarioAvailable:true,boundedOriginalGapsScenarioAvailable:true,
  scenarioMaxSamples:12,scenarioRunMarkerRequired:true,
  requiresBackendPreviewAuthorization:true,liveSensorSenderEnabled:false,
  sensorIngestVerified:false,runtimeParsingVerified:false,
}} as BackendCapabilities;
const sample=(sequence:number)=>({
  contract:'parser-studio.synthetic-preview.v0.1',
  format:'json',
  sequence,generatedAt:'2026-10-12T05:20:00.000Z',
  changedPaths:['time','src_ip','username','url','run_id'],
  syntheticEvent:JSON.stringify({
    time:'2026-10-12T05:20:00Z',src_ip:'192.0.2.253',
    username:'synthetic_user_300397',
    url:'https://synthetic.invalid/synthetic/f040cef8',
    action:sequence%2===0?'allow':'deny',
    run_id:'test_run_'+'0'.repeat(32),
  }),
  safeToSendToSensor:false,runtimeParsingVerified:false,targetSensorVerified:false,
});
const returned=(mode:'constant-rate'|'original-gaps',sequence:0|1|2|3)=>({
  sampleId:sequence%2===0?'allow-event':'deny-event',
  nextDelayMs:mode==='constant-rate'?500:600,
  preview:sample(sequence),replayMode:mode,sampleFamilyCount:2,
  safeToSendToSensor:false,sensorReceivedVerified:false,runtimeParsingVerified:false,
});
const fake=(result:unknown,status=200)=>vi.fn(async()=>({
  status,json:async()=>result,
})) as unknown as typeof fetch;

describe('independently authorized offline synthetic scenario selection',()=>{
  it('requires bounded offline scenario capability and no current live sender',()=>{
    expect(()=>assertOfflineSyntheticScenarioCapability(capabilities)).not.toThrow();
    for(const key of ['scenarioOfflinePreviewAvailable','multiSampleReplayAvailable',
      'constantRateScenarioAvailable','boundedOriginalGapsScenarioAvailable',
      'scenarioRunMarkerRequired','requiresBackendPreviewAuthorization'] as const){
      expect(()=>assertOfflineSyntheticScenarioCapability({
        testLab:{...capabilities.testLab,[key]:false},
      } as BackendCapabilities)).toThrow();
    }
    for(const fields of [
      {scenarioMaxSamples:20},{liveSensorSenderEnabled:true},
      {sensorIngestVerified:true},{runtimeParsingVerified:true},
    ])expect(()=>assertOfflineSyntheticScenarioCapability({
      testLab:{...capabilities.testLab,...fields},
    } as BackendCapabilities)).toThrow();
  });
  it.each(['constant-rate','original-gaps'] as const)(
    'selects alternating pre-approved public JSON event families using %s',async mode=>{
      for(const sequence of [0,1,2,3] as const){
        const f=fake(returned(mode,sequence));
        const result=await requestOfflineSyntheticScenarioPreview(capabilities,mode,sequence,f);
        expect(result).toMatchObject({
          sampleId:sequence%2===0?'allow-event':'deny-event',
          replayMode:mode,sampleFamilyCount:2,
          safeToSendToSensor:false,sensorReceivedVerified:false,
          runtimeParsingVerified:false,
        });
        const [url,init]=(f as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
        expect(url).toBe('/api/v1/test-lab/scenario/preview');
        expect(init).toMatchObject({method:'POST',credentials:'same-origin',cache:'no-store'});
        const body=JSON.parse(init.body);
        expect(Object.keys(body).sort()).toEqual(['ratePerSecond','scenario','sequence']);
        expect(body.sequence).toBe(sequence);
        expect(body.ratePerSecond).toBe(2);
        expect(body.scenario).toMatchObject({
          scenarioId:'synthetic-two-family-demo',mode,events:[
            {id:'allow-event',sample:{format:'json',runMarkerField:'run_id'}},
            {id:'deny-event',sample:{format:'json',runMarkerField:'run_id'}},
          ],
        });
        expect(body.scenario.events).toHaveLength(2);
        if(mode==='original-gaps'){
          expect(body.scenario.cycleMs).toBe(1200);
          expect(body.scenario.events.map((e:{offsetMs:number})=>e.offsetMs)).toEqual([0,600]);
        }else{
          expect(body.scenario.cycleMs).toBeUndefined();
          expect(body.scenario.events[0].offsetMs).toBeUndefined();
        }
        expect(JSON.stringify(body)).toContain('192.0.2.10');
        for(const secret of ['PRIVATE_KEY','CUSTOMER_LOG','sensorIp','tenantId','dpUrl','runId','approvalId']){
          expect(JSON.stringify(body)).not.toContain(secret);
        }
      }
    });
  it.each([401,403,404,422,429,503])('HTTP %s denies preview without claiming any sensor delivery',async status=>{
    await expect(requestOfflineSyntheticScenarioPreview(
      capabilities,'constant-rate',0,fake({error:'DENIED'},status),
    )).rejects.toThrow(String(status));
  });
  it('rejects out-of-range sequences without any request',async()=>{
    const f=fake(returned('constant-rate',0));
    await expect(requestOfflineSyntheticScenarioPreview(
      capabilities,'constant-rate',5 as 0,f,
    )).rejects.toThrow();
    expect(f).not.toHaveBeenCalled();
  });
  it.each([
    {...returned('constant-rate',0),sampleId:'real-customer'},
    {...returned('constant-rate',0),sensorReceivedVerified:true},
    {...returned('constant-rate',0),runtimeParsingVerified:true},
    {...returned('constant-rate',0),safeToSendToSensor:true},
    {...returned('constant-rate',0),targetHost:'10.0.0.1'},
    {...returned('constant-rate',0),nextDelayMs:0},
    {...returned('constant-rate',0),sampleFamilyCount:99},
    {...returned('constant-rate',0),preview:{...sample(0),targetSensorVerified:true}},
    {...returned('constant-rate',0),preview:{...sample(0),rawLog:'SECRET'}},
    {...returned('constant-rate',0),preview:{...sample(0),changedPaths:['time','token']}},
    {...returned('constant-rate',0),preview:{...sample(0),sequence:1}},
    {...returned('constant-rate',0),preview:{
      ...sample(0),syntheticEvent:JSON.stringify({
        ...JSON.parse(sample(0).syntheticEvent),customerSecret:'NO',
      }),
    }},
    {...returned('constant-rate',0),preview:{
      ...sample(0),syntheticEvent:JSON.stringify({
        ...JSON.parse(sample(0).syntheticEvent),src_ip:'10.0.0.1',
      }),
    }},
  ])('refuses false runtime or sensor proof, extra data, invalid picks and leaks',wrong=>{
    expect(()=>validateOfflineSyntheticScenarioResponse(wrong,'constant-rate',0)).toThrow();
  });
});
