import type { BackendCapabilities } from './backendCapabilities';

/**
 * Offline, public-only, two-family synthetic scenario preview.
 * Never accepts a user sample, run ID, tenant, credentials, network address,
 * parser artifacts, or an unbounded repetition count.
 * A server-side preview authorization callback is always required.
 */
export type SyntheticScenarioMode='constant-rate'|'original-gaps';
export type SyntheticScenarioSequence=0|1|2|3;
export interface SyntheticScenarioSelection {
  sampleId:'allow-event'|'deny-event';
  nextDelayMs:500|600;
  replayMode:SyntheticScenarioMode;
  sampleFamilyCount:2;
  safeToSendToSensor:false;
  sensorReceivedVerified:false;
  runtimeParsingVerified:false;
  preview:{
    contract:'parser-studio.synthetic-preview.v0.1';
    format:'json';
    syntheticEvent:string;
    generatedAt:string;
    sequence:SyntheticScenarioSequence;
    changedPaths:string[];
    safeToSendToSensor:false;
    runtimeParsingVerified:false;
    targetSensorVerified:false;
  };
}
const MARKER='test_run_'+'0'.repeat(32);
const DOC_IPV4=/^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4])$/;
const ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const TIMESTAMP=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/;
const CHANGED='time,src_ip,username,url,run_id';
const TOP_FIELDS=['sampleId','nextDelayMs','preview','replayMode','sampleFamilyCount',
  'safeToSendToSensor','sensorReceivedVerified','runtimeParsingVerified'].sort().join(',');
const PREVIEW_FIELDS=['changedPaths','contract','format','generatedAt','runtimeParsingVerified',
  'safeToSendToSensor','sequence','syntheticEvent','targetSensorVerified'].sort().join(',');

export function assertOfflineSyntheticScenarioCapability(cap:BackendCapabilities):void {
  const t=cap.testLab;
  if(!t ||
    t.scenarioOfflinePreviewAvailable!==true ||
    t.multiSampleReplayAvailable!==true ||
    t.constantRateScenarioAvailable!==true ||
    t.boundedOriginalGapsScenarioAvailable!==true ||
    t.scenarioMaxSamples!==12 ||
    t.scenarioRunMarkerRequired!==true ||
    t.requiresBackendPreviewAuthorization!==true ||
    t.liveSensorSenderEnabled!==false ||
    t.sensorIngestVerified!==false ||
    t.runtimeParsingVerified!==false){
    throw new Error('The backend cannot confirm an authorized, offline-only synthetic scenario preview.');
  }
}
const SAMPLE=(action:'allow'|'deny',ip:string)=>({
  format:'json' as const,
  source:JSON.stringify({
    time:'2026-01-01T01:02:03Z',
    src_ip:ip,username:'example_user',
    url:'https://example.invalid/synthetic',
    action,run_id:'synthetic_initial',
  }),
  seed:42,sequence:0,
  timestampField:'time',
  variableFields:[
    {path:'src_ip',kind:'ipv4' as const},
    {path:'username',kind:'username' as const},
    {path:'url',kind:'url' as const},
  ],
  runMarkerField:'run_id',
});

function scenario(mode:SyntheticScenarioMode){
  const events=[
    {id:'allow-event',sample:SAMPLE('allow','192.0.2.10')},
    {id:'deny-event',sample:SAMPLE('deny','198.51.100.20')},
  ];
  if(mode==='original-gaps')return {
    scenarioId:'synthetic-two-family-demo',mode,cycleMs:1200,
    events:[{...events[0],offsetMs:0},{...events[1],offsetMs:600}],
  };
  return {scenarioId:'synthetic-two-family-demo',mode,events};
}
export function validateOfflineSyntheticScenarioResponse(
  payload:unknown,mode:SyntheticScenarioMode,sequence:SyntheticScenarioSequence,
):SyntheticScenarioSelection {
  if(!payload || typeof payload!=='object'||Array.isArray(payload)||
    Object.keys(payload).sort().join(',')!==TOP_FIELDS){
    throw new Error('Scenario preview response contained unexpected or sensitive fields.');
  }
  const v=payload as Partial<SyntheticScenarioSelection>;
  const expectedId=sequence%2===0?'allow-event':'deny-event';
  const expectedDelay=mode==='constant-rate'?500:600;
  if(v.sampleId!==expectedId ||
    v.nextDelayMs!==expectedDelay ||
    v.replayMode!==mode ||v.sampleFamilyCount!==2||
    v.safeToSendToSensor!==false ||
    v.sensorReceivedVerified!==false||
    v.runtimeParsingVerified!==false||
    !v.preview||typeof v.preview!=='object'||Array.isArray(v.preview)||
    Object.keys(v.preview).sort().join(',')!==PREVIEW_FIELDS){
    throw new Error('Scenario selection or no-delivery proof is invalid.');
  }
  const preview=v.preview;
  if(preview.contract!=='parser-studio.synthetic-preview.v0.1'||
    preview.format!=='json'||preview.sequence!==sequence||
    preview.safeToSendToSensor!==false||
    preview.runtimeParsingVerified!==false||
    preview.targetSensorVerified!==false||
    typeof preview.generatedAt!=='string' ||
    !ISO.test(preview.generatedAt)||
    !Number.isFinite(Date.parse(preview.generatedAt))||
    !Array.isArray(preview.changedPaths)||
    preview.changedPaths.join(',')!==CHANGED ||
    typeof preview.syntheticEvent!=='string'||
    preview.syntheticEvent.length>8192){
    throw new Error('Scenario event metadata contains unexpected verification or content.');
  }
  let event:unknown;
  try{event=JSON.parse(preview.syntheticEvent);}
  catch{throw new Error('Scenario event is not valid public synthetic JSON.');}
  if(!event||typeof event!=='object'||Array.isArray(event))
    throw new Error('Scenario event must be a synthetic JSON object.');
  const data=event as Record<string,unknown>;
  if(Object.keys(data).sort().join(',')!=='action,run_id,src_ip,time,url,username' ||
    data.action!==(sequence%2===0?'allow':'deny')||
    data.run_id!==MARKER||
    typeof data.time!=='string'||!TIMESTAMP.test(data.time)||
    typeof data.src_ip!=='string'||!DOC_IPV4.test(data.src_ip)||
    typeof data.username!=='string'||!/^synthetic_user_\d{6}$/.test(data.username)||
    typeof data.url!=='string'||!/^https:\/\/synthetic\.invalid\/synthetic\/[a-f0-9]{8}$/.test(data.url)){
    throw new Error('Scenario preview contains user data or unsupported fields.');
  }
  return v as SyntheticScenarioSelection;
}

export async function requestOfflineSyntheticScenarioPreview(
  cap:BackendCapabilities,
  mode:SyntheticScenarioMode,
  sequence:SyntheticScenarioSequence,
  requester:typeof fetch=fetch,
):Promise<SyntheticScenarioSelection>{
  assertOfflineSyntheticScenarioCapability(cap);
  if(!['constant-rate','original-gaps'].includes(mode)||![0,1,2,3].includes(sequence)){
    throw new Error('Only four bounded public scenario previews are supported.');
  }
  const response=await requester('/api/v1/test-lab/scenario/preview',{
    method:'POST',credentials:'same-origin',cache:'no-store',
    headers:{'Content-Type':'application/json',Accept:'application/json'},
    body:JSON.stringify({scenario:scenario(mode),sequence,ratePerSecond:2}),
  });
  if(response.status!==200){
    throw new Error('Backend preview authorization denied or unavailable (HTTP '+response.status+').');
  }
  let payload:unknown;
  try{payload=await response.json();}
  catch{throw new Error('Scenario preview backend response is not valid JSON.');}
  return validateOfflineSyntheticScenarioResponse(payload,mode,sequence);
}
