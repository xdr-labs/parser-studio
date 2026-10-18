import type { BackendCapabilities } from './backendCapabilities';

/** Always uses a fixed public synthetic sample, NEVER a customer sample.
 * Server-side preview authorization is mandatory. No listener/sender/session.
 */
const SOURCE=JSON.stringify({
  time:'2026-01-01T01:02:03Z',
  src_ip:'192.0.2.10',
  username:'example-user',
  url:'https://example.invalid/synthetic',
  action:'allow',
});
const REQUEST={
  format:'json' as const,
  source:SOURCE,
  seed:42,
  sequence:0,
  timestampField:'time',
  variableFields:[
    {path:'src_ip',kind:'ipv4' as const},
    {path:'username',kind:'username' as const},
    {path:'url',kind:'url' as const},
  ],
};
const CHANGED=['time','src_ip','username','url'];
const RESULT_KEYS=['changedPaths','contract','format','generatedAt','runtimeParsingVerified',
  'safeToSendToSensor','sequence','syntheticEvent','targetSensorVerified'].sort().join(',');
const ISO=/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const DOC_IPV4=/^(?:192\.0\.2|198\.51\.100|203\.0\.113)\.(?:[1-9]\d?|1\d\d|2[0-4]\d|25[0-4])$/;

export interface AuthorizedSyntheticPreview {
  contract:'parser-studio.synthetic-preview.v0.1';
  format:'json';
  syntheticEvent:string;
  generatedAt:string;
  sequence:0;
  changedPaths:string[];
  safeToSendToSensor:false;
  runtimeParsingVerified:false;
  targetSensorVerified:false;
}

export function validateBackendSyntheticPreviewCapability(cap:BackendCapabilities):void {
  const testLab=cap?.testLab;
  if(!testLab || testLab.offlineJsonPreview!==true ||
     testLab.requiresBackendPreviewAuthorization!==true ||
     testLab.liveSensorSenderEnabled!==false ||
     testLab.sensorIngestVerified!==false ||
     testLab.runtimeParsingVerified!==false) {
    throw new Error('The backend-authorized JSON synthetic preview or its no-delivery status could not be verified.');
  }
}

export async function requestAuthorizedSyntheticPreview(
  cap:BackendCapabilities,
  requester:typeof fetch=fetch,
):Promise<AuthorizedSyntheticPreview> {
  validateBackendSyntheticPreviewCapability(cap);
  const res=await requester('/api/v1/test-lab/preview',{
    method:'POST',credentials:'same-origin',cache:'no-store',
    headers:{'Content-Type':'application/json',Accept:'application/json'},
    body:JSON.stringify(REQUEST),
  });
  if(res.status!==200) throw new Error('Unable to execute the authorized synthetic preview (HTTP '+res.status+').');
  let payload:unknown;
  try{payload=await res.json();}
  catch{throw new Error('Synthetic preview response is not valid JSON.');}
  if(!payload || typeof payload!=='object' || Array.isArray(payload) ||
     Object.keys(payload).sort().join(',')!==RESULT_KEYS) {
    throw new Error('Unrecognized synthetic preview response format.');
  }
  const result=payload as Partial<AuthorizedSyntheticPreview>;
  if(result.contract!=='parser-studio.synthetic-preview.v0.1' ||
     result.format!=='json' || result.sequence!==0 ||
     result.safeToSendToSensor!==false ||
     result.runtimeParsingVerified!==false ||result.targetSensorVerified!==false ||
     typeof result.generatedAt!=='string' || !ISO.test(result.generatedAt) ||
     !Number.isFinite(Date.parse(result.generatedAt)) ||
     !Array.isArray(result.changedPaths) ||
     result.changedPaths.length!==CHANGED.length ||
     result.changedPaths.some((value,i)=>value!==CHANGED[i]) ||
     typeof result.syntheticEvent!=='string'||result.syntheticEvent.length>8192) {
    throw new Error('Preview contains unverified delivery/runtime claims or an invalid format.');
  }
  let event:unknown;
  try{event=JSON.parse(result.syntheticEvent);}
  catch{throw new Error('Synthetic preview must contain a valid JSON object.');}
  if(!event||Array.isArray(event)||typeof event!=='object') throw new Error('Invalid synthetic preview event.');
  const parsed=event as Record<string,unknown>;
  if(Object.keys(parsed).sort().join(',')!=='action,src_ip,time,url,username' ||
     parsed.action!=='allow' ||
     typeof parsed.time!=='string'||!/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(parsed.time) ||
     typeof parsed.src_ip!=='string'||!DOC_IPV4.test(parsed.src_ip) ||
     typeof parsed.username!=='string'||!/^synthetic_user_\d{6}$/.test(parsed.username) ||
     typeof parsed.url!=='string'||!/^https:\/\/synthetic\.invalid\/synthetic\/[a-f0-9]{8}$/.test(parsed.url)) {
    throw new Error('Backend synthetic preview contains customer data or unsupported values.');
  }
  return result as AuthorizedSyntheticPreview;
}
