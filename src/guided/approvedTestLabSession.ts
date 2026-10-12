import type { BackendCapabilities } from './backendCapabilities';

/** Owner-approved backend-controlled Test Lab sender. This client NEVER opens a
 * direct browser UDP/TCP socket, chooses an IP/port, or accesses DP credentials.
 * Default backend explicitly advertises liveSensorSenderEnabled=false and is
 * incapable of starting; a separate trusted sink/approval policy is required.
 */
export interface ApprovedTestLabStatus {
  runId: string;
  state: 'RUNNING'|'PAUSED'|'STOPPED'|'EXPIRED'|'FAILED'|'COMPLETED';
  sentCount: number;
  nextSequence: number;
  replayMode: 'single'|'constant-rate'|'original-gaps';
  sampleFamilyCount: number;
  ratePerSecond: number;
  maxEvents: number;
  leaseExpiresAt: string;
  lastSentAt: string|null;
  errorCode: string|null;
  parserLifecycleNotModified: true;
  realSensorVerified: false;
  runtimeParsingVerified: false;
  sensorIngestVerified: false;
}

const ROOT='/api/v1/test-lab/sessions';
const ID=/^test_run_[0-9a-f]{32}$/;
const APPROVAL=/^[A-Za-z0-9_.-]{8,96}$/;
const TIME=/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{3})?Z$/;
const STATES=new Set(['RUNNING','PAUSED','STOPPED','EXPIRED','FAILED','COMPLETED']);
const MODES=new Set(['single','constant-rate','original-gaps']);
const STATUS_FIELDS=[
  'runId','state','sentCount','nextSequence','replayMode','sampleFamilyCount',
  'ratePerSecond','maxEvents','leaseExpiresAt','lastSentAt','errorCode',
  'parserLifecycleNotModified','realSensorVerified','runtimeParsingVerified','sensorIngestVerified',
].sort().join(',');
const SYNTHETIC_SOURCE=JSON.stringify({
  time:'2026-01-01T01:00:00Z',src_ip:'192.0.2.10',
  username:'example_user',url:'https://example.invalid/synthetic',action:'allow',
  test:{run_id:'synthetic_initial'},
});
const FIXTURE={
  format:'json' as const,source:SYNTHETIC_SOURCE,seed:42,sequence:0,
  timestampField:'time',variableFields:[
    {path:'src_ip',kind:'ipv4' as const},
    {path:'username',kind:'username' as const},
    {path:'url',kind:'url' as const},
  ],
  runMarkerField:'test.run_id',
};
const u=(n:unknown,min:number,max:number)=>
  typeof n==='number' && Number.isInteger(n) && n>=min && n<=max;
const time=(value:unknown)=>typeof value==='string' && TIME.test(value) &&
  Number.isFinite(Date.parse(value));
const id=(raw:unknown)=>typeof raw==='string' && ID.test(raw);

export function assertApprovedSessionReady(cap:BackendCapabilities):void {
  const t=cap.testLab;
  if(!t || t.liveSensorSenderEnabled!==true ||
     t.trustedSinkSessionControlAvailable!==true ||
     t.sessionControlRequiresBackendAuthorization!==true ||
     t.serverInjectedUdpTcpSinkAvailable!==true ||
     t.sinkRequiresIpLiteralAllowlist!==true ||
     t.sinkRequiresPerDeliveryPolicyAndAudit!==true ||
     t.sessionRenewalRequiresSeparateApproval!==true ||
     t.sessionDurableAcrossRestart!==false ||
     t.sessionMaxRatePerSecond!==5 ||
     t.sessionMaxLeaseMs!==900000 ||
     t.sessionMaxAdditionalEventsPerRenewal!==3000 ||
     t.sessionMaxCumulativeEvents!==300000 ||
     t.sensorIngestVerified!==false ||
     t.runtimeParsingVerified!==false) {
    throw new Error('별도 백엔드 승인·허용 목록·감사 전송 정책이 확인되지 않아 Test Lab 센서 송신이 차단됐습니다.');
  }
}
export function validateApprovedSessionStatus(value:unknown,expectedRunId?:string):ApprovedTestLabStatus {
  if(!value || typeof value!=='object' || Array.isArray(value) ||
     Object.keys(value).sort().join(',')!==STATUS_FIELDS) {
    throw new Error('Test Lab 세션 메타데이터 계약이 검증되지 않았습니다.');
  }
  const v=value as Partial<ApprovedTestLabStatus>;
  if(!id(v.runId) || (expectedRunId && v.runId!==expectedRunId) ||
     !STATES.has(String(v.state)) || !MODES.has(String(v.replayMode)) ||
     !u(v.sentCount,0,300000) ||
     !u(v.maxEvents,1,300000) || v.sentCount! > v.maxEvents! ||
     !u(v.nextSequence,0,300000) || v.nextSequence!==v.sentCount ||
     !u(v.sampleFamilyCount,1,12) ||
     typeof v.ratePerSecond!=='number' || !Number.isFinite(v.ratePerSecond) ||
     v.ratePerSecond<0.2 || v.ratePerSecond>5 ||
     !time(v.leaseExpiresAt) ||
     (v.lastSentAt!==null && !time(v.lastSentAt)) ||
     (v.errorCode!==null && v.errorCode!=='TESTLAB_SINK_FAILED') ||
     v.parserLifecycleNotModified!==true ||
     v.realSensorVerified!==false || v.runtimeParsingVerified!==false ||
     v.sensorIngestVerified!==false) {
    throw new Error('Test Lab 세션 결과의 원본·센서 검증 범위를 신뢰할 수 없습니다.');
  }
  return v as ApprovedTestLabStatus;
}

async function requestSession(
  action:'start'|'status'|'pause'|'resume'|'stop'|'renew',
  body:Record<string,unknown>|null,
  requester:typeof fetch,
):Promise<ApprovedTestLabStatus> {
  let res:Response;
  if(action==='status'){
    const runId=body?.runId;
    if(!id(runId))throw new Error('잘못된 Test Lab 실행 ID입니다.');
    res=await requester(ROOT+'/status?runId='+runId,{
      method:'GET',credentials:'same-origin',cache:'no-store',
      headers:{Accept:'application/json'},
    });
  }else{
    res=await requester(ROOT+'/'+action,{
      method:'POST',credentials:'same-origin',cache:'no-store',
      headers:{'Content-Type':'application/json',Accept:'application/json'},
      body:JSON.stringify(body),
    });
  }
  if(res.status!==200)throw new Error('Test Lab 서버 승인이 없거나 작업이 거부됐습니다 (HTTP '+res.status+').');
  let data:unknown;
  try{data=await res.json();}
  catch{throw new Error('Test Lab 상태 응답 형식이 잘못되었습니다.');}
  return validateApprovedSessionStatus(data,action==='start'?undefined:body?.runId as string);
}

/** Fixed public synthetic fixture only; no customer/event/destination arguments. */
export async function startApprovedSyntheticSession(
  approvalId:string,
  rate:1|2|5,
  capability:BackendCapabilities,
  requester:typeof fetch=fetch,
):Promise<ApprovedTestLabStatus> {
  assertApprovedSessionReady(capability);
  if(!APPROVAL.test(approvalId) || ![1,2,5].includes(rate)) {
    throw new Error('유효한 별도 승인 ID 및 최대 5 이벤트/초 속도가 필요합니다.');
  }
  return requestSession('start',{
    sample:FIXTURE,approvalId,ratePerSecond:rate,leaseMs:60000,maxEvents:100,
  },requester);
}
export async function fetchApprovedSessionStatus(
  runId:string,requester:typeof fetch=fetch,
):Promise<ApprovedTestLabStatus> {
  if(!id(runId))throw new Error('유효한 실행 ID가 필요합니다.');
  return requestSession('status',{runId},requester);
}
export async function controlApprovedSession(
  runId:string,action:'pause'|'resume'|'stop',
  requester:typeof fetch=fetch,
):Promise<ApprovedTestLabStatus> {
  if(!id(runId) || !['pause','resume','stop'].includes(action)) {
    throw new Error('승인된 실행 ID 및 중지·일시정지·재개 작업만 허용합니다.');
  }
  return requestSession(action,{runId},requester);
}
export async function renewApprovedSession(
  runId:string,approvalId:string,leaseMs:number,additionalEvents:number,
  requester:typeof fetch=fetch,
):Promise<ApprovedTestLabStatus> {
  if(!id(runId) || !APPROVAL.test(approvalId) ||
     !u(leaseMs,250,900000) || !u(additionalEvents,0,3000)) {
    throw new Error('세션 연장은 별도의 유효한 승인 ID와 제한된 시간/이벤트 수가 필요합니다.');
  }
  return requestSession('renew',{
    runId,approvalId,leaseMs,additionalEvents,
  },requester);
}
