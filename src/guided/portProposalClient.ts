/** Read-only, server-authorized provisional parser *listener* port analysis.
 * NEVER equivalent to a reservation, sensor ingestion port, DP deployment,
 * or confirmation that no existing parser is using the port.
 */
export interface ParserPortProposal {
  contract: 'stellar-parser-listener-port-proposal.v0.1';
  recommendedPort: number;
  source: 'SUGGESTED' | 'USER_OVERRIDE';
  status: 'CANDIDATE_REQUIRES_DEPLOY_RECHECK' | 'INCOMPLETE_EVIDENCE';
  missingEvidence: Array<'catalogue' | 'tenant' | 'sensorBindings' | 'localReservations'>;
  occupiedPorts: number[];
  candidateOnly: true;
  deployableNow: false;
  verifiedIngestPort: false;
  sensorIngestPort: null;
  needsFinalRecheck: true;
}

const BASE='/api/v1/stellar/legacy/port-proposal';
const MISSING=new Set(['catalogue','tenant','sensorBindings','localReservations']);
const KEYS=[
  'candidateOnly','contract','deployableNow','missingEvidence','needsFinalRecheck',
  'occupiedPorts','recommendedPort','sensorIngestPort','source','status','verifiedIngestPort',
].sort().join(',');
const isPort=(value:unknown):value is number=>
  typeof value==='number' && Number.isInteger(value) && value>=1 && value<=65535;

export async function fetchParserPortProposal(
  requestedPort?:number,
  requester:typeof fetch=fetch,
):Promise<ParserPortProposal> {
  if(requestedPort!==undefined && (!isPort(requestedPort) || requestedPort<1024)) {
    throw new Error('수신 포트는 권한 포트가 아닌 1024–65535 범위의 정수여야 합니다.');
  }
  const url=BASE+(requestedPort===undefined?'':'?port='+requestedPort);
  const res=await requester(url,{
    method:'GET',cache:'no-store',credentials:'same-origin',
    headers:{Accept:'application/json'},
  });
  if(res.status!==200){
    throw new Error('승인된 로컬 파서 포트 목록 확인이 불가능합니다 (HTTP '+res.status+'). 현재 포트는 미검증입니다.');
  }
  let value:unknown;
  try {value=await res.json();}
  catch {throw new Error('파서 수신 포트 조회 결과가 JSON 형식이 아닙니다.');}
  if(!value || typeof value!=='object' || Array.isArray(value)) {
    throw new Error('파서 포트 조회 결과가 지원 계약과 일치하지 않습니다.');
  }
  const plan=value as Partial<ParserPortProposal>;
  const occupancy=plan.occupiedPorts;
  const missing=plan.missingEvidence;
  if(Object.keys(plan).sort().join(',')!==KEYS ||
     plan.contract!=='stellar-parser-listener-port-proposal.v0.1' ||
     !isPort(plan.recommendedPort) || plan.recommendedPort<1024 ||
     plan.source!==(requestedPort===undefined?'SUGGESTED':'USER_OVERRIDE') ||
     (requestedPort!==undefined && plan.recommendedPort!==requestedPort) ||
     plan.candidateOnly!==true || plan.deployableNow!==false ||
     plan.verifiedIngestPort!==false || plan.sensorIngestPort!==null ||
     plan.needsFinalRecheck!==true ||
     !Array.isArray(occupancy) || occupancy.length>20000 ||
     !occupancy.every(isPort) || new Set(occupancy).size!==occupancy.length ||
     occupancy.some((port,index)=>index>0 && port<=occupancy[index-1]) ||
     occupancy.includes(plan.recommendedPort) ||
     !Array.isArray(missing) || missing.length>4 ||
     new Set(missing).size!==missing.length ||
     !missing.every(field=>MISSING.has(field)) ||
     plan.status!==(missing.length?'INCOMPLETE_EVIDENCE':'CANDIDATE_REQUIRES_DEPLOY_RECHECK')) {
    throw new Error('포트 후보의 점유 현황·증거 완전성·배포 미승인 상태가 검증되지 않았습니다.');
  }
  return plan as ParserPortProposal;
}
