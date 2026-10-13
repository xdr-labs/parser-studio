/** Read-only, server-authorized provisional shared receiver-port analysis.
 * The chosen value is ONE port for the sensor log destination AND generated
 * Fluentd CONF <source>. It is never proof that a listener actually exists,
 * or an inventory reservation, DP deployment, or collision-free target.
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
  sensorIngestPort: number;
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
  parserFormat?:'syslog_rfc3164'|'syslog_rfc5424',
):Promise<ParserPortProposal> {
  if(parserFormat!==undefined&& !['syslog_rfc3164','syslog_rfc5424'].includes(parserFormat))
    throw new Error('Unsupported parser format for port proposal.');
  if(requestedPort!==undefined && (!isPort(requestedPort) || requestedPort<1024)) {
    throw new Error('The shared sensor/CONF port must be an integer from 1024 to 65535.');
  }
  if(['syslog_rfc3164','syslog_rfc5424'].includes(parserFormat??'') &&
     requestedPort!==undefined && requestedPort<6800)
    throw new Error('Syslog sensor and CONF listener ports must be at least 6800.');
  const query=new URLSearchParams();
  if(parserFormat) query.set('format',parserFormat);
  if(requestedPort!==undefined)query.set('port',String(requestedPort));
  const url=BASE+(query.size?'?'+query.toString():'');
  const res=await requester(url,{
    method:'GET',cache:'no-store',credentials:'same-origin',
    headers:{Accept:'application/json'},
  });
  if(res.status!==200){
    throw new Error('Authorized local parser port inventory unavailable (HTTP '+res.status+'). Candidate ports are unverified.');
  }
  let value:unknown;
  try {value=await res.json();}
  catch {throw new Error('Parser listener port response is not valid JSON.');}
  if(!value || typeof value!=='object' || Array.isArray(value)) {
    throw new Error('Parser port response does not match the supported contract.');
  }
  const plan=value as Partial<ParserPortProposal>;
  const occupancy=plan.occupiedPorts;
  const missing=plan.missingEvidence;
  if(Object.keys(plan).sort().join(',')!==KEYS ||
     plan.contract!=='stellar-parser-listener-port-proposal.v0.1' ||
     !isPort(plan.recommendedPort) || plan.recommendedPort<1024 ||
     (['syslog_rfc3164','syslog_rfc5424'].includes(parserFormat??'')&&plan.recommendedPort<6800) ||
     plan.source!==(requestedPort===undefined?'SUGGESTED':'USER_OVERRIDE') ||
     (requestedPort!==undefined && plan.recommendedPort!==requestedPort) ||
     plan.candidateOnly!==true || plan.deployableNow!==false ||
     plan.verifiedIngestPort!==false ||
     plan.sensorIngestPort!==plan.recommendedPort ||
     plan.needsFinalRecheck!==true ||
     !Array.isArray(occupancy) || occupancy.length>20000 ||
     !occupancy.every(isPort) || new Set(occupancy).size!==occupancy.length ||
     occupancy.some((port,index)=>index>0 && port<=occupancy[index-1]) ||
     occupancy.includes(plan.recommendedPort) ||
     !Array.isArray(missing) || missing.length>4 ||
     new Set(missing).size!==missing.length ||
     !missing.every(field=>MISSING.has(field)) ||
     plan.status!==(missing.length?'INCOMPLETE_EVIDENCE':'CANDIDATE_REQUIRES_DEPLOY_RECHECK')) {
    throw new Error('Port candidate occupancy, evidence completeness, or no-deployment status cannot be verified.');
  }
  return plan as ParserPortProposal;
}
