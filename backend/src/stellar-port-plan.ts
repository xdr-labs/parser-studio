/**
 * Server-side-only provisional parser-listener port planner.
 * Occupancy observations are NOT port reservations, sensor reachability,
 * or a guarantee that the Stellar target will use this listener.
 *
 * All inventory flags must come from trusted backend sources; never accept
 * browser assertions of sensor/catalogue completeness as deployment proof.
 */
export class PortPlanError extends Error{
  constructor(readonly code:string){super(code);this.name="PortPlanError";}
}
function reject(code:string):never{throw new PortPlanError(code);}

export type PortInventory={
  /** Parsed from documented custom_log_parsers/parsers GET incl builtins. */
  cataloguePorts:readonly number[];
  /** Tenant-owned/custom legacy parser ports from authorized inventory. */
  tenantLegacyPorts:readonly number[];
  /** Independently evidenced active receiver/source bindings, the SAME ingest port. */
  sensorParserPorts:readonly number[];
  /** Server-side lease inventory for concurrent authoring sessions. */
  localReservedPorts:readonly number[];
  /** Administrator-defined additional blocked ports, never user-supplied. */
  adminReservedPorts:readonly number[];
  evidence:{
    catalogueComplete:boolean;
    tenantComplete:boolean;
    sensorBindingsComplete:boolean;
    reservationsComplete:boolean;
  };
};
export type PortPlanOptions={
  rangeStart?:number;
  rangeEnd?:number;
  requestedPort?:number;
  /** RFC3164/RFC5424 Syslog enforce the same 6800 listener minimum. */
  parserFormat?:"syslog_rfc3164"|"syslog_rfc5424";
};
export type PortProposal={
  contract:"stellar-parser-listener-port-proposal.v0.1";
  recommendedPort:number;
  source:"SUGGESTED"|"USER_OVERRIDE";
  status:"CANDIDATE_REQUIRES_DEPLOY_RECHECK"|"INCOMPLETE_EVIDENCE";
  missingEvidence:string[];
  occupiedPorts:number[];
  candidateOnly:true;
  deployableNow:false;
  verifiedIngestPort:false;
  /** Same chosen source port for sensor destination and generated CONF. */
  sensorIngestPort:number;
  needsFinalRecheck:true;
};

function validPort(n:unknown):n is number{
  return typeof n==="number"&&Number.isInteger(n)&&n>=1&&n<=65535;
}
function knownOccupancy(data:PortInventory):Set<number>{
  if(!data||typeof data!=="object"||!data.evidence||
     typeof data.evidence!=="object")reject("PORT_EVIDENCE_INVALID");
  const arrays=[data.cataloguePorts,data.tenantLegacyPorts,
    data.sensorParserPorts,data.localReservedPorts,data.adminReservedPorts];
  if(arrays.some(values=>!Array.isArray(values)||values.length>20000||
    values.some(value=>!validPort(value))))
    reject("PORT_EVIDENCE_INVALID");
  const f=data.evidence;
  if([f.catalogueComplete,f.tenantComplete,
      f.sensorBindingsComplete,f.reservationsComplete].some(value=>typeof value!=="boolean"))
    reject("PORT_EVIDENCE_INVALID");
  return new Set(arrays.flat());
}

/** Browser override changes compiled Ruby+CONF before either download/apply. */
export function validatePortOverride(port:unknown,data:PortInventory,
  parserFormat?:"syslog_rfc3164"|"syslog_rfc5424"):number{
  const occupied=knownOccupancy(data);
  if(!validPort(port))reject("PORT_INVALID");
  if(["syslog_rfc3164","syslog_rfc5424"].includes(parserFormat??"")&&port<6800)
    reject("PORT_SYSLOG_MINIMUM");
  if(port<1024)reject("PORT_PRIVILEGED");
  if(occupied.has(port))reject("PORT_ALREADY_OCCUPIED");
  return port;
}

export function proposeParserPort(data:PortInventory,
  options:PortPlanOptions={}):PortProposal{
  const occupied=knownOccupancy(data);
  if(options.parserFormat!==undefined&&
    !["syslog_rfc3164","syslog_rfc5424"].includes(options.parserFormat))
    reject("PORT_FORMAT_INVALID");
  // New DRAFT receivers start at 6801; availability is still only a candidate.
  const start=options.rangeStart??6801;
  const end=options.rangeEnd??30000;
  if(["syslog_rfc3164","syslog_rfc5424"].includes(options.parserFormat??"")&&start<6800)
    reject("PORT_SYSLOG_MINIMUM");
  if(!validPort(start)||!validPort(end)||start<1024||start>end||
    end-start>30000)reject("PORT_RANGE_INVALID");
  let chosen:number;
  let source:PortProposal["source"];
  if(options.requestedPort!==undefined){
    chosen=validatePortOverride(options.requestedPort,data,options.parserFormat);
    source="USER_OVERRIDE";
  }else{
    let candidate:number|undefined;
    for(let port=start;port<=end;port++){
      if(!occupied.has(port)){candidate=port;break;}
    }
    if(candidate===undefined)reject("PORT_NO_CANDIDATE");
    chosen=candidate;
    source="SUGGESTED";
  }
  const missingEvidence:string[]=[];
  const sources=[
    ["catalogue",data.evidence.catalogueComplete],
    ["tenant",data.evidence.tenantComplete],
    ["sensorBindings",data.evidence.sensorBindingsComplete],
    ["localReservations",data.evidence.reservationsComplete],
  ] as const;
  for(const [name,present] of sources)if(!present)missingEvidence.push(name);
  return {
    contract:"stellar-parser-listener-port-proposal.v0.1",
    recommendedPort:chosen,
    source,
    status:missingEvidence.length?"INCOMPLETE_EVIDENCE":"CANDIDATE_REQUIRES_DEPLOY_RECHECK",
    missingEvidence,occupiedPorts:[...occupied].sort((a,b)=>a-b),
    candidateOnly:true,deployableNow:false,verifiedIngestPort:false,
    sensorIngestPort:chosen,needsFinalRecheck:true,
  };
}
