/**
 * Bounded User Scope Stellar Lucene Interflow query/field-diff contract.
 *
 * Based on the independent xdr-labs/stellar-data-exporter User Scope GET
 * /connect/api/data/{index}/_search with tenantid, timestamp, size and q.
 * This module is pure, does not contain credentials or execute network calls.
 * Expected field comparisons never echo raw/normalized customer data.
 */
export type InterflowIndex="session"|"threat"|"syslog"|"winlogevent";
export type InterflowSearchRequest={
  index:InterflowIndex;
  runId:string;
  markerField:string;
  startMs:number;
  endMs:number;
  limit:number;
};
export type InterflowQueryPlan={
  method:"GET";
  path:string;
  params:URLSearchParams;
  tenant:string;
  runId:string;
  markerField:string;
  startMs:number;
  endMs:number;
  limit:number;
  realTargetVerified:false;
};
export type InterflowFieldStatus={field:string;status:"MATCH"|"MISMATCH"|"MISSING"};
export type InterflowFieldResult={
  state:"MATCHED_RESPONSE_FIELDS"|"FIELD_MISMATCH"|"NO_MATCH";
  matchCount:number;
  fields:InterflowFieldStatus[];
  sensorReceivedVerified:false;
  endToEndVerified:false;
  runtimeParsingVerified:false;
  targetImportVerified:false;
};
export class InterflowContractError extends Error{
  constructor(readonly code:string){super(code);this.name="InterflowContractError";}
}
function invalid(code:string):never{throw new InterflowContractError(code);}
const TENANT=/^[A-Za-z0-9_-]{1,128}$/;
const RUN=/^test_run_[0-9a-f]{32}$/;
const FIELD=/^[A-Za-z_][A-Za-z0-9_.-]{0,95}$/;
const BAD=new Set(["__proto__","constructor","prototype"]);
const INDEX_SET=new Set(["session","threat","syslog","winlogevent"]);
function validateField(field:string):boolean{
  return typeof field==="string"&&FIELD.test(field)&&
    field.split(".").every(part=>!!part&&!BAD.has(part));
}

export function buildInterflowQuery(tenant:string,
  request:InterflowSearchRequest):InterflowQueryPlan{
  if(typeof tenant!=="string"||!TENANT.test(tenant))
    invalid("INTERFLOW_TENANT_INVALID");
  if(!request||typeof request!=="object"||
    !INDEX_SET.has(request.index))invalid("INTERFLOW_INDEX_INVALID");
  if(!RUN.test(request.runId))invalid("INTERFLOW_RUN_ID_INVALID");
  if(!validateField(request.markerField))
    invalid("INTERFLOW_MARKER_FIELD_INVALID");
  if(!Number.isSafeInteger(request.startMs)||
    !Number.isSafeInteger(request.endMs)||
    request.startMs<0||request.startMs>=request.endMs||
    request.endMs-request.startMs>900000)
    invalid("INTERFLOW_TIME_RANGE_INVALID");
  if(!Number.isInteger(request.limit)||request.limit<1||request.limit>100)
    invalid("INTERFLOW_RESULT_LIMIT_INVALID");
  const params=new URLSearchParams({
    size:String(request.limit),
    track_total_hits:"false",
    q:'(tenantid:"'+tenant+'") AND ('+request.markerField+':"'+request.runId+
      '") AND timestamp:['+request.startMs+' TO '+request.endMs+']',
  });
  return {
    method:"GET",
    path:"/connect/api/data/"+request.index+"/_search",
    params,tenant,runId:request.runId,markerField:request.markerField,
    startMs:request.startMs,endMs:request.endMs,limit:request.limit,
    realTargetVerified:false,
  };
}

function atPath(record:Record<string,unknown>,path:string):unknown{
  if(Object.hasOwn(record,path))return record[path];
  let node:unknown=record;
  for(const part of path.split(".")){
    if(!node||typeof node!=="object"||Array.isArray(node)||
       !Object.hasOwn(node,part))return undefined;
    node=(node as Record<string,unknown>)[part];
  }
  return node;
}
function isRecord(value:unknown):value is Record<string,unknown>{
  return value!==null&&typeof value==="object"&&!Array.isArray(value);
}
export function compareInterflowHits(
  payload:unknown,plan:InterflowQueryPlan,
  expected:Record<string,string|number|boolean>
):InterflowFieldResult{
  if(!isRecord(expected)||Object.keys(expected).length<1||
    Object.keys(expected).length>16||
    Object.entries(expected).some(([key,value])=>
      !validateField(key)||
      !(typeof value==="string"||
        typeof value==="boolean"||
        (typeof value==="number"&&Number.isFinite(value)))))
    invalid("INTERFLOW_EXPECTED_FIELDS_INVALID");
  if(!isRecord(payload)||!isRecord(payload.hits)||
     !Array.isArray(payload.hits.hits)||
     payload.hits.hits.length>100)
    invalid("INTERFLOW_RESPONSE_INVALID");
  const names=Object.keys(expected);
  const empty:InterflowFieldResult={
    state:"NO_MATCH",matchCount:0,
    fields:names.map(field=>({field,status:"MISSING"})),
    sensorReceivedVerified:false,endToEndVerified:false,
    runtimeParsingVerified:false,targetImportVerified:false,
  };
  const candidates:InterflowFieldStatus[][]=[];
  for(const hit of payload.hits.hits){
    if(!isRecord(hit)||!isRecord(hit._source))continue;
    const source=hit._source;
    if(source.tenantid!==plan.tenant)continue;
    if(atPath(source,plan.markerField)!==plan.runId)continue;
    let eventMs=source.timestamp;
    if(typeof eventMs==="string")eventMs=Date.parse(eventMs);
    if(!Number.isFinite(eventMs)||typeof eventMs!=="number"||
      eventMs<plan.startMs||eventMs>plan.endMs)continue;
    const fields:InterflowFieldStatus[]=names.map(field=>{
      const actual=atPath(source,field);
      return {field,status:actual===undefined?"MISSING":
        actual===expected[field]?"MATCH":"MISMATCH"};
    });
    candidates.push(fields);
  }
  if(candidates.length===0)return empty;
  const best=candidates.sort((a,b)=>
    b.filter(x=>x.status==="MATCH").length-
    a.filter(x=>x.status==="MATCH").length)[0]!;
  return {
    state:best.every(x=>x.status==="MATCH")?
      "MATCHED_RESPONSE_FIELDS":"FIELD_MISMATCH",
    matchCount:candidates.length,fields:best,
    sensorReceivedVerified:false,endToEndVerified:false,
    runtimeParsingVerified:false,targetImportVerified:false,
  };
}
