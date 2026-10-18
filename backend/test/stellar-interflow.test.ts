import assert from "node:assert/strict";
import test from "node:test";
import {
  buildInterflowQuery,compareInterflowHits,
} from "../src/stellar-interflow.js";
import {LegacyPocClient,LegacyApiError} from "../src/stellar-legacy-client.js";

const tenant="synthetic_tenant";
const runId="test_run_0123456789abcdef0123456789abcdef";
const startMs=Date.parse("2026-10-12T01:00:00Z");
const endMs=Date.parse("2026-10-12T01:03:00Z");
const requested={index:"session" as const,runId,markerField:"log.run_id",
  startMs,endMs,limit:20};
const expected={srcip:"192.0.2.44",dstport:443,action:"deny"};

test("bounded User Scope Interflow search uses documented GET q, size and exact tenant/time/run-marker filters",()=>{
  const plan=buildInterflowQuery(tenant,requested);
  assert.equal(plan.method,"GET");
  assert.equal(plan.path,"/connect/api/data/session/_search");
  assert.equal(plan.params.get("size"),"20");
  assert.equal(plan.params.get("track_total_hits"),"false");
  const q=plan.params.get("q")??"";
  assert.match(q,/tenantid:"synthetic_tenant"/);
  assert.ok(q.includes('log.run_id:"'+runId+'"'));
  assert.ok(q.includes("timestamp:["+startMs+" TO "+endMs+"]"));
  assert.equal(q.includes("OR *:*"),false);
  assert.equal(plan.realTargetVerified,false);
});

test("search cannot be widened by untrusted tenant, index, query field, marker or date range",()=>{
  for(const bad of [
    {...requested,index:"../custom_log_parsers"},
    {...requested,index:"*"},
    {...requested,markerField:"log.run_id OR *:*"},
    {...requested,runId:"test_run_x"},
    {...requested,startMs:endMs+1},
    {...requested,endMs:startMs+90000000},
    {...requested,limit:1000},
  ]){
    assert.throws(()=>buildInterflowQuery(tenant,bad as any),/INTERFLOW_/);
  }
  assert.throws(()=>buildInterflowQuery('bad" OR *:*',requested),/INTERFLOW_TENANT_INVALID/);
});

test("interflow field-level result comparison returns only statuses, never actual raw event body",()=>{
  const plan=buildInterflowQuery(tenant,requested);
  const payload={hits:{hits:[
    {_source:{tenantid:tenant,timestamp:startMs+5000,
      log:{run_id:runId},srcip:"192.0.2.44",dstport:443,action:"deny",
      raw_log:"SECRET_CUSTOMER_EVENT_MUST_NOT_APPEAR"}},
  ]}};
  const result=compareInterflowHits(payload,plan,expected);
  assert.equal(result.state,"MATCHED_RESPONSE_FIELDS");
  assert.equal(result.matchCount,1);
  assert.deepEqual(result.fields.map(x=>x.status),["MATCH","MATCH","MATCH"]);
  assert.equal(result.sensorReceivedVerified,false);
  assert.equal(result.endToEndVerified,false);
  assert.equal(JSON.stringify(result).includes("SECRET_CUSTOMER"),false);
  assert.equal(JSON.stringify(result).includes("192.0.2.44"),false);
});

test("missing tenant/run marker or mismatched field never reports real parsing success",()=>{
  const plan=buildInterflowQuery(tenant,requested);
  const missing=compareInterflowHits({hits:{hits:[]}},plan,expected);
  assert.equal(missing.state,"NO_MATCH");
  assert.equal(missing.endToEndVerified,false);
  const mixed=compareInterflowHits({hits:{hits:[
    {_source:{tenantid:"another_tenant",timestamp:startMs+5000,
      log:{run_id:runId},srcip:"192.0.2.44"}},
    {_source:{tenantid:tenant,timestamp:startMs+5000,
      srcip:"192.0.2.44"}},
  ]}},plan,expected);
  assert.equal(mixed.state,"NO_MATCH");
  const wrong=compareInterflowHits({hits:{hits:[
    {_source:{tenantid:tenant,timestamp:startMs+5000,
      log:{run_id:runId},srcip:"192.0.2.77",dstport:443}},
  ]}},plan,expected);
  assert.equal(wrong.state,"FIELD_MISMATCH");
  assert.ok(wrong.fields.some(x=>x.status==="MISMATCH"));
  assert.ok(wrong.fields.some(x=>x.status==="MISSING"));
});

test("POC User Scope Interflow client uses GET, JWT renewal and never echoes raw vendor documents",async()=>{
  const calls:Array<{path:string;method:string;q:string|null}>=[];
  let auth=0,read=0;
  const client=new LegacyPocClient({
    host:"https://poc-apac.stellarcyber.cloud",tenant,apiKey:"PRIVATE_SCOPE_KEY",
    fetchImpl:async(input,init)=>{
      const url=new URL(String(input));
      const method=init?.method??"GET";
      calls.push({path:url.pathname,method,q:url.searchParams.get("q")});
      if(url.pathname.endsWith("/access_token")){
        auth++;
        return new Response(JSON.stringify({access_token:"PRIVATE_JWT_"+auth}),{
          status:200,headers:{"content-type":"application/json"}});
      }
      if(url.pathname.endsWith("/_search")){
        read++;
        assert.equal(method,"GET");
        assert.ok(url.searchParams.get("q")?.includes('tenantid:"'+tenant+'"'));
        if(read===1)return new Response("PRIVATE_401_BODY",{status:401});
        return new Response(JSON.stringify({hits:{hits:[
          {_source:{tenantid:tenant,timestamp:startMs+5000,log:{run_id:runId},
            srcip:"192.0.2.44",dstport:443,action:"deny",raw_log:"PRIVATE_RAW_EVENT"}},
        ]}}),{status:200,headers:{"content-type":"application/json"}});
      }
      throw Error("Unexpected mock request");
    },
  });
  const result=await client.searchInterflow(requested,expected);
  assert.equal(result.state,"MATCHED_RESPONSE_FIELDS");
  assert.equal(result.endToEndVerified,false);
  assert.equal(auth,2,"only one GET 401 JWT refresh");
  assert.equal(read,2);
  assert.equal(JSON.stringify(result).includes("PRIVATE_RAW_EVENT"),false);
  assert.equal(JSON.stringify(result).includes("PRIVATE_SCOPE_KEY"),false);
});

test("Interflow 403 permissions error is redacted, no retry/false-success",async()=>{
  let calls=0;
  const client=new LegacyPocClient({
    host:"https://poc-apac.stellarcyber.cloud",tenant,apiKey:"PRIVATE_SCOPE_KEY",
    fetchImpl:async(input)=>{
      const url=new URL(String(input));
      if(url.pathname.endsWith("/access_token")){
        return new Response(JSON.stringify({access_token:"PRIVATE_JWT"}),{status:200});
      }
      calls++;
      return new Response("CUSTOMER_RESPONSE_RAW_NEVER_ECHO",{status:403});
    },
  });
  await assert.rejects(()=>client.searchInterflow(requested,expected),(error:unknown)=>
    error instanceof LegacyApiError&&error.httpStatus===403&&
    !error.message.includes("CUSTOMER_RESPONSE_RAW"));
  assert.equal(calls,1);
});
