import assert from "node:assert/strict";
import test from "node:test";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {LegacyPocClient} from "../src/stellar-legacy-client.js";
import {SyntheticSessionController} from "../src/testlab-session.js";

const tenant="synthetic_tenant";
const host="https://poc-apac.stellarcyber.cloud";
const startMs=Date.parse("2026-10-12T01:00:00Z");
const endMs=Date.parse("2026-10-12T01:02:00Z");
async function localServer(options:Parameters<typeof createBackendServer>[0],
  run:(base:string)=>Promise<void>){
  const server=createBackendServer(options);
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{await run("http://127.0.0.1:"+(server.address() as AddressInfo).port);}
  finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
}
function request(base:string,body:unknown,actor="actor-a"){
  return fetch(base+"/api/v1/test-lab/interflow/search",{
    method:"POST",headers:{"content-type":"application/json","x-test-actor":actor},
    body:JSON.stringify(body),
  });
}
test("Interflow HTTP is off without audited, owner-authenticated and configured backend",async()=>{
  await localServer({},async base=>{
    const response=await request(base,{index:"session"});
    assert.equal(response.status,403);
    assert.equal((await response.json() as any).error,"INTERFLOW_SEARCH_DISABLED");
  });
});

test("Interflow HTTP correlates mock tenant/run/field diff without returning raw vendor event",async()=>{
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{},
  });
  const s=await runner.start({
    sample:{format:"json",source:JSON.stringify({
      time:"2026-01-01T01:02:03Z",srcip:"192.0.2.4",test:{run_id:"synthetic_before"}}),
      seed:1,sequence:0,variableFields:[],runMarkerField:"test.run_id"},
    approvalId:"owner-test-interflow",ratePerSecond:1,leaseMs:1300,maxEvents:3,
  },"actor-a");
  const audits:Array<{index:string;fieldNames:string[];runId:string}>=[];
  let upstream=0;
  const client=new LegacyPocClient({host,tenant,apiKey:"PRIVATE_OWNER_KEY",
    fetchImpl:async(input)=>{
      const url=new URL(String(input));
      if(url.pathname.endsWith("/access_token"))
        return new Response(JSON.stringify({access_token:"PRIVATE_JWT"}),{status:200});
      assert.equal(url.pathname,"/connect/api/data/session/_search");
      assert.ok(url.searchParams.get("q")?.includes('tenantid:"'+tenant+'"'));
      assert.ok(url.searchParams.get("q")?.includes(s.runId));
      upstream++;
      return new Response(JSON.stringify({hits:{hits:[{
        _source:{tenantid:tenant,timestamp:startMs+5000,
          log:{run_id:s.runId},srcip:"192.0.2.44",
          raw_log:"SENSITIVE_EVENT_NOT_FOR_BROWSER"},
      }]}}),{status:200});
    },
  });
  try{
    await localServer({legacyClient:client,testLabController:runner,
      authorizeInterflowRead:async req=>
        req.headers["x-test-actor"]==="actor-a"?"actor-a":
        req.headers["x-test-actor"]==="actor-b"?"actor-b":null,
      auditInterflowRead:async event=>{audits.push(event);},
    },async base=>{
      const body={runId:s.runId,index:"session",markerField:"log.run_id",
        startMs,endMs,limit:20,expectedFields:{srcip:"192.0.2.44"}};
      const foreign=await request(base,body,"actor-b");
      assert.equal(foreign.status,404);
      assert.equal(upstream,0);
      const read=await request(base,body,"actor-a");
      assert.equal(read.status,200);
      const result=await read.json() as any;
      assert.equal(result.state,"MATCHED_RESPONSE_FIELDS");
      assert.equal(result.fields[0].status,"MATCH");
      assert.equal(result.endToEndVerified,false);
      assert.equal(result.sensorReceivedVerified,false);
      assert.equal(JSON.stringify(result).includes("SENSITIVE_EVENT"),false);
      assert.equal(JSON.stringify(result).includes("192.0.2.44"),false);
      assert.equal(JSON.stringify(result).includes("PRIVATE_JWT"),false);
      assert.equal(audits.length,1);
      assert.deepEqual(audits[0]!.fieldNames,["srcip"]);
      assert.equal(JSON.stringify(audits).includes("192.0.2.44"),false);
      assert.equal(upstream,1);
      const widen=await request(base,{...body,limit:9999},"actor-a");
      assert.equal(widen.status,422);
      assert.equal(upstream,1);
    });
  }finally{runner.stopAll();}
});

test("Interflow HTTP refuses unaudited read before obtaining a vendor JWT",async()=>{
  let upstream=0;
  const client=new LegacyPocClient({host,tenant,apiKey:"PRIVATE_OWNER_KEY",
    fetchImpl:async()=>{upstream++;throw Error("must not read unauthorized vendor");},
  });
  const runner=new SyntheticSessionController({approveStart:async()=>true,deliver:async()=>{}});
  try{
    await localServer({legacyClient:client,testLabController:runner,
      authorizeInterflowRead:async()=> "actor-a",
    },async base=>{
      const response=await request(base,{
        index:"session",runId:"test_run_0123456789abcdef0123456789abcdef",
        markerField:"log.run_id",startMs,endMs,limit:20,expectedFields:{srcip:"192.0.2.44"},
      });
      assert.equal(response.status,403);
      assert.equal(upstream,0);
    });
  }finally{runner.stopAll();}
});

test("Interflow audit failure blocks upstream lookup before JWT acquisition",async()=>{
  let upstream=0;
  const runner=new SyntheticSessionController({
    approveStart:async()=>true,deliver:async()=>{},
  });
  const s=await runner.start({
    sample:{format:"json",source:JSON.stringify({
      time:"2026-01-01T01:02:03Z",srcip:"192.0.2.4",test:{run_id:"synthetic_before"}}),
      seed:1,sequence:0,variableFields:[],runMarkerField:"test.run_id"},
    approvalId:"owner-test-interflow",ratePerSecond:1,leaseMs:1300,maxEvents:3,
  },"actor-a");
  const client=new LegacyPocClient({
    host,tenant,apiKey:"PRIVATE_KEY",
    fetchImpl:async()=>{upstream++;throw Error("No audit, no upstream");},
  });
  try{
    await localServer({
      legacyClient:client,testLabController:runner,
      authorizeInterflowRead:async()=> "actor-a",
      auditInterflowRead:async()=>{throw Error("PRIVATE_AUDIT_FAILURE");},
    },async base=>{
      const result=await request(base,{
        index:"session",runId:s.runId,markerField:"log.run_id",
        startMs,endMs,limit:20,expectedFields:{srcip:"192.0.2.44"},
      });
      assert.equal(result.status,503);
      const body=await result.json() as any;
      assert.equal(body.error,"INTERFLOW_AUDIT_UNAVAILABLE");
      assert.equal(JSON.stringify(body).includes("PRIVATE_AUDIT_FAILURE"),false);
      assert.equal(upstream,0);
    });
  }finally{runner.stopAll();}
});
