import assert from "node:assert/strict";
import test from "node:test";
import type {AddressInfo} from "node:net";
import {createBackendServer} from "../src/http.js";
import {LegacyPocClient} from "../src/stellar-legacy-client.js";

async function withServer(options:Parameters<typeof createBackendServer>[0],run:(url:string)=>Promise<void>){
  const srv=createBackendServer(options);
  await new Promise<void>(resolve=>srv.listen(0,"127.0.0.1",resolve));
  try{await run("http://127.0.0.1:"+(srv.address() as AddressInfo).port);}
  finally{await new Promise<void>(resolve=>srv.close(()=>resolve()));}
}

test("tenant-authorized port candidate reads verified backend inventory but stays unreserved",async()=>{
  const upstream:string[]=[];
  const client=new LegacyPocClient({host:"https://poc-apac.stellarcyber.cloud",
    tenant:"synthetic_tenant",apiKey:"local-secret",
    fetchImpl:async(input)=>{
      const url=new URL(String(input));upstream.push(url.pathname);
      const data=url.pathname.endsWith("/access_token")?{access_token:"private-jwt"}:
        url.pathname.endsWith("/custom_log_parsers/parsers")?{data:[{port:20000},{port:20001}]}:
        {data:[{parser_name:"customized_demo",version:"1.0.0",cust_id:"synthetic_tenant",port:20002}]};
      return new Response(JSON.stringify(data),{status:200,headers:{"content-type":"application/json"}});
    }});
  await withServer({legacyClient:client,authorizeLegacyRead:async()=>true},async base=>{
    const response=await fetch(base+"/api/v1/stellar/legacy/port-proposal");
    assert.equal(response.status,200);
    const p=await response.json() as any;
    assert.equal(p.recommendedPort,20003);
    assert.equal(p.deployableNow,false);
    assert.equal(p.needsFinalRecheck,true);
    assert.equal(p.status,"INCOMPLETE_EVIDENCE");
    assert.ok(p.missingEvidence.includes("sensorBindings"));
    assert.equal(p.sensorIngestPort,p.recommendedPort);
    assert.equal(JSON.stringify(p).includes("local-secret"),false);
    const conflict=await fetch(base+"/api/v1/stellar/legacy/port-proposal?port=20000");
    assert.equal(conflict.status,422);
    const selected=await fetch(base+"/api/v1/stellar/legacy/port-proposal?port=25000");
    assert.equal(selected.status,200);
    const choice=await selected.json() as any;
    assert.equal(choice.recommendedPort,25000);
    assert.equal(choice.source,"USER_OVERRIDE");
    assert.equal(choice.deployableNow,false);
    const syslog=await fetch(base+"/api/v1/stellar/legacy/port-proposal?format=syslog_rfc5424");
    assert.equal(syslog.status,200);
    const port=await syslog.json() as any;
    assert.equal(port.recommendedPort,6800);
    assert.equal(port.sensorIngestPort,6800);
    assert.equal(port.deployableNow,false);
    const belowMin=await fetch(base+"/api/v1/stellar/legacy/port-proposal?format=syslog_rfc5424&port=6799");
    assert.equal(belowMin.status,422);
    assert.equal((await belowMin.json() as any).error,"PORT_SYSLOG_MINIMUM");
    const matching=await fetch(base+"/api/v1/stellar/legacy/port-proposal?format=syslog_rfc5424&port=6800");
    assert.equal(matching.status,200);
    assert.equal((await matching.json() as any).sensorIngestPort,6800);
    assert.ok(upstream.includes("/connect/api/v1/custom_log_parsers/parsers"));
  });
});

test("port proposal requires same read grant and never opens upstream when denied",async()=>{
  let called=0;
  const client=new LegacyPocClient({host:"https://poc-apac.stellarcyber.cloud",
    tenant:"synthetic_tenant",apiKey:"local-secret",fetchImpl:async()=>{
      called++;throw Error("not authorized");
    }});
  await withServer({legacyClient:client,authorizeLegacyRead:async()=>false},async base=>{
    const blocked=await fetch(base+"/api/v1/stellar/legacy/port-proposal");
    assert.equal(blocked.status,403);
    assert.equal(called,0);
  });
});
