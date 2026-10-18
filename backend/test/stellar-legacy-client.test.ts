import assert from "node:assert/strict";
import test from "node:test";
import {LegacyPocClient, type LegacyAuditEvent} from "../src/stellar-legacy-client.js";
import {makeDisposablePocTestPair,makeLegacyUploadPlan} from "../src/stellar-legacy-plan.js";
import {sampleProject} from "./fixture.js";

const host="https://poc-apac.stellarcyber.cloud";
const tenant="synthetic_tenant";
const path="/connect/api/v1";
const respond=(value:unknown,status=200)=>new Response(JSON.stringify(value),{
  status,headers:{"content-type":"application/json"},
});
function pair(version="1.0.0"){
 const p=sampleProject();p.slug="ps_api_crud_test_a1b2c3";
 p.receiver={...p.receiver,bindAddress:"127.0.0.1",port:7891};
 return makeLegacyUploadPlan(makeDisposablePocTestPair(p),tenant,version);
}

test("POC client accepts only host allowlist, never discloses key/JWT; JWT age and GET 401 refresh once",async()=>{
  let now=0,auth=0,list=0;
  const requests:string[]=[];
  const fetchImpl:typeof fetch=async (input,init)=>{
    const url=new URL(String(input));requests.push(url.pathname);
    assert.equal(url.origin,host);
    assert.equal(init?.redirect,"manual");
    if(url.pathname.endsWith("/access_token")){
      assert.equal((init?.headers as Record<string,string>).Authorization,"Bearer key_SENSITIVE_NEVER_EXPOSE");
      auth++;return respond({access_token:"jwt_PRIVATE_"+auth});
    }
    assert.equal(url.searchParams.get("cust_id"),tenant);
    const h=(init?.headers as Record<string,string>).Authorization;
    assert.ok(h?.startsWith("Bearer jwt_PRIVATE_"));
    list++;
    return list===1?respond({error:"expire_PRIVATE"},401):respond({
      data:[{parser_name:"customized_alpha",version:"1.2.0",cust_id:tenant,port:8123,
        authorization:"DO_NOT_RETURN_PRIVATE"}]
    });
  };
  const client=new LegacyPocClient({host,tenant,apiKey:"key_SENSITIVE_NEVER_EXPOSE",fetchImpl,clock:()=>now});
  const records=await client.listParsers();
  assert.equal(records.length,1);
  assert.equal(records[0]?.name,"customized_alpha");
  assert.equal(records[0]?.version,"1.2.0");
  assert.equal(JSON.stringify(records).includes("DO_NOT_RETURN_PRIVATE"),false);
  assert.equal(auth,2,"GET 401 refreshed once");
  now=480001;
  await client.listParsers();
  assert.equal(auth,3,"JWT proactive renewal after bounded age");
  assert.equal(JSON.stringify(client).includes("SENSITIVE"),false);
  assert.equal(JSON.stringify(client).includes("jwt_PRIVATE"),false);
  assert.throws(()=>new LegacyPocClient({host:"https://example.com",tenant,apiKey:"x",fetchImpl}),/POC_HOST_UNAUTHORIZED/);
});

test("POC writes need server approval, strictly test-only pair and auditable before/after events",async()=>{
  const records:Array<{parser_name:string;version:string;port:number;cust_id:string}>=[];
  const requests:Array<{method:string;url:string;partNames?:string[];partFiles?:string[]}>=[];
  const events:LegacyAuditEvent[]=[];
  let approvals=0,auth=0;
  const fetchImpl:typeof fetch=async(input,init)=>{
    const url=new URL(String(input));const method=init?.method||"GET";
    if(url.pathname===path+"/access_token"){auth++;return respond({access_token:"jwt_SYNTHETIC"});}
    if(url.pathname===path+"/custom_log_parsers/parsers")return respond({data:[{port:7111}]});
    if(url.pathname===path+"/custom_log_parsers"&&method==="GET")return respond({data:records});
    if(url.pathname===path+"/custom_log_parsers"&&method==="POST"){
      assert.ok(init?.body instanceof FormData);
      const f=init.body as FormData;
      const parts=f.getAll("file");assert.equal(parts.length,2);
      assert.equal(f.get("parser_name"),"customized_ps_api_crud_test_a1b2c3");
      assert.equal(f.get("cust_id"),tenant);
      assert.equal(f.get("version"),"1.0.0");
      const names=parts.map(part=>(part as File).name);
      assert.deepEqual(names,["customized_ps_api_crud_test_a1b2c3","customized_ps_api_crud_test_a1b2c3.conf"]);
      requests.push({method,url:url.pathname,partNames:names});
      records.push({parser_name:String(f.get("parser_name")),version:"1.0.0",port:7891,cust_id:tenant});
      return respond({});
    }
    if(method==="PUT"){
      const f=init?.body as FormData;assert.equal(f.get("version"),"1.0.1");
      assert.equal(f.get("parser_name"),null);
      assert.equal(f.getAll("file").length,2);
      records[0]!.version="1.0.1";requests.push({method,url:url.pathname});
      return respond({});
    }
    if(method==="DELETE"){
      assert.equal(url.searchParams.get("cust_id"),tenant);
      records.pop();requests.push({method,url:url.pathname});
      return respond({});
    }
    throw Error("Unexpected method in synthetic adapter");
  };
  const client=new LegacyPocClient({
    host,tenant,apiKey:"key_PRIVATE",fetchImpl,
    approveWrite:async intent=>{approvals++;assert.equal(intent.tenant,tenant);return true;},
    audit:async event=>{events.push(event);},
  });
  const createPlan=pair();
  await assert.rejects(()=>client.create(createPlan,{confirmed:false,approvalId:"ticket-one"}),/POC_CONFIRMATION_REQUIRED/);
  assert.equal(auth,0,"no token request before confirmation and proof");
  const created=await client.create(createPlan,{confirmed:true,approvalId:"ticket-one"});
  assert.equal(created.apiRegistrationVerified,true);
  assert.equal(created.runtimeParsingVerified,false);
  assert.equal(created.modularActivationVerified,false);
  assert.equal(created.method,"POST");
  assert.equal(records.length,1);
  const updated=await client.update(pair("1.0.1"),{
    expectedVersion:"1.0.0",confirmed:true,approvalId:"ticket-two"});
  assert.equal(updated.apiRegistrationVerified,true);
  const deleted=await client.delete("customized_ps_api_crud_test_a1b2c3",{
    expectedVersion:"1.0.1",confirmed:true,approvalId:"ticket-three"});
  assert.equal(deleted.apiRegistrationVerified,true);
  assert.equal(records.length,0);
  assert.deepEqual(requests.map(x=>x.method),["POST","PUT","DELETE"]);
  assert.equal(approvals,3);
  assert.equal(events.filter(e=>e.phase==="BEFORE").length,3);
  assert.equal(events.filter(e=>e.phase==="AFTER").length,3);
  assert.equal(JSON.stringify(events).includes("key_PRIVATE"),false);
  assert.equal(JSON.stringify(events).includes("jwt_SYNTHETIC"),false);
  assert.equal(JSON.stringify(events).includes("STELLAR_INIT_BEGIN"),false);
});

test("Legacy client blocks missing write gate, duplicate parser, occupied port and stale expected version before HTTP mutation",async()=>{
  const calls:string[]=[];
  const fetchImpl:typeof fetch=async(input,init)=>{
    const pathname=new URL(String(input)).pathname;calls.push((init?.method||"GET")+" "+pathname);
    if(pathname.endsWith("/access_token"))return respond({access_token:"jwt"});
    if(pathname.endsWith("/parsers"))return respond({data:[{port:7891}]});
    return respond({data:[{parser_name:"customized_ps_api_crud_test_a1b2c3",version:"1.0.0",cust_id:tenant}]});
  };
  const noGate=new LegacyPocClient({host,tenant,apiKey:"secret",fetchImpl});
  await assert.rejects(()=>noGate.create(pair(),{confirmed:true,approvalId:"test"}),/POC_WRITE_DISABLED/);
  assert.equal(calls.length,0);
  const client=new LegacyPocClient({host,tenant,apiKey:"secret",fetchImpl,
    approveWrite:async()=>true,audit:async()=>{}});
  await assert.rejects(()=>client.create(pair(),{confirmed:true,approvalId:"ok-1"}),/POC_NAME_CONFLICT/);
  await assert.rejects(()=>client.update(pair("1.0.1"),{
    confirmed:true,approvalId:"ok-1",expectedVersion:"0.0.9"}),/POC_VERSION_CONFLICT/);
  assert.equal(calls.filter(x=>/POST \/connect\/api\/v1\/custom_log_parsers$|PUT /.test(x)).length,0);
});

test("Non-idempotent writes never retry 401, errors contain no secret or vendor raw body",async()=>{
  let writes=0;
  const fetchImpl:typeof fetch=async(input,init)=>{
    const path=new URL(String(input)).pathname;
    if(path.endsWith("/access_token"))return respond({access_token:"jwt_SECRET"});
    if((init?.method||"GET")==="GET")return respond({data:path.endsWith("/parsers")?[{port:7088}]:[]});
    writes++;return respond({error:"VENDOR_SECRET_RESPONSE"},401);
  };
  const client=new LegacyPocClient({host,tenant,apiKey:"key_SECRET",fetchImpl,
    approveWrite:async()=>true,audit:async()=>{}});
  await assert.rejects(()=>client.create(pair(),{confirmed:true,approvalId:"owner-ok"}),
    (e:unknown)=>e instanceof Error && e.message.includes("401") &&
      !e.message.includes("VENDOR_SECRET") && !e.message.includes("key_SECRET"));
  assert.equal(writes,1);
});

test("POC port collision rejects create before any mutation; backend audit failure rejects write before POST",async()=>{
  let created=0;
  const fetchImpl:typeof fetch=async(input,init)=>{
    const url=new URL(String(input));
    if(url.pathname.endsWith("/access_token"))return respond({access_token:"jwt"});
    if(url.pathname.endsWith("/parsers"))return respond({data:[{port:7891}]});
    if((init?.method||"GET")==="GET")return respond({data:[]});
    created++;return respond({});
  };
  const client=new LegacyPocClient({host,tenant,apiKey:"secret",fetchImpl,
    approveWrite:async()=>true,audit:async()=>{}});
  await assert.rejects(()=>client.create(pair(),{confirmed:true,approvalId:"ticket-1"}),/POC_PORT_CONFLICT/);
  assert.equal(created,0);
  const auditFetch:typeof fetch=async(input,init)=>{
    const url=new URL(String(input));
    if(url.pathname.endsWith("/access_token"))return respond({access_token:"jwt"});
    if(url.pathname.endsWith("/parsers"))return respond({data:[{port:7111}]});
    if((init?.method||"GET")==="GET")return respond({data:[]});
    created++;return respond({});
  };
  const client2=new LegacyPocClient({host,tenant,apiKey:"secret",fetchImpl:auditFetch,
    approveWrite:async()=>true,audit:async()=>{throw Error("private sink error");}});
  await assert.rejects(()=>client2.create(pair(),{confirmed:true,approvalId:"ticket-2"}),/POC_AUDIT_UNAVAILABLE/);
  assert.equal(created,0);
});

test("POC cleanup removes only an approved newly created disposable test identity after unverified readback",async()=>{
  const auditEvents:LegacyAuditEvent[]=[];
  const approvalMethods:string[]=[];
  let created=false,deleted=0;
  const fetchImpl:typeof fetch=async(input,init)=>{
    const url=new URL(String(input));const method=init?.method||"GET";
    if(url.pathname.endsWith("/access_token"))return respond({access_token:"jwt"});
    if(url.pathname.endsWith("/parsers"))return respond({data:[{port:7111}]});
    if(method==="GET"){
      // A stale list after acknowledged POST must not claim success.
      return respond({data:[]});
    }
    if(method==="POST"){created=true;return respond({});}
    if(method==="DELETE"){deleted++;created=false;return respond({});}
    throw Error("unexpected synthetic method");
  };
  const client=new LegacyPocClient({host,tenant,apiKey:"secret",fetchImpl,
    approveWrite:async intent=>{approvalMethods.push(intent.method);return true;},
    audit:async item=>{auditEvents.push(item);}});
  await assert.rejects(()=>client.create(pair(),{confirmed:true,approvalId:"owner-cleanup"}),/POC_CREATE_UNVERIFIED/);
  assert.equal(created,false);
  assert.equal(deleted,1,"Exactly one approved one-time cleanup DELETE");
  assert.deepEqual(approvalMethods,["POST","CLEANUP"]);
  assert.ok(auditEvents.some(event=>event.phase==="FAILED"));
  assert.ok(auditEvents.some(event=>event.phase==="CLEANUP" && event.apiRegistrationVerified===true));
  assert.equal(JSON.stringify(auditEvents).includes("STELLAR_INIT"),false);
});

test("POC denied write permission never resubmits mutation and never echoes server body",async()=>{
  let mutations=0;
  const fetchImpl:typeof fetch=async(input,init)=>{
    const path=new URL(String(input)).pathname;
    if(path.endsWith("/access_token"))return respond({access_token:"jwt"});
    if((init?.method||"GET")==="GET")return respond({data:path.endsWith("/parsers")?[{port:7131}]:[]});
    mutations++;return respond({detail:"secret_permission_detail"},403);
  };
  const client=new LegacyPocClient({host,tenant,apiKey:"SECRET_key",fetchImpl,
    approveWrite:async()=>true,audit:async()=>{}});
  await assert.rejects(()=>client.create(pair(),{confirmed:true,approvalId:"ticket-403"}),
    (error:unknown)=>error instanceof Error && error.message.includes("403")&&
      !error.message.includes("secret_permission_detail")&&!error.message.includes("SECRET_key"));
  assert.equal(mutations,1);
});
