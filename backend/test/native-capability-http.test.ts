import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import type {AddressInfo} from "node:net";
import {createBackendServer,type BackendServerOptions} from "../src/http.js";

const HEAD="a".repeat(40);
const sha=(text:string)=>createHash("sha256").update(text).digest("hex");
const endpoint="/api/v1/parser-pairs/native-capability-manifest";
const known=[
  ["sample_cef","cef","none",2],
  ["sample_csv","csv","none",2],
  ["sample_enriched","json","none",1],
  ["sample_extended","json","none",1],
  ["sample_firewall","json","none",2],
  ["sample_kv","kv","none",1],
  ["sample_leef","leef","none",3],
  ["sample_syslog","syslog_rfc5424","kv",5],
  ["sample_syslog_cef","syslog_rfc5424","cef",3],
  ["sample_syslog_leef","syslog_rfc5424","leef",3],
] as const;
function evidence(){
  const unsigned={
    contract:"parser-studio.synthetic-native-capabilities.v0.1",
    proofScope:"REVIEWED_PUBLIC_SYNTHETIC_ONLY",
    backendHead:HEAD,
    fixtureSha256:"f".repeat(64),
    caseEvidenceSha256:"e".repeat(64),
    engine:{ruby:"3.2.x",fluentd:"1.17.1",
      validation:"PINNED_FLUENTD_PARSER_PLUGIN_API_AND_CONF_AST"},
    casesPassed:23,nativeCapabilityVerified:true,
    profiles:known.map(([slug,extraction,bodyFormat,goldenCases])=>({
      slug,extraction,bodyFormat,goldenCases,rubySha256:"a".repeat(64),
      confSha256:"b".repeat(64),
      fluentdSyntheticCallbackVerified:true,fluentdConfAstVerified:true,
      stellarLoaderVerified:false,
    })),
    optionalSupportVerified:{
      rfc3164:false,multiline:false,arbitraryRegex:false,
      jsonata:false,mixedFormatAutoRouting:false,arbitraryRuby:false,
    },
    stellarImportVerified:false,
    sensorReceivingVerified:false,
    customerSampleVerified:false,
    supportedBeyondSynthetic:false,
  };
  return {...unsigned,digest:sha(JSON.stringify(unsigned))};
}
const access=(manifest:unknown=evidence(),expectedHead=HEAD):BackendServerOptions=>({
  nativeCapabilityAccess:{
    manifest,expectedHead,
    authorize:async(req)=>req.headers["x-test-native-user"]==="alice",
  },
});
async function withServer(options:BackendServerOptions,
  check:(base:string)=>Promise<void>){
  const server=createBackendServer(options);
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  try{
    await check("http://127.0.0.1:"+(server.address() as AddressInfo).port);
  }finally{
    await new Promise<void>(resolve=>server.close(()=>resolve()));
  }
}
const get=(base:string,user?:string,query="")=>fetch(base+endpoint+query,{
  headers:user?{"x-test-native-user":user}:{},
});

test("native capability report endpoint denies by default and does not lift per-user parser verification",async()=>{
  await withServer({},async base=>{
    const response=await get(base,"alice");
    assert.equal(response.status,403);
    assert.equal((await response.json() as any).error,"NATIVE_CAPABILITY_DISABLED");
    const caps=await fetch(base+"/api/v1/parser-pairs/capabilities");
    assert.equal(caps.status,200);
    const capability=await caps.json() as any;
    assert.equal(capability.verification.engineVerified,false);
    assert.equal(capability.verification.targetImportVerified,false);
  });
});
test("only explicitly authenticated principal reads exact-head redacted public-synthetic manifest",async()=>{
  await withServer(access(),async base=>{
    const response=await get(base,"alice");
    assert.equal(response.status,200);
    assert.equal(response.headers.get("cache-control"),"no-store");
    const body=await response.json() as any;
    assert.equal(body.backendHead,HEAD);
    assert.equal(body.casesPassed,23);
    assert.equal(body.profiles.length,10);
    assert.equal(body.proofScope,"REVIEWED_PUBLIC_SYNTHETIC_ONLY");
    assert.equal(body.nativeCapabilityVerified,true);
    assert.equal(body.stellarImportVerified,false);
    assert.equal(body.sensorReceivingVerified,false);
    assert.equal(body.customerSampleVerified,false);
    assert.equal(body.supportedBeyondSynthetic,false);
    assert.equal(JSON.stringify(body).includes("rawEvent"),false);
    assert.equal((await get(base,"bob")).status,403);
    assert.equal((await get(base)).status,403);
    assert.equal((await get(base,"alice","?projectId=secret")).status,422);
    const wrong=await fetch(base+endpoint,{method:"POST",headers:{
      "x-test-native-user":"alice","content-type":"application/json",
    },body:JSON.stringify({apiKey:"SECRET"})});
    assert.equal(wrong.status,405);
  });
});
test("stale, forged or corrupted manifests return redacted 503, never a verification badge",async()=>{
  for(const [manifest,expectedHead] of [
    [evidence(),"c".repeat(40)],
    [{...evidence(),stellarImportVerified:true},HEAD],
    [{...evidence(),rawEvent:"PRIVATE_CUSTOMER_TOKEN"},HEAD],
    [{...evidence(),digest:"0".repeat(64)},HEAD],
    [{...evidence(),profiles:[...evidence().profiles].reverse()},HEAD],
  ] as const){
    await withServer(access(manifest,expectedHead),async base=>{
      const response=await get(base,"alice");
      assert.equal(response.status,503);
      const body=await response.json() as any;
      assert.deepEqual(body,{error:"NATIVE_CAPABILITY_EVIDENCE_UNAVAILABLE",
        targetImportVerified:false});
      assert.equal(JSON.stringify(body).includes("PRIVATE_CUSTOMER_TOKEN"),false);
    });
  }
});
