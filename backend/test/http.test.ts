import test from "node:test";
import assert from "node:assert/strict";
import type { AddressInfo } from "node:net";
import { createBackendServer, compilePair } from "../src/index.js";
import { sampleProject } from "./fixture.js";
async function withServer(fn:(base:string)=>Promise<void>){
 const srv=createBackendServer();
 await new Promise<void>(resolve=>srv.listen(0,"127.0.0.1",resolve));
 const address=srv.address() as AddressInfo;
 try {await fn("http://127.0.0.1:"+address.port);}
 finally {await new Promise<void>(resolve=>srv.close(()=>resolve()));}
}
function post(base:string,path:string,value:unknown){
 return fetch(base+path,{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify(value)});
}
test("health, validation, generate API and explicit unverified status",async()=>{
 await withServer(async base=>{
  const h=await fetch(base+"/health");assert.equal(h.status,200);
  const schemaResponse=await fetch(base+"/api/v1/parser-pairs/schema");
  assert.equal(schemaResponse.status,200);
  const schema=await schemaResponse.json() as any;
  assert.equal(schema.title,"Parser Studio portable ParserProject v0.1");
  const v=await post(base,"/api/v1/parser-pairs/validate",sampleProject());assert.equal(v.status,200);
  assert.equal((await v.json() as any).ok,true);
  const r=await post(base,"/api/v1/parser-pairs/generate",sampleProject());
  assert.equal(r.status,200);const body=await r.json() as any;
  assert.equal(body.files.length,2);assert.equal(body.manifest.status,"DRAFT");
  assert.equal(body.manifest.targetImportVerified,false);
 });
});
test("reject invalid input, too large input and wrong content types",async()=>{
 await withServer(async base=>{
  const p=sampleProject();p.slug="../bad";
  const r=await post(base,"/api/v1/parser-pairs/generate",p);
  assert.equal(r.status,422);
  const error=await r.json() as any;assert.equal(error.error,"INVALID_PROJECT");assert.equal(error.files,undefined);
  const large=await fetch(base+"/api/v1/parser-pairs/generate",{method:"POST",headers:{"content-type":"application/json"},body:" ".repeat(300000)});
  assert.equal(large.status,413);
  const plain=await fetch(base+"/api/v1/parser-pairs/generate",{method:"POST",headers:{"content-type":"text/plain"},body:"hi"});
  assert.equal(plain.status,415);
  const unknown=await fetch(base+"/unknown");assert.equal(unknown.status,404);
 });
});

test("POST inspect supports exact self-generated project and safe opaque legacy inspection", async () => {
 await withServer(async base => {
   const generated=compilePair(sampleProject());
   const pair={
     name:"customized_sample_firewall",
     confContent:generated.files[0]!.content,
     fragmentContent:generated.files[1]!.content,
   };
   const ok=await post(base,"/api/v1/parser-pairs/inspect",pair);
   assert.equal(ok.status,200);
   const result=await ok.json() as any;
   assert.equal(result.roundTripVerified,true);
   assert.equal(result.importStatus,"EDITABLE_EXACT");
   assert.equal(result.portableProject.slug,"sample_firewall");
   assert.equal(JSON.stringify(result).includes("# STELLAR_INIT_BEGIN"),false);

   const legacy=await post(base,"/api/v1/parser-pairs/inspect",{
     name:"customized_legacy",
     confContent:"<source>\n @type udp\n port 7123\n tag customized_legacy\n</source>",
     fragmentContent:"# STELLAR_INIT_BEGIN\n# vendor-private-secret\n# STELLAR_INIT_END"
   });
   assert.equal(legacy.status,200);
   const opaque=await legacy.json() as any;
   assert.equal(opaque.importStatus,"OPAQUE_READ_ONLY");
   assert.equal(JSON.stringify(opaque).includes("vendor-private-secret"),false);
 });
});

test("inspect API rejects malformed and oversized pairs without echoing private content", async () => {
 await withServer(async base => {
   const path="/api/v1/parser-pairs/inspect";
   const bad=await post(base,path,{name:"../private",confContent:"TOP_SECRET_ABC",fragmentContent:"RubyPrivate_123"});
   assert.equal(bad.status,422);
   const error=await bad.json() as any;
   assert.equal(error.error,"INVALID_PAIR");
   assert.equal(error.issues[0].code,"PAIR_NAME_INVALID");
   assert.equal(JSON.stringify(error).includes("TOP_SECRET_ABC"),false);

   const wrong=await post(base,path,{name:"customized_example",confContent:18,fragmentContent:"RubyPrivate_123"});
   assert.equal(wrong.status,422);
   assert.equal(((await wrong.json()) as any).issues[0].code,"PAIR_CONTENT_INVALID");

   const garbage=await fetch(base+path,{method:"POST",headers:{"content-type":"application/json"},body:"{ bad json"});
   assert.equal(garbage.status,400);
   const plain=await fetch(base+path,{method:"POST",headers:{"content-type":"text/plain"},body:"raw logs"});
   assert.equal(plain.status,415);
   const huge=await post(base,path,{name:"customized_example",confContent:"a".repeat(2*1024*1024),fragmentContent:"x"});
   assert.equal(huge.status,413);
 });
});

test("capabilities API must truthfully advertise only supported and verified backend scope", async () => {
 await withServer(async base => {
   const response = await fetch(base+"/api/v1/parser-pairs/capabilities");
   assert.equal(response.status,200);
   assert.equal(response.headers.get("cache-control"),"no-store");
   const info=await response.json() as any;
   assert.equal(info.contract,"host-customized-pair.v0.1");
   assert.deepEqual(info.authoring.receiverProtocols,["udp","tcp"]);
   assert.deepEqual(info.authoring.extractionFormats,["json","kv","csv","syslog_rfc3164","syslog_rfc5424","cef","leef","mixed","java_stacktrace","regex","generic_structural"]);
   assert.equal(info.authoring.boundedRegexNamedCaptureSubset,true);
   assert.equal(info.authoring.boundedRegexMaxPatternChars,256);
   assert.equal(info.authoring.boundedRegexRuntimeTimeoutMs,50);
   assert.equal(info.authoring.genericStructuralGrammar,"GENERIC_STRUCTURAL_ULTRA_COMPILER_V15");
   assert.equal(info.authoring.httpReceiver,false);
   assert.equal(info.authoring.multipleDistinctReceiverPorts,false);
   assert.equal(info.authoring.formatCoverage,"reviewed-bounded-subset");
   assert.equal(info.authoring.rfc5424AdjacentStructuredDataSubset,true);
   assert.equal(info.authoring.rfc5424StructuredDataMaxBytes,1024);
   assert.deepEqual(info.authoring.rfc5424BodyFormats,["raw","json","kv","cef","leef","regex"]);
   assert.equal(info.authoring.leefHexSeparatorSubset,true);
   assert.equal(info.authoring.multiline,false);
   assert.equal(info.authoring.jsonBlankLineTcpFraming,true);
   assert.equal(info.authoring.jsonBlankLineOtherTransports,false);
   assert.equal(info.authoring.jsonBlankLineDelimiter,'LF_LF');
   assert.equal(info.authoring.javaBlankLineTcpFraming,true);
   assert.equal(info.authoring.javaBlankLineOtherTransports,false);
   assert.equal(info.authoring.javaBlankLineDelimiter,'LF_LF');
   assert.equal(info.authoring.javaStackTraceGrammar,'EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1');
   assert.deepEqual(info.authoring.strictMixedSingleLineFamilies,['json','kv','cef','leef','rfc5424_cef','rfc5424_leef','rfc3164_kv','rfc5424_json','rfc5424_kv','rfc3164_cef','rfc3164_leef','csv']);
   assert.equal(info.authoring.strictMixedRequiresExplicitAllowlist,true);
   assert.equal(info.authoring.rfc3164StrictTaggedMessageSubset,true);
   assert.equal(info.authoring.rfc3164TimePolicy,"YEAR_AND_ZONE_UNKNOWN");
   assert.equal(info.authoring.rfc3164NativeTimeReconstruction,false);
   assert.equal(info.authoring.arbitraryRuby,false);
   assert.equal(info.import.exactInternalPairsEditable,true);
   assert.equal(info.import.unknownLegacyRubyEditable,false);
   assert.equal(info.verification.nativeSyntheticProfile,"ruby3.2.x-fluentd1.17.1");
   assert.equal(info.verification.liveListenerVerified,false);
   assert.equal(info.verification.proprietaryLoaderVerified,false);
   assert.equal(info.verification.targetImportVerified,false);
   assert.equal(info.verification.engineVerified,false);
   assert.equal(info.limits.maxInspectBodyBytes,2*1024*1024);
   assert.equal(info.limits.maxProjectBodyBytes,256*1024);
   assert.equal(JSON.stringify(info).includes("TARGET_IMPORT_VERIFIED"),false);
   const badMethod=await post(base,"/api/v1/parser-pairs/capabilities",{});
   assert.equal(badMethod.status,405);
 });
});

test("HTTP rejects malformed UTF-8 bytes and unsupported JSON charset before inspection or generation", async()=>{
  await withServer(async base=>{
    const inspectPath="/api/v1/parser-pairs/inspect";
    // Synthetic invalid UTF-8 in an otherwise legal JSON body.
    const bytes=Buffer.concat([
      Buffer.from('{"name":"customized_test","confContent":"'),
      Buffer.from([0xc3,0x28]),
      Buffer.from('","fragmentContent":""}'),
    ]);
    const corrupt=await fetch(base+inspectPath,{
      method:"POST",headers:{"content-type":"application/json"},body:bytes,
    });
    assert.equal(corrupt.status,400,"malformed bytes must not become a changed imported pair");
    const error=await corrupt.json() as any;
    assert.equal(error.error,"INVALID_JSON");
    assert.equal(JSON.stringify(error).includes("\uFFFD"),false);

    const badCharset=await fetch(base+"/api/v1/parser-pairs/validate",{
      method:"POST",headers:{"content-type":"application/json; charset=iso-8859-1"},
      body:JSON.stringify(sampleProject()),
    });
    assert.equal(badCharset.status,415);
    const goodCharset=await fetch(base+"/api/v1/parser-pairs/validate",{
      method:"POST",headers:{"content-type":"application/json; charset=UTF-8"},
      body:JSON.stringify(sampleProject()),
    });
    assert.equal(goodCharset.status,200);
  });
});

test("HTTP JSON rejects unpaired escaped Unicode while allowing valid supplementary pairs",async()=>{
  await withServer(async base=>{
    const path="/api/v1/parser-pairs/inspect";
    const malformed=await fetch(base+path,{
      method:"POST",headers:{"content-type":"application/json"},
      body:'{"name":"customized_test","confContent":"\\ud800","fragmentContent":""}',
    });
    assert.equal(malformed.status,400);
    assert.equal(((await malformed.json()) as any).error,"INVALID_JSON");

    const key=await fetch(base+path,{
      method:"POST",headers:{"content-type":"application/json"},
      body:'{"name":"customized_test","\\udc00":"value","confContent":"","fragmentContent":""}',
    });
    assert.equal(key.status,400,"Invalid escaped Unicode object keys must fail before inspection");
    const paired=await fetch(base+path,{
      method:"POST",headers:{"content-type":"application/json"},
      body:'{"name":"customized_test","confContent":"\\ud83d\\ude00","fragmentContent":""}',
    });
    assert.equal(paired.status,200);
    const result=await paired.json() as any;
    assert.equal(result.importStatus,"OPAQUE_READ_ONLY");
    assert.equal(result.portableProject,null);
  });
});