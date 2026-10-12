import assert from "node:assert/strict";
import test from "node:test";
import {createHash} from "node:crypto";
import {execFileSync} from "node:child_process";
import {mkdtempSync,rmSync,writeFileSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import type {AddressInfo} from "node:net";
import {buildArtifactPackage} from "../src/artifact-package.js";
import {createBackendServer} from "../src/http.js";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";
import type {PairExport} from "../src/types.js";

const hash=(bytes:Buffer|string)=>createHash("sha256").update(bytes).digest("hex");
function unzipEntries(buf:Buffer,names:string[]){
  const dir=mkdtempSync(join(tmpdir(),"parser-studio-zip-contract-"));
  const path=join(dir,"generated.zip");
  try{
    writeFileSync(path,buf,{mode:0o600});
    execFileSync("unzip",["-tqq",path],{timeout:5000});
    return Object.fromEntries(names.map(name=>[
      name,execFileSync("unzip",["-p",path,name],{timeout:5000}).toString("utf8")
    ]));
  }finally{rmSync(dir,{recursive:true,force:true});}
}
async function localServer(run:(url:string)=>Promise<void>){
  const server=createBackendServer();
  await new Promise<void>(resolve=>server.listen(0,"127.0.0.1",resolve));
  const addr=server.address() as AddressInfo;
  try{await run("http://127.0.0.1:"+addr.port);}
  finally{await new Promise<void>(resolve=>server.close(()=>resolve()));}
}

test("immutable parser ZIP includes byte-identical files and safe manifest without DP credentials",()=>{
  const pair=compilePair(sampleProject());
  const bundle=buildArtifactPackage(pair,"1.0.0");
  assert.match(bundle.manifest.artifactRevisionId,/^[0-9a-f]{64}$/);
  assert.equal(bundle.manifest.selectedParserPort,7123);
  assert.deepEqual(bundle.manifest.receiverProtocols,["udp","tcp"]);
  assert.equal(bundle.manifest.version,"1.0.0");
  assert.equal(bundle.manifest.status,"DRAFT");
  assert.equal(bundle.manifest.targetImportVerified,false);
  assert.equal(bundle.manifest.runtimeParsingVerified,false);
  const files=unzipEntries(bundle.zip,[
    "customized_sample_firewall",
    "customized_sample_firewall.conf",
    "manifest.json",
  ]);
  for(const f of pair.files){
    assert.equal(files[f.name],f.content,f.name);
    assert.equal(bundle.manifest.fileHashes[f.name],f.sha256);
    assert.equal(Buffer.byteLength(files[f.name]!,"utf8"),f.bytes);
  }
  assert.deepEqual(JSON.parse(files["manifest.json"]!),bundle.manifest);
  assert.equal(bundle.zipSha256,hash(bundle.zip));
  assert.equal(bundle.zip.includes(Buffer.from("Bearer ")),false);
  assert.equal(bundle.zip.includes(Buffer.from("JWT_SECRET")),false);
  assert.equal(bundle.zip.includes(Buffer.from("PRIVATE_API_KEY")),false);
  assert.deepEqual(buildArtifactPackage(pair,"1.0.0"),bundle,"ZIP/revision must be reproducible");
});

test("recompiling a different selected parser port invalidates old zip and artifact revision",()=>{
  const project=sampleProject();
  const original=buildArtifactPackage(compilePair(project),"1.0.0");
  project.receiver.port=7895;
  const moved=buildArtifactPackage(compilePair(project),"1.0.0");
  assert.notEqual(moved.manifest.artifactRevisionId,original.manifest.artifactRevisionId);
  assert.notEqual(moved.manifest.fileHashes["customized_sample_firewall.conf"],
    original.manifest.fileHashes["customized_sample_firewall.conf"]);
  assert.notEqual(moved.manifest.fileHashes["customized_sample_firewall"],
    original.manifest.fileHashes["customized_sample_firewall"]);
  assert.equal(moved.manifest.selectedParserPort,7895);
  assert.notEqual(hash(original.zip),hash(moved.zip));
});

test("package cannot contain forged Ruby, checksum, manifest or dangerous caller version",()=>{
  const pair=compilePair(sampleProject());
  for(const patch of [
    (p:PairExport)=>{p.files[0]!.content+="\n@include /etc/passwd";},
    (p:PairExport)=>{p.files[1]!.sha256="a".repeat(64);},
    (p:PairExport)=>{p.manifest.fileHashes["customized_sample_firewall"]="b".repeat(64);},
    (p:PairExport)=>{p.manifest.projectRevision=999;},
    (p:PairExport)=>{p.files[1]!.name="../unsafe";},
  ]){
    const changed=structuredClone(pair);
    patch(changed);
    assert.throws(()=>buildArtifactPackage(changed,"1.0.0"),/ARTIFACT_/);
  }
  assert.throws(()=>buildArtifactPackage(pair,"../bad"),/ARTIFACT_VERSION_INVALID/);
  assert.throws(()=>buildArtifactPackage(pair,"1.0.0/../../"),/ARTIFACT_VERSION_INVALID/);
});

test("HTTP ZIP route works without Stellar API Key and refuses tampering; existing generate stays nondeploying",async()=>{
  await localServer(async base=>{
    const features=await (await fetch(base+"/api/v1/parser-pairs/capabilities")).json() as any;
    assert.equal(features.downloads.zipWithManifest,true);
    assert.equal(features.downloads.requiresDpConnection,false);
    assert.equal(features.downloads.autoDeploys,false);
    const pair=compilePair(sampleProject());
    const response=await fetch(base+"/api/v1/parser-pairs/package",{
      method:"POST",headers:{"content-type":"application/json"},
      body:JSON.stringify({pair,version:"1.0.0"}),
    });
    assert.equal(response.status,200);
    assert.equal(response.headers.get("content-type"),"application/zip");
    assert.equal(response.headers.get("cache-control"),"no-store");
    assert.match(response.headers.get("content-disposition")??"",/attachment/);
    assert.match(response.headers.get("x-parser-artifact-revision")??"",/^[0-9a-f]{64}$/);
    const bytes=Buffer.from(await response.arrayBuffer());
    assert.equal(hash(bytes),response.headers.get("x-parser-zip-sha256"));
    const entries=unzipEntries(bytes,["customized_sample_firewall","customized_sample_firewall.conf","manifest.json"]);
    assert.equal(entries["customized_sample_firewall"],pair.files[1]!.content);
    assert.equal(JSON.parse(entries["manifest.json"]!).targetImportVerified,false);
    const corrupted=structuredClone(pair);
    corrupted.files[0]!.bytes++;
    const invalid=await fetch(base+"/api/v1/parser-pairs/package",{
      method:"POST",headers:{"content-type":"application/json"},
      body:JSON.stringify({pair:corrupted,version:"1.0.0"}),
    });
    assert.equal(invalid.status,422);
    assert.equal((await invalid.json() as any).error.startsWith("ARTIFACT_"),true);
  });
});
