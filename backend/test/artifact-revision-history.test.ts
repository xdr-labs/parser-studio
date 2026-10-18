import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";
import {ArtifactRevisionHistory} from "../src/artifact-revision-history.js";
const alice={ownerId:"alice",tenant:"test_tenant"};
const bob={ownerId:"bob",tenant:"test_tenant"};
const otherTenant={ownerId:"alice",tenant:"other_tenant"};
const first=()=>compilePair(sampleProject());
const next=()=>{
  const changed=sampleProject();
  changed.revision=2;
  changed.receiver.port=7330;
  return compilePair(changed);
};
const hash=(body:Buffer)=>createHash("sha256").update(body).digest("hex");

test("owned revision records and download are immutable DRAFTs with no deployment",()=>{
  const history=new ArtifactRevisionHistory();
  const pair=first();
  const before=JSON.stringify(pair);
  const stored=history.register(alice,pair,"1.0.0");
  assert.match(stored.artifactRevisionId,/^[0-9a-f]{64}$/);
  assert.equal(stored.version,"1.0.0");
  assert.equal(stored.selectedParserPort,7123);
  assert.equal(stored.targetImportVerified,false);
  assert.equal(stored.deploymentPerformed,false);
  pair.files[0]!.content="MUTATED_EXTERNAL_INPUT";
  const download=history.download(alice,stored.artifactRevisionId);
  assert.equal(hash(download.zip),download.zipSha256);
  assert.equal(download.artifactRevisionId,stored.artifactRevisionId);
  const changed=download.zip[30];
  download.zip[30]=0xff;
  assert.notEqual(history.download(alice,stored.artifactRevisionId).zip[30],0xff);
  assert.equal(history.list(alice,"synthetic-fixture")[0]?.artifactRevisionId,
    stored.artifactRevisionId);
  assert.equal(JSON.stringify(history.list(alice,"synthetic-fixture")).includes("STELLAR_INIT"),false);
  assert.notEqual(JSON.stringify(pair),before,"caller mutation should have occurred");
});

test("checksum-only diff shows changed CONF/Ruby, port, version without source values",()=>{
  const history=new ArtifactRevisionHistory();
  const a=history.register(alice,first(),"1.0.0");
  const b=history.register(alice,next(),"1.0.1");
  const diff=history.diff(alice,a.artifactRevisionId,b.artifactRevisionId);
  assert.equal(diff.fromRevisionId,a.artifactRevisionId);
  assert.equal(diff.toRevisionId,b.artifactRevisionId);
  assert.equal(diff.selectedParserPort.changed,true);
  assert.deepEqual(diff.selectedParserPort,{from:7123,to:7330,changed:true});
  assert.equal(diff.version.changed,true);
  assert.deepEqual(diff.files.map(f=>f.changed),[true,true]);
  assert.equal(JSON.stringify(diff).includes("STELLAR_INIT"),false);
  assert.deepEqual(history.list(alice,"synthetic-fixture").map(x=>x.projectRevision),[1,2]);
});
test("owner/tenant isolation masks unauthorized revisions and never lists another user's revisions",()=>{
  const history=new ArtifactRevisionHistory();
  const a=history.register(alice,first(),"1.0.0");
  assert.deepEqual(history.list(bob,"synthetic-fixture"),[]);
  assert.deepEqual(history.list(otherTenant,"synthetic-fixture"),[]);
  for(const actor of [bob,otherTenant]){
    assert.throws(()=>history.download(actor,a.artifactRevisionId),
      /REVISION_NOT_FOUND/);
    assert.throws(()=>history.diff(actor,a.artifactRevisionId,a.artifactRevisionId),
      /REVISION_NOT_FOUND/);
    assert.throws(()=>history.prepareRestore(actor,a.artifactRevisionId,
      a.artifactRevisionId),/REVISION_NOT_FOUND/);
  }
});
test("same exact deterministic revision is independently owned by different tenants/users",()=>{
  const history=new ArtifactRevisionHistory();
  const a=history.register(alice,first(),"1.0.0");
  const b=history.register(bob,first(),"1.0.0");
  const c=history.register(otherTenant,first(),"1.0.0");
  assert.equal(a.artifactRevisionId,b.artifactRevisionId);
  assert.equal(b.artifactRevisionId,c.artifactRevisionId);
  assert.equal(history.list(bob,"synthetic-fixture").length,1);
  assert.equal(history.list(otherTenant,"synthetic-fixture").length,1);
  assert.equal(history.list(alice,"synthetic-fixture").length,1);
  assert.equal(hash(history.download(bob,b.artifactRevisionId).zip),
    hash(history.download(alice,a.artifactRevisionId).zip));
});
test("explicit offline restore prepares identical archive without changing current revision",()=>{
  const history=new ArtifactRevisionHistory();
  const a=history.register(alice,first(),"1.0.0");
  const b=history.register(alice,next(),"1.0.1");
  const snapshot=history.prepareRestore(alice,a.artifactRevisionId,
    b.artifactRevisionId);
  assert.equal(snapshot.status,"OFFLINE_RESTORE_PREVIEW");
  assert.equal(snapshot.realTargetVerified,false);
  assert.equal(snapshot.appliesToDp,false);
  assert.equal(snapshot.immutableRevisionId,a.artifactRevisionId);
  assert.equal(hash(snapshot.zip),history.download(alice,a.artifactRevisionId).zipSha256);
  assert.deepEqual(history.list(alice,"synthetic-fixture").map(x=>x.projectRevision),[1,2]);
  assert.throws(()=>history.prepareRestore(alice,a.artifactRevisionId,
    a.artifactRevisionId),/REVISION_CURRENT_CONFLICT/);
});
test("duplicate revisions and stale cross-project or missing current restore fail closed",()=>{
  const history=new ArtifactRevisionHistory();
  const a=history.register(alice,first(),"1.0.0");
  assert.throws(()=>history.register(alice,first(),"1.0.0"),/REVISION_DUPLICATE/);
  assert.throws(()=>history.prepareRestore(alice,a.artifactRevisionId,
    "c".repeat(64)),/REVISION_NOT_FOUND/);
  const other=sampleProject();
  other.projectId="synthetic-other";
  const b=history.register(alice,compilePair(other),"1.0.0");
  assert.throws(()=>history.diff(alice,a.artifactRevisionId,b.artifactRevisionId),
    /REVISION_PROJECT_MISMATCH/);
  assert.throws(()=>history.prepareRestore(alice,a.artifactRevisionId,
    b.artifactRevisionId),/REVISION_PROJECT_MISMATCH/);
});
test("revision metadata never trusts unsafe identity or unverified artifact source",()=>{
  const history=new ArtifactRevisionHistory();
  assert.throws(()=>history.register({ownerId:"alice",tenant:"bad/tenant"},
    first(),"1.0.0"),/REVISION_ACTOR_INVALID/);
  const tampered=first();
  tampered.files[0]!.content+="\nPRIVATE_LOG_VALUE";
  assert.throws(()=>history.register(alice,tampered,"1.0.0"),/ARTIFACT_/);
  assert.deepEqual(history.list(alice,"synthetic-fixture"),[]);
});
test("retention quota and TTL are finite with no implied persistent restore",()=>{
  let now=1000000;
  const history=new ArtifactRevisionHistory({now:()=>now,maxRevisions:1,ttlMs:1000});
  const a=history.register(alice,first(),"1.0.0");
  assert.throws(()=>history.register(alice,next(),"1.0.1"),/REVISION_CAPACITY_REACHED/);
  now+=1001;
  assert.deepEqual(history.list(alice,"synthetic-fixture"),[]);
  assert.throws(()=>history.download(alice,a.artifactRevisionId),/REVISION_NOT_FOUND/);
  assert.equal(history.register(alice,next(),"1.0.1").projectRevision,2);
});


test("server-only owned Apply resolver returns immutable exact pair and denies cross-owner IDs",()=>{
  const history=new ArtifactRevisionHistory();
  const id=history.register(alice,first(),"1.0.0").artifactRevisionId;
  for(const unauthorized of [bob,otherTenant]){
    assert.throws(()=>history.resolveOwnedRevision(unauthorized,id),
      /REVISION_NOT_FOUND/);
  }
  const owned=history.resolveOwnedRevision(alice,id);
  assert.equal(owned.ownerId,alice.ownerId);
  assert.equal(owned.tenant,alice.tenant);
  assert.equal(owned.artifact.manifest.artifactRevisionId,id);
  assert.equal(owned.artifact.manifest.selectedParserPort,7123);
  const parser=owned.pair.files.find(f=>f.name==="customized_sample_firewall");
  assert.ok(parser);
  parser.content="MUTATED_IN_CALLER";
  owned.artifact.zip[30]=0xff;
  owned.artifact.manifest.fileHashes["customized_sample_firewall"]="0".repeat(64);
  const next=history.resolveOwnedRevision(alice,id);
  assert.notEqual(next.pair.files.find(f=>f.name==="customized_sample_firewall")!.content,
    "MUTATED_IN_CALLER");
  assert.notEqual(next.artifact.zip[30],0xff);
  assert.notEqual(next.artifact.manifest.fileHashes["customized_sample_firewall"],
    "0".repeat(64));
});
