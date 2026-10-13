import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,readFileSync,writeFileSync,chmodSync,statSync,symlinkSync,unlinkSync,linkSync,rmSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";
import {DurableArtifactRevisionHistory} from "../src/durable-revision-history.js";

const alice={ownerId:"synthetic-alice",tenant:"tenant_a"};
const bob={ownerId:"synthetic-bob",tenant:"tenant_a"};
const other={ownerId:"synthetic-alice",tenant:"tenant_b"};
const pair=(revision=1,port=7123)=>{
  const p=sampleProject(); p.revision=revision;p.receiver.port=port;
  return compilePair(p);
};
const use=(fn:(file:string,dir:string)=>void)=>{
  const dir=mkdtempSync(join(tmpdir(),"parserstudio-durable-"));
  try{fn(join(dir,"artifact-revisions.json"),dir);}
  finally{rmSync(dir,{recursive:true,force:true});}
};
const store=(file:string,options?:{now?:()=>number;ttlMs?:number;maxRevisions?:number})=>
  new DurableArtifactRevisionHistory(file,options);

test("durable offline owner revisions reopen byte-identically and retain only verified pairs",()=>{
  use(file=>{
    const a=store(file);
    const first=a.register(alice,pair(),"1.0.0");
    assert.deepEqual(a.list(bob,"synthetic-fixture"),[]);
    assert.deepEqual(a.list(other,"synthetic-fixture"),[]);
    assert.throws(()=>a.resolveOwnedRevision(bob,first.artifactRevisionId),
      /REVISION_NOT_FOUND/);
    assert.throws(()=>a.download(other,first.artifactRevisionId),
      /REVISION_NOT_FOUND/);
    const second=a.register(alice,pair(2,7330),"1.0.1");
    const old=a.download(alice,first.artifactRevisionId);
    assert.equal(a.persistent,true);
    assert.equal(statSync(file).mode&0o777,0o600);
    const restarted=store(file);
    assert.deepEqual(restarted.list(alice,"synthetic-fixture").map(x=>x.artifactRevisionId),
      [first.artifactRevisionId,second.artifactRevisionId]);
    assert.equal(restarted.download(alice,first.artifactRevisionId).zip.equals(old.zip),true);
    assert.equal(restarted.resolveOwnedRevision(alice,second.artifactRevisionId).artifact.zipSha256,
      second.zipSha256);
    assert.equal(restarted.diff(alice,first.artifactRevisionId,second.artifactRevisionId)
      .selectedParserPort.changed,true);
    assert.equal(restarted.prepareRestore(alice,first.artifactRevisionId,
      second.artifactRevisionId).status,"OFFLINE_RESTORE_PREVIEW");
    assert.equal(restarted.prepareRestore(alice,first.artifactRevisionId,
      second.artifactRevisionId).appliesToDp,false);
  });
});
test("only the fixed compiler-owned TCP blank-line JSON warning enters durable offline revisions",()=>{
  use(file=>{
    const p=sampleProject();
    p.projectId="draft-synthetic_blankline";
    p.receiver.protocols=["tcp"];
    p.receiver.tcpFraming="blank_line_json";
    p.extraction.format="json";
    const generated=compilePair(p);
    const h=store(file);
    const item=h.register(alice,generated,"1.2.3");
    const restarted=store(file);
    const saved=restarted.resolveOwnedRevision(alice,item.artifactRevisionId);
    assert.deepEqual(saved.pair.manifest.warnings,generated.manifest.warnings);
    p.revision=2;
    const forged=compilePair(p);
    forged.manifest.warnings[2]="PRIVATE_LOG_INJECTED";
    assert.throws(()=>restarted.register(alice,forged,"1.2.4"),
      /REVISION_STORE_INPUT_UNSAFE/);
  });
});
test("tenant and actor isolation persists through restart; metadata-only mock Apply audit",()=>{
  use(file=>{
    const h=store(file);
    const row=h.register(alice,pair(),"1.0.0");
    h.register(bob,pair(),"1.0.0");
    h.register(other,pair(),"1.0.0");
    h.recordMockApplyAudit({actorId:alice.ownerId,tenant:alice.tenant,phase:"BEFORE",
      artifactRevisionId:row.artifactRevisionId,status:"REQUESTED"});
    h.recordMockApplyAudit({actorId:alice.ownerId,tenant:alice.tenant,phase:"AFTER",
      artifactRevisionId:row.artifactRevisionId,status:"MOCK_READBACK_VERIFIED"});
    const reboot=store(file);
    assert.equal(reboot.list(bob,"synthetic-fixture").length,1);
    assert.deepEqual(reboot.listMockApplyAudit(bob),[]);
    assert.deepEqual(reboot.listMockApplyAudit(other),[]);
    assert.deepEqual(reboot.listMockApplyAudit(alice).map(x=>x.status),
      ["REQUESTED","MOCK_READBACK_VERIFIED"]);
    const text=readFileSync(file,"utf8");
    for(const prohibited of ["rawEvent","apiKey","approvalId","Bearer ","customerPassword"])
      assert.equal(text.includes(prohibited),false);
    assert.throws(()=>reboot.recordMockApplyAudit({...{
      actorId:bob.ownerId,tenant:bob.tenant,phase:"BEFORE" as const,
      artifactRevisionId:"f".repeat(64),status:"REQUESTED" as const
    }}),/REVISION_NOT_FOUND/);
    assert.throws(()=>reboot.recordMockApplyAudit({actorId:alice.ownerId,tenant:alice.tenant,
      phase:"BEFORE",artifactRevisionId:row.artifactRevisionId,status:"REQUESTED",
      apiKey:"bad"} as any),/AUDIT_EVENT_INVALID/);
  });
});
test("tampered/truncated artifact ledger fails closed across all reads and writes",()=>{
  use(file=>{
    const h=store(file);
    const row=h.register(alice,pair(),"1.0.0");
    const original=readFileSync(file,"utf8");
    writeFileSync(file,original.replace("customized_sample_firewall","customized_malicious"),{mode:0o600});
    assert.throws(()=>store(file).download(alice,row.artifactRevisionId),/REVISION_STORE_INTEGRITY/);
    assert.throws(()=>store(file).register(alice,pair(2,7330),"1.0.1"),/REVISION_STORE_INTEGRITY/);
    writeFileSync(file,original.slice(0,-5),{mode:0o600});
    assert.throws(()=>store(file).list(alice,"synthetic-fixture"),/REVISION_STORE_INTEGRITY/);
    writeFileSync(file,original,{mode:0o600});
    assert.equal(store(file).download(alice,row.artifactRevisionId).zipSha256,row.zipSha256);
  });
});
test("insecure directory, symlink, hardlink, and file permission are denied",()=>{
  use((file,dir)=>{
    chmodSync(dir,0o770);
    assert.throws(()=>store(file).register(alice,pair(),"1.0.0"),/REVISION_DIRECTORY_UNSAFE/);
    chmodSync(dir,0o700);
    const h=store(file);const row=h.register(alice,pair(),"1.0.0");
    chmodSync(file,0o644);
    assert.throws(()=>store(file).list(alice,"synthetic-fixture"),/REVISION_FILE_UNSAFE/);
    chmodSync(file,0o600);
    linkSync(file,join(dir,"hardlink"));
    assert.throws(()=>store(file).download(alice,row.artifactRevisionId),/REVISION_FILE_UNSAFE/);
    unlinkSync(join(dir,"hardlink"));
    unlinkSync(file);
    symlinkSync(join(dir,"target.json"),file);
    assert.throws(()=>store(file).register(alice,pair(),"1.0.0"),/REVISION_FILE_UNSAFE/);
    unlinkSync(file);
    const linkdir=join(tmpdir(),"parserstudio-durable-link-"+process.pid);
    symlinkSync(dir,linkdir);
    try{
      assert.throws(()=>store(join(linkdir,"artifact-revisions.json")).list(alice,"synthetic-fixture"),
        /REVISION_DIRECTORY_UNSAFE/);
    }finally{unlinkSync(linkdir);}
  });
});
test("bounded TTL, capacity, stale revisions, rejected lock, and immutable audit validation",()=>{
  use((file,dir)=>{
    let now=1_000_000;
    const h=store(file,{now:()=>now,maxRevisions:2,ttlMs:1000});
    const a=h.register(alice,pair(),"1.0.0");
    const b=h.register(alice,pair(2,7330),"1.0.1");
    assert.throws(()=>h.register(alice,pair(3,7331),"1.0.2"),/REVISION_CAPACITY_REACHED/);
    assert.throws(()=>h.register(alice,pair(2,7330),"1.0.2"),/REVISION_VERSION_CONFLICT/);
    assert.throws(()=>h.prepareRestore(alice,a.artifactRevisionId,a.artifactRevisionId),
      /REVISION_CURRENT_CONFLICT/);
    assert.throws(()=>h.recordMockApplyAudit({actorId:alice.ownerId,tenant:alice.tenant,
      phase:"AFTER",status:"MOCK_READBACK_VERIFIED",
      artifactRevisionId:b.artifactRevisionId}),/AUDIT_TRANSITION_INVALID/);
    writeFileSync(join(dir,".artifact-revisions.lock"),"untrusted",{mode:0o600});
    assert.throws(()=>h.recordMockApplyAudit({actorId:alice.ownerId,tenant:alice.tenant,
      phase:"BEFORE",status:"REQUESTED",artifactRevisionId:b.artifactRevisionId}),
      /REVISION_STORE_LOCKED/);
    unlinkSync(join(dir,".artifact-revisions.lock"));
    now+=1001;
    assert.deepEqual(store(file,{now:()=>now,maxRevisions:2,ttlMs:1000})
      .list(alice,"synthetic-fixture"),[]);
    assert.equal(h.register(alice,pair(3,7331),"1.0.2").projectRevision,3);
    assert.throws(()=>h.download(alice,a.artifactRevisionId),/REVISION_NOT_FOUND/);
  });
});

test("untrusted warning/credential fields cannot enter private durable artifact storage",()=>{
  use(file=>{
    const h=store(file);
    const edited=pair();
    edited.manifest.warnings.push("rawEvent=PRIVATE_CUSTOMER_LOG apiKey=SECRET");
    assert.throws(()=>h.register(alice,edited,"1.0.0"),/REVISION_STORE_INPUT_UNSAFE/);
    assert.deepEqual(h.list(alice,"synthetic-fixture"),[]);
    const valid=h.register(alice,pair(),"1.0.0");
    assert.match(valid.zipSha256,/^[0-9a-f]{64}$/);
    const stored=readFileSync(file,"utf8");
    assert.equal(stored.includes("PRIVATE_CUSTOMER_LOG"),false);
    assert.equal(stored.includes("apiKey=SECRET"),false);
  });
});
