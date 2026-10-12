import test from "node:test";
import assert from "node:assert/strict";
import {mkdtempSync,chmodSync,readFileSync,writeFileSync,symlinkSync,unlinkSync,
  rmSync,statSync,linkSync,mkdirSync} from "node:fs";
import {tmpdir} from "node:os";
import {join} from "node:path";
import {SyntheticNativeRegressionStore} from "../src/native-regression-store.js";

const sha=(letter:string)=>letter.repeat(64);
const commit=(letter:string)=>letter.repeat(40);
const a=commit("a"),b=commit("b"),f=sha("f");
const report=(head:string)=>({
  kind:"parser-studio.synthetic-native-case-evidence.v0.1",
  origin:"independently-authored-public-synthetic",
  backendHead:head,fixtureSha256:f,
  ruby:"3.2",fluentd:"1.17.1",
  cases:[
    {id:"test-json",slug:"sample_firewall",status:"PASS",outputSha256:sha("3")},
    {id:"test-cef",slug:"sample_cef",status:"PASS",outputSha256:sha("4")},
  ],
  sensorTrafficSent:false,actualTdAgentOrStellarImport:false,
  targetImportVerified:false,
});
function inSandbox(fn:(root:string)=>void){
  const parent=mkdtempSync(join(tmpdir(),"parser-studio-regression-"));
  try{fn(join(parent,"native-regression"));}
  finally{rmSync(parent,{recursive:true,force:true});}
}
test("private per-head offline archive persists same-fixture evidence and idempotent reread",()=>{
  inSandbox(root=>{
    const repo=new SyntheticNativeRegressionStore(root);
    assert.deepEqual(repo.archiveVerifiedCaseEvidence(report(a),f),
      {backendHead:a,cases:2,reused:false});
    assert.deepEqual(repo.archiveVerifiedCaseEvidence(report(a),f),
      {backendHead:a,cases:2,reused:true});
    assert.equal(statSync(root).mode&0o777,0o700);
    assert.equal(statSync(join(root,a+".json")).mode&0o777,0o600);
    const second=report(b);
    second.cases[0]!.outputSha256=sha("5");
    repo.archiveVerifiedCaseEvidence(second,f);
    const result=new SyntheticNativeRegressionStore(root).compare(a,b);
    assert.equal(result.status,"SYNTHETIC_DIFFERENCE_DETECTED");
    assert.equal(result.changedOutputs.length,1);
    assert.equal(result.targetImportVerified,false);
    assert.equal(JSON.stringify(result).includes("raw"),false);
  });
});
test("never archive unqualified, tampered, secret-bearing or alternate fixture reports",()=>{
  inSandbox(root=>{
    const repo=new SyntheticNativeRegressionStore(root);
    for(const invalid of [
      {...report(a),fixtureSha256:sha("2")},
      {...report(a),cases:[{...report(a).cases[0]!,status:"RECORD_MISMATCH"}]},
      {...report(a),apiKey:"SECRET"},
      {...report(a),targetImportVerified:true},
    ]){
      assert.throws(()=>repo.archiveVerifiedCaseEvidence(invalid,f),
        /REGRESSION_(UNQUALIFIED|REPORT_INVALID)/);
    }
    assert.throws(()=>repo.archiveVerifiedCaseEvidence(report(a),sha("7")),
      /REGRESSION_UNQUALIFIED/);
    assert.deepEqual(repo.archiveVerifiedCaseEvidence(report(a),f),
      {backendHead:a,cases:2,reused:false});
    const replacement=report(a);
    replacement.cases[0]!.outputSha256=sha("5");
    assert.throws(()=>repo.archiveVerifiedCaseEvidence(replacement,f),
      /REGRESSION_ARCHIVE_CONFLICT/);
  });
});
test("private report file corruption, symlinks, hardlinks and unsafe file permissions fail closed",()=>{
  inSandbox(root=>{
    const repo=new SyntheticNativeRegressionStore(root);
    repo.archiveVerifiedCaseEvidence(report(a),f);
    const file=join(root,a+".json");
    chmodSync(file,0o644);
    assert.throws(()=>repo.compare(a,a),/REGRESSION_FILE_UNSAFE/);
    chmodSync(file,0o600);
    const body=readFileSync(file,"utf8");
    writeFileSync(file,body.replace("sample_firewall","PRIVATE_CUSTOMER_PASSWORD"),{mode:0o600});
    assert.throws(()=>repo.compare(a,a),/REGRESSION_REPORT_INVALID/);
    writeFileSync(file,body,{mode:0o600});
    linkSync(file,join(root,"unwanted-hardlink"));
    assert.throws(()=>repo.compare(a,a),/REGRESSION_FILE_UNSAFE/);
    unlinkSync(join(root,"unwanted-hardlink"));
    unlinkSync(file);
    symlinkSync(join(root,"wrong.json"),file);
    assert.throws(()=>repo.compare(a,a),/REGRESSION_FILE_UNSAFE/);
    unlinkSync(file);
    chmodSync(root,0o755);
    assert.throws(()=>repo.archiveVerifiedCaseEvidence(report(b),f),
      /REGRESSION_DIRECTORY_UNSAFE/);
  });
});
test("source root symlink and unknown HEAD are denied without reading files",()=>{
  inSandbox(root=>{
    const parent=join(root,"..");
    const target=join(parent,"real");
    mkdirSync(target,{mode:0o700});
    symlinkSync(target,root);
    assert.throws(()=>new SyntheticNativeRegressionStore(root).compare(a,a),
      /REGRESSION_DIRECTORY_UNSAFE/);
    unlinkSync(root);
    const valid=new SyntheticNativeRegressionStore(root);
    valid.archiveVerifiedCaseEvidence(report(a),f);
    for(const head of ["../etc/passwd","short","A".repeat(64)]){
      assert.throws(()=>valid.compare(head,a),/REGRESSION_HEAD_INVALID/);
    }
    assert.throws(()=>valid.compare(a,b),/REGRESSION_NOT_FOUND/);
  });
});
