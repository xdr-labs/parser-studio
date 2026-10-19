import assert from "node:assert/strict";
import test from "node:test";
import {
  chmodSync,mkdtempSync,writeFileSync,readFileSync,symlinkSync,unlinkSync,rmSync,
} from "node:fs";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {
  loadPocProfileClient,createPocFileAuditSink,
} from "../src/stellar-legacy-server-secrets.js";

test("explicit local POC profile accepts owner-only file, denies symlink/permissions/bad host without exposing secret",()=>{
  const root=mkdtempSync(join(tmpdir(),"parser-studio-poc-vault-"));
  const file=join(root,"test-profile.json");
  const secret="PRIVATE_API_KEY_NEVER_ECHO";
  const content=JSON.stringify({host:"https://poc-apac.stellarcyber.cloud",
    tenant:"synthetic_tenant",key:secret});
  try{
    writeFileSync(file,content,{mode:0o600});
    const client=loadPocProfileClient(file);
    assert.equal(client.tenant,"synthetic_tenant");
    assert.equal(JSON.stringify(client).includes(secret),false);
    chmodSync(file,0o644);
    assert.throws(()=>loadPocProfileClient(file),/POC_PRIVATE_FILE_UNSAFE/);
    chmodSync(file,0o600);
    chmodSync(root,0o777);
    assert.throws(()=>loadPocProfileClient(file),/POC_PRIVATE_DIRECTORY_UNSAFE/);
    chmodSync(root,0o700);
    unlinkSync(file);
    writeFileSync(join(root,"real.json"),content,{mode:0o600});
    symlinkSync(join(root,"real.json"),file);
    assert.throws(()=>loadPocProfileClient(file),/POC_PRIVATE_FILE_UNSAFE/);
    unlinkSync(file);
    writeFileSync(file,JSON.stringify({host:"https://evil.example",tenant:"synthetic_tenant",key:secret}));
    chmodSync(file,0o600);
    assert.throws(()=>loadPocProfileClient(file),/POC_PRIVATE_PROFILE_INVALID/);
  }finally{
    chmodSync(root,0o700);rmSync(root,{recursive:true,force:true});
  }
});

test("durable local audit creates owner-only NDJSON with safe metadata, no parser contents, token or key",async()=>{
  const root=mkdtempSync(join(tmpdir(),"parser-studio-poc-audit-"));
  const file=join(root,"poc-events.ndjson");
  try{
    const audit=createPocFileAuditSink(file);
    const base={method:"POST" as const,tenant:"synthetic_tenant",
      name:"customized_ps_api_crud_test_a1b2c3",version:"1.0.0",
      approvalId:"operator-approval-1",apiRegistrationVerified:false,
      runtimeParsingVerified:false as const,targetImportVerified:false as const};
    await audit({...base,phase:"BEFORE"});
    await audit({...base,phase:"AFTER",apiRegistrationVerified:true,httpStatus:200});
    const output=readFileSync(file,"utf8");
    assert.equal(output.trim().split("\n").length,2);
    assert.equal(output.includes("JWT_PRIVATE"),false);
    assert.equal(output.includes("STELLAR_INIT_BEGIN"),false);
    assert.equal(output.includes("API_KEY"),false);
    const rows=output.trim().split("\n").map(row=>JSON.parse(row));
    assert.equal(rows[1].phase,"AFTER");
    assert.equal(rows[1].apiRegistrationVerified,true);
  }finally{rmSync(root,{recursive:true,force:true});}
});
