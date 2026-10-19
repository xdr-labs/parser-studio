import assert from "node:assert/strict";
import {spawnSync} from "node:child_process";
import {
  chmodSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, unlinkSync, writeFileSync,
} from "node:fs";
import {tmpdir} from "node:os";
import {join, resolve} from "node:path";
import test from "node:test";

/** Entire test uses fresh synthetic temporary files and does not access the
 * owner-operated .tmp/private-fixtures path in the backend repository.
 */
test("private golden offline CLI rejects unsafe files and never prints event contents",()=>{
  const root=mkdtempSync(join(tmpdir(),"parserstudio-fixture-preflight-"));
  const cli=resolve("node_modules/tsx/dist/cli.mjs");
  const script=resolve("scripts/preflight-private-golden.ts");
  const parent=join(root,".tmp");
  const folder=join(parent,"private-fixtures");
  const file=join(folder,"golden.json");
  const sentinel="PRIVATE_SYNTHETIC_NEVER_ECHO";
  const content=JSON.stringify({
    kind:"parser-studio.private-golden.v0.1",
    cases:[{id:"synthetic-test",projectSlug:"sample_firewall",
      rawEvent:'{"note":"'+sentinel+'","source_ip":"192.0.2.19"}',
      expectedTime:null,expectedRecord:{srcip:"192.0.2.19"}}],
  });
  const run=()=>{
    const result=spawnSync(process.execPath,[cli,script],{
      cwd:root,encoding:"utf8",timeout:15000,maxBuffer:128*1024,
    });
    assert.equal(result.error,undefined);
    assert.equal(result.stdout.includes(sentinel),false,"stdout leaks synthetic event");
    assert.equal(result.stderr.includes(sentinel),false,"stderr leaks synthetic event");
    return result;
  };
  try{
    mkdirSync(parent,{mode:0o700});
    mkdirSync(folder,{mode:0o700});
    const absent=run();
    assert.equal(absent.status,2);
    assert.match(absent.stderr,/PRIVATE_FILE_MISSING/);
    writeFileSync(file,content,{mode:0o600});
    const valid=run();
    assert.equal(valid.status,0,valid.stderr);
    assert.match(valid.stdout,/PRIVATE_PREFLIGHT_OK cases=1 profiles=1 native=false target=false/);
    chmodSync(file,0o644);
    const openPermissions=run();
    assert.equal(openPermissions.status,2);
    assert.match(openPermissions.stderr,/PRIVATE_FILE_UNSAFE/);
    chmodSync(file,0o600);
    writeFileSync(file,Buffer.from([0x7b,0x22,0x78,0x22,0x3a,0xc3,0x28,0x7d]));
    const brokenUtf8=run();
    assert.equal(brokenUtf8.status,2);
    assert.match(brokenUtf8.stderr,/PRIVATE_INVALID_UTF8/);
    writeFileSync(file,content);
    chmodSync(parent,0o777);
    const untrustedParent=run();
    assert.equal(untrustedParent.status,2);
    assert.match(untrustedParent.stderr,/PRIVATE_PARENT_UNSAFE/);
    chmodSync(parent,0o700);
    unlinkSync(file);
    const elsewhere=join(folder,"synthetic-source.json");
    writeFileSync(elsewhere,content,{mode:0o600});
    symlinkSync(elsewhere,file);
    const redirected=run();
    assert.equal(redirected.status,2);
    assert.match(redirected.stderr,/PRIVATE_FILE_UNSAFE/);
  }finally{
    chmodSync(parent,0o700);
    rmSync(root,{recursive:true,force:true});
  }
});
