import assert from "node:assert/strict";
import test from "node:test";
import { readFileSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { resolve } from "node:path";
import { safeSyntheticOutputDirectory, writeSyntheticFixture } from "../src/synthetic-fixture-safety.js";

test("native synthetics cannot redirect output files outside ignored project-local fixture root", () => {
  const allowed=resolve(".tmp/native-fixtures");
  assert.equal(safeSyntheticOutputDirectory(),allowed);
  assert.equal(safeSyntheticOutputDirectory(allowed),allowed);
  assert.throws(()=>safeSyntheticOutputDirectory("/tmp/custom-parser-export"),/synthetic.*directory/i);
  assert.throws(()=>writeSyntheticFixture(allowed,"../unrelated.txt","data"),/synthetic.*filename/i);
});

test("native synthetic writer must not follow a symlink into an unrelated file", () => {
  const root=safeSyntheticOutputDirectory();
  const filename="customized_safety_probe_"+process.pid;
  const alias=resolve(root,filename);
  const target=resolve(root,"safety_target_"+process.pid);
  writeFileSync(target,"KEEP_SYNTHETIC_SENTINEL",{mode:0o600});
  symlinkSync(target,alias);
  try {
    assert.throws(()=>writeSyntheticFixture(root,filename,"OVERWRITE"),/synthetic.*file/i);
    assert.equal(readFileSync(target,"utf8"),"KEEP_SYNTHETIC_SENTINEL");
  } finally {
    unlinkSync(alias);
    unlinkSync(target);
  }
});
