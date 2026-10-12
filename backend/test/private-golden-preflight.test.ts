import test from "node:test";
import assert from "node:assert/strict";
import { inspectPrivateGolden, decodePrivateGoldenBytes } from "../src/private-golden.js";

function syntheticDocument(): unknown {
  return {
    kind:"parser-studio.private-golden.v0.1",
    cases:[
      {id:"synthetic-a",projectSlug:"sample_firewall",
        rawEvent:'{"src_ip":"192.0.2.17","action":"deny"}',
        expectedTime:null,expectedRecord:{srcip:"192.0.2.17",stellar_log_index:"threat"}},
      {id:"synthetic-b",projectSlug:"sample_kv",
        rawEvent:"src_ip=198.51.100.17 action=allow",
        expectedTime:"2026-10-12T01:02:03Z",
        expectedRecord:{srcip:"198.51.100.17",log:{action:"allow"}}}
    ],
  };
}

test("private golden preflight returns only bounded counts; never input records",()=>{
  const checked=inspectPrivateGolden(syntheticDocument());
  assert.equal(checked.ok,true,JSON.stringify(checked));
  if(!checked.ok)return;
  assert.equal(checked.caseCount,2);
  assert.equal(checked.profileCount,2);
  assert.equal(JSON.stringify(checked).includes("192.0.2.17"),false);
  assert.equal(JSON.stringify(checked).includes("rawEvent"),false);
});

test("private golden preflight fails closed on unrecognized fields, duplicates, unsafe record keys",()=>{
  const unknown=syntheticDocument() as any;
  unknown.cases[0].extra="DO_NOT_ECHO_PRIVATE_SECRET";
  const result=inspectPrivateGolden(unknown);
  assert.equal(result.ok,false);
  assert.equal(JSON.stringify(result).includes("DO_NOT_ECHO_PRIVATE_SECRET"),false);
  assert.ok(!result.ok && result.issues.some(x=>x.code==="PRIVATE_UNKNOWN_FIELD"));

  const dupe=syntheticDocument() as any;
  dupe.cases[1].id=dupe.cases[0].id;
  const duplicate=inspectPrivateGolden(dupe);
  assert.equal(duplicate.ok,false);
  assert.ok(!duplicate.ok && duplicate.issues.some(x=>x.code==="PRIVATE_DUPLICATE_CASE"));

  const unsafe=syntheticDocument() as any;
  unsafe.cases[0].expectedRecord=Object.fromEntries([["__proto__","unsafe"]]);
  const bad=inspectPrivateGolden(unsafe);
  assert.equal(bad.ok,false);
  assert.ok(!bad.ok && bad.issues.some(x=>x.code==="PRIVATE_UNSAFE_RECORD_KEY"));
});

test("private golden preflight rejects oversized events and unapproved paths/formats",()=>{
  const large=syntheticDocument() as any;
  large.cases[0].rawEvent="SENSITIVE_INPUT".repeat(2000);
  const oversized=inspectPrivateGolden(large);
  assert.equal(oversized.ok,false);
  assert.ok(!oversized.ok && oversized.issues.some(x=>x.code==="PRIVATE_EVENT_SIZE"));
  assert.equal(JSON.stringify(oversized).includes("SENSITIVE_INPUT"),false);

  const bad=syntheticDocument() as any;
  bad.cases[0].projectSlug="../outside";
  bad.cases[1].expectedTime="yesterday";
  const inspected=inspectPrivateGolden(bad);
  assert.equal(inspected.ok,false);
  assert.ok(!inspected.ok && inspected.issues.some(x=>x.code==="PRIVATE_PROJECT_SLUG"));
  assert.ok(!inspected.ok && inspected.issues.some(x=>x.code==="PRIVATE_TIME_FORMAT"));
});

test("private golden preflight rejects empty or oversized collections",()=>{
  const base=syntheticDocument() as any;
  base.cases=[];
  const empty=inspectPrivateGolden(base);
  assert.equal(empty.ok,false);
  assert.ok(!empty.ok && empty.issues.some(x=>x.code==="PRIVATE_CASE_COUNT"));
  base.cases=Array.from({length:33},(_,i)=>({...syntheticDocument() as any}).cases[0]);
  const many=inspectPrivateGolden(base);
  assert.equal(many.ok,false);
  assert.ok(!many.ok && many.issues.some(x=>x.code==="PRIVATE_CASE_COUNT"));
});

test("private golden UTF-8 decoding must reject malformed bytes rather than rewriting evidence", () => {
  const intact = Buffer.from('{"rawEvent":"synthetic-\uD55C\uAE00"}', "utf8");
  assert.equal(decodePrivateGoldenBytes(intact),'{"rawEvent":"synthetic-\uD55C\uAE00"}');
  const damaged = Uint8Array.from([0x7b,0x22,0x78,0x22,0x3a,0x22,0xc3,0x28,0x22,0x7d]);
  assert.throws(()=>decodePrivateGoldenBytes(damaged),(error:unknown)=>
    error instanceof Error && error.message==="PRIVATE_INVALID_UTF8");
});

test("private fixture rejects unpaired Unicode surrogates before any future replay", () => {
  const raw = syntheticDocument() as any;
  raw.cases[0].rawEvent = "PRIVATE_RAW_\uD800_END";
  const rejectedRaw = inspectPrivateGolden(raw);
  assert.equal(rejectedRaw.ok,false);
  assert.ok(!rejectedRaw.ok && rejectedRaw.issues.some(x=>
    x.code==="PRIVATE_INVALID_UNICODE" && x.path==="/cases/0/rawEvent"));
  assert.equal(JSON.stringify(rejectedRaw).includes("PRIVATE_RAW_"),false);

  const expected = syntheticDocument() as any;
  expected.cases[1].expectedRecord.log.action = "PRIVATE_EXPECTED_\uDC00_END";
  const rejectedValue = inspectPrivateGolden(expected);
  assert.equal(rejectedValue.ok,false);
  assert.ok(!rejectedValue.ok && rejectedValue.issues.some(x=>
    x.code==="PRIVATE_INVALID_UNICODE" && x.path==="/cases/1/expectedRecord"));
  assert.equal(JSON.stringify(rejectedValue).includes("PRIVATE_EXPECTED_"),false);

  const paired = syntheticDocument() as any;
  paired.cases[0].rawEvent = "synthetic \uD83D\uDE00";
  paired.cases[0].expectedRecord.log = { action:"synthetic \uD83D\uDE00" };
  const checked = inspectPrivateGolden(paired);
  assert.equal(checked.ok,true,JSON.stringify(checked));
});
