import test from "node:test";
import assert from "node:assert/strict";
import {compilePair} from "../src/compiler.js";
import {sampleProject} from "./fixture.js";
import {buildImportLossReport} from "../src/import-loss-report.js";
import {PairInspectionError} from "../src/import.js";
const synthetic=()=>{
  const pair=compilePair(sampleProject());
  return {
    name:"customized_sample_firewall",
    confContent:pair.files.find(f=>f.name.endsWith(".conf"))!.content,
    fragmentContent:pair.files.find(f=>!f.name.endsWith(".conf"))!.content,
  };
};
test("exact internally generated import report has byte-equivalent roundtrip and no loss claim",()=>{
  const source=synthetic();
  const result=buildImportLossReport(source);
  assert.equal(result.contract,"parser-import-loss-report.v0.1");
  assert.equal(result.conversionStatus,"EXACT_EDITABLE");
  assert.equal(result.roundTripVerified,true);
  assert.equal(result.knownConversionLoss,false);
  assert.equal(result.unknownContentRisk,false);
  assert.equal(result.requiresOriginalFiles,false);
  assert.deepEqual(result.issueCodes,[]);
  assert.match(result.sourceHashes.conf,/^[a-f0-9]{64}$/);
  assert.equal(result.includesSourceText,false);
  assert.equal(JSON.stringify(result).includes("STELLAR_INIT_BEGIN"),false);
});
test("opaque Ruby is never represented as losslessly editable or safely converted",()=>{
  const source=synthetic();
  source.fragmentContent="# STELLAR_INIT_BEGIN\n# PRIVATE_CUSTOMER_VALUE\n# STELLAR_INIT_END\n";
  const result=buildImportLossReport(source);
  assert.equal(result.conversionStatus,"OPAQUE_KEEP_ORIGINALS");
  assert.equal(result.roundTripVerified,false);
  assert.equal(result.knownConversionLoss,null);
  assert.equal(result.unknownContentRisk,true);
  assert.equal(result.requiresOriginalFiles,true);
  assert.ok(result.issueCodes.includes("PAIR_NOT_REPRODUCIBLE"));
  assert.ok(result.issueCodes.includes("RUBY_MARKERS_INCOMPLETE"));
  assert.equal(JSON.stringify(result).includes("PRIVATE_CUSTOMER_VALUE"),false);
  assert.equal(JSON.stringify(result).includes("STELLAR_INIT_BEGIN"),false);
});
test("distinct CONF ports or unsupported receivers become actionable redacted issue codes",()=>{
  const source=synthetic();
  source.confContent+=[
    "\n<source>"," @type http"," port 7654",
    " tag customized_sample_firewall",
    " <parse>"," @type customized_sample_firewall"," </parse>",
    "</source>\n",
  ].join("\n");
  const result=buildImportLossReport(source);
  assert.equal(result.roundTripVerified,false);
  assert.ok(result.issueCodes.includes("CONF_MULTI_PORT_LAYOUT"));
  assert.ok(result.issueCodes.includes("CONF_RECEIVER_NOT_EDITABLE"));
  assert.equal(result.receiver.portConsistencyVerified,false);
  assert.equal(result.deployableNow,false);
});
test("invalid content and oversized import retain original PairInspection safety bounds",()=>{
  const valid=synthetic();
  assert.throws(()=>buildImportLossReport({...valid,name:"../../bad"}),
    (error:unknown)=>error instanceof PairInspectionError&&error.code==="PAIR_NAME_INVALID");
  assert.throws(()=>buildImportLossReport({...valid,fragmentContent:"x".repeat(3*1024*1024)}),
    (error:unknown)=>error instanceof PairInspectionError&&error.code==="PAIR_SIZE_EXCEEDED");
});
test("same bytes give deterministic redacted report; original content is not modified",()=>{
  const source=synthetic();
  const original=JSON.stringify(source);
  const a=buildImportLossReport(source);
  const b=buildImportLossReport(source);
  assert.deepEqual(a,b);
  assert.equal(JSON.stringify(source),original);
});
