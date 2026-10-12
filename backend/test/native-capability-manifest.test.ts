import test from "node:test";
import assert from "node:assert/strict";
import {createHash} from "node:crypto";
import {readFileSync} from "node:fs";
import {resolve} from "node:path";
import {buildSyntheticNativeCapabilityManifest,NativeCapabilityManifestError}
  from "../src/native-capability-manifest.js";

const sha=(value:Buffer|string)=>createHash("sha256").update(value).digest("hex");
const head="a".repeat(40);
const fixtureBytes=readFileSync(resolve("test_native/fixtures/synthetic-golden.v0.1.json"));
const fixture=JSON.parse(fixtureBytes.toString("utf8")) as {
  cases:Array<{id:string;slug:string;raw:string;expectedRecord:unknown}>;
};
const fixtureHash=sha(fixtureBytes);
const cases=()=>({
  kind:"parser-studio.synthetic-native-case-evidence.v0.1",
  origin:"independently-authored-public-synthetic",
  backendHead:head,fixtureSha256:fixtureHash,
  ruby:"3.2",fluentd:"1.17.1",
  cases:fixture.cases.map((row,i)=>({id:row.id,slug:row.slug,status:"PASS",
    outputSha256:sha(String(i))})),
  sensorTrafficSent:false,actualTdAgentOrStellarImport:false,
  targetImportVerified:false,
});
const native=(caseReport=cases())=>{
  const slugs=[...new Set(fixture.cases.map(row=>row.slug))];
  return {
    kind:"xdr-labs.parser-studio.synthetic-native-profile.v0.1",
    backendHead:head,worktreeDirty:false,origin:"synthetic-repository-fixtures",
    rubyProfile:"3.2",fluentd:"1.17.1",fixturePairs:10,
    result:"SYNTHETIC_FLUENTD_PARSER_AND_CONF_AST_PASS",
    pluginParserCallbackChecked:true,generatedFixtureSourceIntegrityChecked:true,
    configParsedWithTransportIncludeRemovedInMemory:true,
    rubyChildResourceLimitsChecked:true,
    syntheticGoldenCases:23,syntheticGoldenProfiles:10,
    syntheticGoldenFixtureHash:fixtureHash,
    syntheticGoldenCaseReportSha256:sha(Buffer.from(JSON.stringify(caseReport)+"\n")),
    verifiedExactPairImports:10,rejectedModifiedPairImports:10,
    offlineSyntheticPreviewCases:7,
    actualTdAgentOrStellarImport:false,targetImportVerified:false,
    sensorTrafficSent:false,pocApiMutationPerformed:false,
    fileHashes:Object.fromEntries(slugs.flatMap(slug=>([
      ["customized_"+slug,"f".repeat(64)],
      ["customized_"+slug+".conf","e".repeat(64)],
    ]))),
  };
};
const golden=()=>({
  kind:"parser-studio.synthetic-golden-native.v0.1",
  backendHead:head,
  origin:"independently-authored-public-synthetic",
  fixtureSha256:fixtureHash,casesPassed:23,profilesPassed:10,
  fluentd:"1.17.1",actualTdAgentOrStellarImport:false,
  targetImportVerified:false,
});
const fixtureIds=fixture.cases.map(row=>({id:row.id,slug:row.slug}));
const make=(overrides?:{
  native?:Record<string,unknown>;golden?:Record<string,unknown>;
  cases?:ReturnType<typeof cases>;
  expectedHead?:string;expectedCaseIds?:typeof fixtureIds;
})=>{
  const caseReport=overrides?.cases??cases();
  return buildSyntheticNativeCapabilityManifest({
    nativeReport:overrides?.native??native(caseReport),
    goldenReport:overrides?.golden??golden(),caseReport,
    caseEvidenceBytes:Buffer.from(JSON.stringify(caseReport)+"\n"),
    expectedHead:overrides?.expectedHead??head,
    expectedFixtureSha256:fixtureHash,
    expectedCases:overrides?.expectedCaseIds??fixtureIds,
  });
};
const reject=(f:()=>unknown)=>assert.throws(f,(error:unknown)=>
  error instanceof NativeCapabilityManifestError&&
  error.code.startsWith("NATIVE_CAPABILITY_"));

test("exact-HEAD native manifest is deterministic per fixed synthetic profile and shows no target claims",()=>{
  const m=make();
  assert.equal(m.contract,"parser-studio.synthetic-native-capabilities.v0.1");
  assert.equal(m.proofScope,"REVIEWED_PUBLIC_SYNTHETIC_ONLY");
  assert.equal(m.backendHead,head);
  assert.equal(m.engine.ruby,"3.2.x");
  assert.equal(m.engine.fluentd,"1.17.1");
  assert.equal(m.casesPassed,23);
  assert.equal(m.profiles.length,10);
  assert.deepEqual(m.profiles.map(p=>p.slug),[...m.profiles.map(p=>p.slug)].sort());
  assert.equal(m.profiles.reduce((sum,p)=>sum+p.goldenCases,0),23);
  assert.equal(m.profiles.filter(p=>p.extraction==="syslog_rfc5424").length,3);
  assert.equal(m.profiles.filter(p=>p.extraction==="cef").length,1);
  assert.equal(m.profiles.filter(p=>p.extraction==="leef").length,1);
  for(const p of m.profiles){
    assert.match(p.rubySha256,/^[0-9a-f]{64}$/);
    assert.match(p.confSha256,/^[0-9a-f]{64}$/);
    assert.equal(p.fluentdSyntheticCallbackVerified,true);
    assert.equal(p.fluentdConfAstVerified,true);
    assert.equal(p.stellarLoaderVerified,false);
  }
  assert.equal(m.nativeCapabilityVerified,true);
  assert.equal(m.stellarImportVerified,false);
  assert.equal(m.sensorReceivingVerified,false);
  assert.equal(m.customerSampleVerified,false);
  assert.equal(m.supportedBeyondSynthetic,false);
  assert.equal(m.optionalSupportVerified.rfc3164,false);
  assert.equal(m.optionalSupportVerified.multiline,false);
  assert.equal(m.optionalSupportVerified.arbitraryRegex,false);
  assert.equal(m.optionalSupportVerified.jsonata,false);
  assert.equal(m.optionalSupportVerified.mixedFormatAutoRouting,false);
  assert.equal(m.digest,make().digest);
  assert.equal(JSON.stringify(m).includes(fixture.cases[0]!.raw),false);
  assert.equal(JSON.stringify(m).includes("192.0.2.17"),false);
});

test("report body/hashes cannot claim verified target or accept unexpected sample fields",()=>{
  for(const mutate of [
    (n:any)=>{n.worktreeDirty=true;},
    (n:any)=>{n.targetImportVerified=true;},
    (n:any)=>{n.sensorTrafficSent=true;},
    (n:any)=>{n.pluginParserCallbackChecked=false;},
    (n:any)=>{n.syntheticGoldenCases=24;},
    (n:any)=>{n.fileHashes.customized_unknown="1".repeat(64);},
    (n:any)=>{n.fileHashes.customized_sample_cef="BAD";},
    (n:any)=>{delete n.fileHashes["customized_sample_leef.conf"];},
  ]){
    const r=native();mutate(r);
    reject(()=>make({native:r}));
  }
  const g=golden();
  reject(()=>make({golden:{...g,targetImportVerified:true}}));
  const c=cases();
  (c.cases[0] as any).rawEvent="CUSTOMER_PASSWORD";
  reject(()=>make({cases:c,native:native(c)}));
});

test("head/fixture/case list/version/case evidence changes reject rather than silently certify",()=>{
  reject(()=>make({expectedHead:"b".repeat(40)}));
  reject(()=>make({expectedCaseIds:fixtureIds.slice(1)}));
  const g=golden();g.fixtureSha256="b".repeat(64);
  reject(()=>make({golden:g}));
  const c=cases();
  c.cases[0]!.status="RECORD_MISMATCH";
  reject(()=>make({cases:c,native:native(c)}));
  const c2=cases();c2.cases[1]!.slug="sample_wrong";
  reject(()=>make({cases:c2,native:native(c2)}));
  const c3=cases();c3.cases.push({...c3.cases[0]!});
  reject(()=>make({cases:c3,native:native(c3)}));
});
