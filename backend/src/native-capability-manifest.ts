/**
 * Fixed-public-synthetic Fluentd capability evidence. No parser source,
 * customer events, normalized values or credentials are serialized.
 *
 * This is a deterministic description of the exact-HEAD offline native
 * qualification, NOT a per-user parser claim, installed Stellar loader proof,
 * general Ruby sandbox or live sensor/DP verification.
 */
import {createHash} from "node:crypto";
import {validateSyntheticNativeCaseReport,NativeRegressionError}
  from "./native-regression-diff.js";

const SHA=/^[0-9a-f]{64}$/;
const HEAD=/^[0-9a-f]{40}$/;
const sha=(bytes:Buffer|string)=>createHash("sha256").update(bytes).digest("hex");
export class NativeCapabilityManifestError extends Error{
  constructor(readonly code:string){super(code);this.name="NativeCapabilityManifestError";}
}
const deny=(code:string):never=>{throw new NativeCapabilityManifestError(code);};
const isPlain=(value:unknown):value is Record<string,unknown>=>
  value!==null&&typeof value==="object"&&!Array.isArray(value)&&
  (Object.getPrototypeOf(value)===Object.prototype||
   Object.getPrototypeOf(value)===null);
const keysMatch=(v:unknown,fields:readonly string[]):v is Record<string,unknown>=>
  isPlain(v)&&Object.keys(v).length===fields.length&&
  Object.keys(v).every(key=>fields.includes(key));

type Extraction="json"|"kv"|"csv"|"cef"|"leef"|"syslog_rfc5424";
type BodyFormat="none"|"kv"|"cef"|"leef";
const PROFILES={
  sample_firewall:{extraction:"json",bodyFormat:"none"},
  sample_kv:{extraction:"kv",bodyFormat:"none"},
  sample_extended:{extraction:"json",bodyFormat:"none"},
  sample_csv:{extraction:"csv",bodyFormat:"none"},
  sample_syslog:{extraction:"syslog_rfc5424",bodyFormat:"kv"},
  sample_syslog_cef:{extraction:"syslog_rfc5424",bodyFormat:"cef"},
  sample_syslog_leef:{extraction:"syslog_rfc5424",bodyFormat:"leef"},
  sample_cef:{extraction:"cef",bodyFormat:"none"},
  sample_leef:{extraction:"leef",bodyFormat:"none"},
  sample_enriched:{extraction:"json",bodyFormat:"none"},
} as const satisfies Record<string,{extraction:Extraction;bodyFormat:BodyFormat}>;
const SLUGS=Object.keys(PROFILES).sort();
const REPORT_FIELDS=new Set([
  "kind","backendHead","worktreeDirty","origin","rubyProfile","fluentd",
  "fixturePairs","result","pluginParserCallbackChecked",
  "generatedFixtureSourceIntegrityChecked","rubyChildVirtualMemoryLimitKiB",
  "rubyChildCpuLimitSeconds","rubyChildWallLimitSeconds",
  "rubyChildResourceLimitsChecked","operatorTargetProfileInputTestsPassed",
  "operatorTargetReadOnlyProbeMockTestsPassed","operatorPortPlanningMockTestsPassed",
  "pocDisposableLoopbackNullSinkAstChecked","pocApiMutationPerformed",
  "offlineSyntheticPreviewNativeChecked","offlineSyntheticPreviewCases",
  "sensorTrafficSent","syntheticLoopbackUdpTcpNodeTestsPassed",
  "rfc5424SdNameAndParameterGrammarChecked","rfc5424SdPositiveCases",
  "rfc5424SdNegativeCases","sourceIntegrityNegativeCases",
  "configParsedWithTransportIncludeRemovedInMemory",
  "verifiedExactPairImports","rejectedModifiedPairImports",
  "syntheticGoldenCases","syntheticGoldenProfiles","syntheticGoldenFixtureHash",
  "syntheticGoldenCaseReportSha256","actualTdAgentOrStellarImport",
  "targetImportVerified","fileHashes","caveat"
]);
const GOLDEN_FIELDS=[
  "kind","backendHead","origin","fixtureSha256","casesPassed",
  "profilesPassed","fluentd","actualTdAgentOrStellarImport",
  "targetImportVerified"
];
const FIXTURE_CASE_FIELDS=["id","slug"];

export type NativeCapabilityManifest={
  contract:"parser-studio.synthetic-native-capabilities.v0.1";
  proofScope:"REVIEWED_PUBLIC_SYNTHETIC_ONLY";
  backendHead:string;
  fixtureSha256:string;
  caseEvidenceSha256:string;
  engine:{
    ruby:"3.2.x";
    fluentd:"1.17.1";
    validation:"PINNED_FLUENTD_PARSER_PLUGIN_API_AND_CONF_AST";
  };
  casesPassed:23;
  nativeCapabilityVerified:true;
  profiles:Array<{
    slug:string;
    extraction:Extraction;
    bodyFormat:BodyFormat;
    goldenCases:number;
    rubySha256:string;
    confSha256:string;
    fluentdSyntheticCallbackVerified:true;
    fluentdConfAstVerified:true;
    stellarLoaderVerified:false;
  }>;
  optionalSupportVerified:{
    rfc3164:false;
    multiline:false;
    arbitraryRegex:false;
    jsonata:false;
    mixedFormatAutoRouting:false;
    arbitraryRuby:false;
  };
  stellarImportVerified:false;
  sensorReceivingVerified:false;
  customerSampleVerified:false;
  supportedBeyondSynthetic:false;
  digest:string;
};
export type NativeCapabilityManifestInput={
  nativeReport:unknown;
  goldenReport:unknown;
  caseReport:unknown;
  caseEvidenceBytes:Buffer;
  expectedHead:string;
  expectedFixtureSha256:string;
  expectedCases:unknown;
};
export function buildSyntheticNativeCapabilityManifest(
  input:NativeCapabilityManifestInput
):NativeCapabilityManifest{
  if(!input||!HEAD.test(input.expectedHead)||!SHA.test(input.expectedFixtureSha256)||
     !Buffer.isBuffer(input.caseEvidenceBytes)||
     input.caseEvidenceBytes.length<1||input.caseEvidenceBytes.length>128*1024||
     !Array.isArray(input.expectedCases)||input.expectedCases.length!==23)
    return deny("NATIVE_CAPABILITY_INPUT_INVALID");

  const expected=new Map<string,string>();
  const counts=new Map<string,number>(SLUGS.map(slug=>[slug,0]));
  for(const item of input.expectedCases){
    if(!keysMatch(item,FIXTURE_CASE_FIELDS)||
       typeof item.id!=="string"||typeof item.slug!=="string"||
       !Object.hasOwn(PROFILES,item.slug)||expected.has(item.id))
      return deny("NATIVE_CAPABILITY_FIXTURE_INVALID");
    expected.set(item.id,item.slug);
    counts.set(item.slug,(counts.get(item.slug)??0)+1);
  }
  if(counts.size!==10||[...counts.values()].some(x=>x<1)||
     !isPlain(input.nativeReport)||!isPlain(input.goldenReport)||
     [...Object.keys(input.nativeReport)].some(x=>!REPORT_FIELDS.has(x)))
    return deny("NATIVE_CAPABILITY_REPORT_INVALID");

  const n=input.nativeReport,g=input.goldenReport;
  if(n.kind!=="xdr-labs.parser-studio.synthetic-native-profile.v0.1"||
     n.backendHead!==input.expectedHead||n.worktreeDirty!==false||
     n.origin!=="synthetic-repository-fixtures"||
     n.rubyProfile!=="3.2"||n.fluentd!=="1.17.1"||
     n.fixturePairs!==10||
     n.result!=="SYNTHETIC_FLUENTD_PARSER_AND_CONF_AST_PASS"||
     n.pluginParserCallbackChecked!==true||
     n.generatedFixtureSourceIntegrityChecked!==true||
     n.configParsedWithTransportIncludeRemovedInMemory!==true||
     n.rubyChildResourceLimitsChecked!==true||
     n.syntheticGoldenCases!==23||n.syntheticGoldenProfiles!==10||
     n.verifiedExactPairImports!==10||n.rejectedModifiedPairImports!==10||
     n.syntheticGoldenFixtureHash!==input.expectedFixtureSha256||
     n.syntheticGoldenCaseReportSha256!==sha(input.caseEvidenceBytes)||
     n.sensorTrafficSent!==false||n.pocApiMutationPerformed!==false||
     n.actualTdAgentOrStellarImport!==false||
     n.targetImportVerified!==false||
     !keysMatch(g,GOLDEN_FIELDS)||
     g.kind!=="parser-studio.synthetic-golden-native.v0.1"||
     g.backendHead!==input.expectedHead||
     g.origin!=="independently-authored-public-synthetic"||
     g.fixtureSha256!==input.expectedFixtureSha256||
     g.casesPassed!==23||g.profilesPassed!==10||
     g.fluentd!=="1.17.1"||g.actualTdAgentOrStellarImport!==false||
     g.targetImportVerified!==false)
    return deny("NATIVE_CAPABILITY_EVIDENCE_MISMATCH");

  let c:ReturnType<typeof validateSyntheticNativeCaseReport>;
  try{c=validateSyntheticNativeCaseReport(input.caseReport);}
  catch(error){
    if(error instanceof NativeRegressionError)
      return deny("NATIVE_CAPABILITY_CASES_INVALID");
    return deny("NATIVE_CAPABILITY_CASES_INVALID");
  }
  if(c.backendHead!==input.expectedHead||
     c.fixtureSha256!==input.expectedFixtureSha256||
     c.cases.length!==23||
     c.cases.some((row,i)=>row.id!==(
       input.expectedCases as Array<{id:string;slug:string}>)[i]!.id||
       expected.get(row.id)!==row.slug||row.status!=="PASS"))
    return deny("NATIVE_CAPABILITY_CASES_INVALID");

  if(!isPlain(n.fileHashes))return deny("NATIVE_CAPABILITY_FILE_HASH_INVALID");
  const fileHashes=n.fileHashes;
  const allowed=new Set(SLUGS.flatMap(slug=>
    ["customized_"+slug,"customized_"+slug+".conf"]));
  if(Object.keys(fileHashes).length!==20||
     Object.keys(fileHashes).some(k=>!allowed.has(k)||
       typeof fileHashes[k]!=="string"||!SHA.test(fileHashes[k])))
    return deny("NATIVE_CAPABILITY_FILE_HASH_INVALID");

  const profiles:NativeCapabilityManifest["profiles"]=SLUGS.map(slug=>({
    slug,
    extraction:PROFILES[slug as keyof typeof PROFILES].extraction,
    bodyFormat:PROFILES[slug as keyof typeof PROFILES].bodyFormat,
    goldenCases:counts.get(slug)!,
    rubySha256:fileHashes["customized_"+slug] as string,
    confSha256:fileHashes["customized_"+slug+".conf"] as string,
    fluentdSyntheticCallbackVerified:true,
    fluentdConfAstVerified:true,
    stellarLoaderVerified:false,
  }));
  const withoutDigest:Omit<NativeCapabilityManifest,"digest">={
    contract:"parser-studio.synthetic-native-capabilities.v0.1",
    proofScope:"REVIEWED_PUBLIC_SYNTHETIC_ONLY",
    backendHead:input.expectedHead,
    fixtureSha256:input.expectedFixtureSha256,
    caseEvidenceSha256:sha(input.caseEvidenceBytes),
    engine:{
      ruby:"3.2.x",fluentd:"1.17.1",
      validation:"PINNED_FLUENTD_PARSER_PLUGIN_API_AND_CONF_AST",
    },
    casesPassed:23,
    nativeCapabilityVerified:true,
    profiles,
    optionalSupportVerified:{
      rfc3164:false,multiline:false,arbitraryRegex:false,jsonata:false,
      mixedFormatAutoRouting:false,arbitraryRuby:false,
    },
    stellarImportVerified:false,
    sensorReceivingVerified:false,
    customerSampleVerified:false,
    supportedBeyondSynthetic:false,
  };
  return {...withoutDigest,digest:sha(JSON.stringify(withoutDigest))};
}
