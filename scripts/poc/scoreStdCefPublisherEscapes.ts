/**
 * Independent publisher-written ArcSight CEF v26 character-encoding examples.
 * Score actual immutable original bytes; never pass source synthetics/native.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {extractStructuredFamily} from '../../src/structuredFamilies';
import {arbitrateIndependentNonJson} from '../../src/poc/independentNonJsonStructural';
import {parseSecurityInput} from '../../src/securityInputPipeline';

const digest=(v:Uint8Array|string)=>createHash('sha256').update(v).digest('hex');
const expectedManifest='ec43bbf61e211e693cff40ce813a289863743396a64b164194cfc65fe16f7309';
const rawManifest=fs.readFileSync('scripts/poc/standardCefPublisherEscapes.pinned.json');
if(digest(rawManifest)!==expectedManifest)
 throw Error('Independent CEF escaped publisher original source oracle has changed');
type Expected={
 name:string;ordinal:number;category:string;startByte:number;endByte:number;
 rawSha256:string;decodedSha256:string;
};
type Example={
 id:string;privateFile:string;originalSha256:string;originalBytes:number;
 cefMarkerByte:number;originalPrefixSha256:string;claimCount:number;claims:Expected[];
};
type Manifest={cases:Example[];sourceOnly:true;nativeTarget:'NOT_VERIFIED'};
const manifest=JSON.parse(rawManifest.toString('utf8')) as Manifest;
if(manifest.cases.length!==4||manifest.sourceOnly!==true||
   manifest.nativeTarget!=='NOT_VERIFIED')
 throw Error('Publisher ArcSight encoding source oracle scope drift');
const expectedTotal=manifest.cases.reduce((sum,c)=>sum+c.claimCount,0);
if(expectedTotal!==39)throw Error('CEF publisher original field denominator drift');
const originalDirectory=path.join(os.homedir(),
 '.local/state/parserstudio-std9-cef-extension-publisher-20261018');
const mapping:Record<string,string>={
 version:'cef_version',deviceVendor:'cef_device_vendor',
 deviceProduct:'cef_device_product',deviceVersion:'cef_device_version',
 deviceEventClassId:'cef_signature_id',name:'cef_name',severity:'cef_severity',
};
const report={
 scope:'PUBLISHER_DOCUMENTATION_ENCODING_ILLUSTRATIONS_ONLY',
 sourceShaPinned:true,examples:manifest.cases.length,
 expectedSourceClaims:expectedTotal,tp:0,fp:0,fn:0,
 exactPublisherExamples:0,originalSpanDrift:0,
 browserExactExamples:0,pipelineExactExamples:0,
 unqualifiedSourceSuccess:0,nativeVerified:false,
 independentDeviceWireCount:0,completeEventNativeAccuracy:'UNSCORABLE',
 historicalSafetyRelabeled:false,
};
const decoder=new TextDecoder('utf8',{fatal:true});
for(const testcase of manifest.cases){
 const file=path.join(originalDirectory,testcase.privateFile);
 if(!fs.existsSync(file))
   throw Error('Publisher private original missing: UNSCORABLE');
 const original=fs.readFileSync(file);
 if(digest(original)!==testcase.originalSha256||
    original.length!==testcase.originalBytes)
   throw Error('ArcSight official original bytes SHA drift');
 const prefix=original.subarray(0,testcase.cefMarkerByte);
 if(digest(prefix)!==testcase.originalPrefixSha256)
   throw Error('Publisher original prefix is not independently anchored');
 const raw=decoder.decode(original);
 const body=raw.slice(testcase.cefMarkerByte);
 if(!body.startsWith('CEF:'))throw Error('CEF source marker boundary drift');
 const source=arbitrateIndependentNonJson(raw);
 const browser=extractStructuredFamily(body,'cef');
 const pipeline=parseSecurityInput(raw);
 const full= pipeline.ok ?
   (pipeline.events[0]?.fields.body as Record<string,unknown>||{}) : {};
 const sourceFields=source.bodyClaims;
 let exampleCorrect=0,browserCorrect=0,pipelineCorrect=0;
 const acceptedBySource=source.disposition==='REVIEW_ONLY_STRUCTURED_BODY'&&
  source.selectedBodyGrammar==='cef'&&source.nativeVerified===false&&
  source.autoPromoted===false;
 if(source.autoPromoted||source.nativeVerified)report.unqualifiedSourceSuccess++;
 for(const claim of testcase.claims){
   const observed=sourceFields[claim.ordinal];
   const slice=original.subarray(claim.startByte,claim.endByte);
   const rawCorrect=digest(slice)===claim.rawSha256;
   const originalOffset=observed?.startByte===claim.startByte&&
     observed?.endByte===claim.endByte;
   const originalLexeme=observed&&digest(observed.rawSpanValue)===claim.rawSha256;
   const sourceDecoded=observed&&typeof observed.value==='string'&&
     digest(observed.value)===claim.decodedSha256;
   const originalName=observed?.name===claim.name;
   const key=mapping[claim.name]??claim.name;
   const inBrowser=browser.errors.length===0&&
     typeof browser.fields[key]==='string'&&
     digest(browser.fields[key] as string)===claim.decodedSha256;
   const inPipeline=pipeline.ok&&pipeline.events.length===1&&
     pipeline.source_raw===raw&&typeof full[key]==='string'&&
     digest(full[key] as string)===claim.decodedSha256;
   if(observed && decoder.decode(original.subarray(
     observed.startByte,observed.endByte))!==observed.rawSpanValue)
     report.originalSpanDrift++;
   if(inBrowser)browserCorrect++;
   if(inPipeline)pipelineCorrect++;
   if(rawCorrect&&originalOffset&&originalLexeme&&sourceDecoded&&
      originalName&&inBrowser&&inPipeline&&acceptedBySource){
     exampleCorrect++;report.tp++;
   }else report.fn++;
 }
 report.fp+=sourceFields.length-exampleCorrect;
 if(exampleCorrect===testcase.claimCount)report.exactPublisherExamples++;
 if(browserCorrect===testcase.claimCount)report.browserExactExamples++;
 if(pipelineCorrect===testcase.claimCount)report.pipelineExactExamples++;
}
console.log('STD_CEF_PUBLISHER_ESCAPE_EXACT_SOURCE_SCORE '+JSON.stringify(report));
if(report.tp!==report.expectedSourceClaims||report.fp||report.fn||
  report.originalSpanDrift||report.unqualifiedSourceSuccess||
  report.exactPublisherExamples!==report.examples||
  report.browserExactExamples!==report.examples||
  report.pipelineExactExamples!==report.examples)
 process.exitCode=1;
