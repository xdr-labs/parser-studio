/**
 * Independently authored ArcSight CEF standard examples; source- and
 * browser-stage field accuracy only, never production/native certification.
 * Original publisher log lines MUST remain private on dev-atlas.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import {createHash} from 'node:crypto';
import {extractStructuredFamily} from '../../src/structuredFamilies';
import {arbitrateIndependentNonJson} from '../../src/poc/independentNonJsonStructural';
import {parseSecurityInput} from '../../src/securityInputPipeline';

const sha=(bytes:Uint8Array|string)=>createHash('sha256').update(bytes).digest('hex');
const manifestSha='c4384572021d05515f7a92918c4f00618eb0acf3e15637172be0adceaa4b4882';
const manifestFile='scripts/poc/standard9PublisherCefExamples.pinned.json';
const manifestBytes=fs.readFileSync(manifestFile);
if(sha(manifestBytes)!==manifestSha)
  throw Error('Expected published ArcSight CEF source evidence manifest changed');
type Claim={
  name:string;ordinal:number;category:string;startByte:number;endByte:number;
  rawValueSha256:string;decodedValueSha256:string;
};
type Case={
  id:string;privateFile:string;sourceSha256:string;sourceBytes:number;
  cefBodyStartByte:number;syslogPrefixSha256:string;syslogPrefixBytes:number;
  claimCount:number;claims:Claim[];
};
type Manifest={cases:Case[];sourceOnly:true;nativeVerified:false;
  authorityClass:string;originalUri:string};
const expected=JSON.parse(manifestBytes.toString('utf8')) as Manifest;
if(expected.cases.length!==2||expected.nativeVerified!==false||expected.sourceOnly!==true)
  throw Error('CEF publisher source scope/denominator mismatch');
const privateDir=path.join(os.homedir(),
  '.local/state/parserstudio-std9-publisher-cef-leef-20261018');
const browserNames:Record<string,string>={
  version:'cef_version',deviceVendor:'cef_device_vendor',
  deviceProduct:'cef_device_product',deviceVersion:'cef_device_version',
  deviceEventClassId:'cef_signature_id',name:'cef_name',severity:'cef_severity',
};
const report={
  scope:'PUBLISHER_WRITTEN_MANUAL_EXAMPLES_NOT_DEVICE_WIRE_OR_NATIVE',
  publishedEvents:2,expectedFields:20,
  tp:0,fp:0,fn:0,exactEvents:0,sourceByteDrift:0,
  pipelineExactRecords:0,sourceObserverDispositionCount:0,
  nativeVerified:false,fullEventAccuracy:'UNSCORABLE',
  vendorOperationalSamples:0,
  historicalSafetyRelabeled:false,
};
for(const fixture of expected.cases){
  const privatePath=path.join(privateDir,fixture.privateFile);
  if(!fs.existsSync(privatePath))
    throw Error('Private exact publisher example unavailable: UNSCORABLE');
  const original=fs.readFileSync(privatePath);
  if(sha(original)!==fixture.sourceSha256||original.length!==fixture.sourceBytes)
    throw Error('Pinned publisher-original CEF source byte SHA drift');
  const raw=new TextDecoder('utf8',{fatal:true}).decode(original);
  const prefix=original.subarray(0,fixture.syslogPrefixBytes);
  if(sha(prefix)!==fixture.syslogPrefixSha256||
     fixture.syslogPrefixBytes!==fixture.cefBodyStartByte)
    throw Error('Original publisher Syslog/CEF source boundary mismatch');
  const body=raw.slice(fixture.cefBodyStartByte);
  if(!body.startsWith('CEF:'))throw Error('Published source did not retain CEF token');
  const observed=arbitrateIndependentNonJson(raw);
  const browser=extractStructuredFamily(body,'cef');
  const pipeline=parseSecurityInput(raw);
  if(observed.disposition!=='REVIEW_ONLY_STRUCTURED_BODY'||
     observed.selectedBodyGrammar!=='cef'||observed.nativeVerified||
     observed.autoPromoted||!pipeline.ok||browser.errors.length)
    throw Error('Published CEF source was not conservatively parsed by all paths');
  report.sourceObserverDispositionCount++;
  if(pipeline.events.length!==1||pipeline.source_raw!==raw)
    throw Error('Published source has unexpected parser line-event boundary');
  const fullFields=pipeline.events[0]?.fields.body as Record<string,unknown>;
  if(!fullFields||Object.keys(fullFields).length!==fixture.claimCount)
    throw Error('Pipeline dropped or invented an example field');
  let correct=0;
  for(const claim of fixture.claims){
    const obs=observed.bodyClaims[claim.ordinal];
    const sourceSlice=original.subarray(claim.startByte,claim.endByte);
    const fieldName=browserNames[claim.name]??claim.name;
    const publisherOriginalMatching=sha(sourceSlice)===claim.rawValueSha256;
    const lexical=obs&&sha(obs.rawSpanValue)===claim.rawValueSha256;
    const value=obs&&sha(obs.value)===claim.decodedValueSha256;
    const name=obs?.name===claim.name;
    const interval=obs?.startByte===claim.startByte&&obs?.endByte===claim.endByte;
    const browserCorrect=typeof browser.fields[fieldName]==='string'&&
      sha(browser.fields[fieldName] as string)===claim.decodedValueSha256;
    const fullCorrect=typeof fullFields[fieldName]==='string'&&
      sha(fullFields[fieldName] as string)===claim.decodedValueSha256;
    if(obs&&new TextDecoder('utf8',{fatal:true}).decode(
      original.subarray(obs.startByte,obs.endByte))!==obs.rawSpanValue)
      report.sourceByteDrift++;
    if(publisherOriginalMatching&&lexical&&value&&name&&interval&&browserCorrect&&fullCorrect){
      correct++;report.tp++;
    }else report.fn++;
  }
  report.fp+=observed.bodyClaims.length-correct;
  if(correct===fixture.claimCount){
    report.exactEvents++;report.pipelineExactRecords++;
  }
}
console.log('STD9_PUBLISHER_CEF_SOURCE_SCORE '+JSON.stringify(report));
if(report.tp!==report.expectedFields||report.fp||report.fn||
  report.sourceByteDrift||report.exactEvents!==report.publishedEvents||
  report.pipelineExactRecords!==report.publishedEvents){
  process.exitCode=1;
}
