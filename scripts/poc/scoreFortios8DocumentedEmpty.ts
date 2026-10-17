/** Manufacturer-authored FortiOS custom log examples, pre-frozen oracle.
 * The upstream document, not this candidate, defines '%' as empty after
 * explicit configuration. No auto/native or device-wire correctness is claimed.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {conservativeKvLocatedFields} from '../../src/poc/conservativeKvUtf8Span';
import {inspectDeclaredEmptyMarker,type EmptyMarkerProfile}
  from '../../src/poc/declaredEmptyMarker';

const base=path.join(os.homedir(),'.local/state/parserstudio-fortios8-empty-author-20261017');
const PAGE='b9ef7ca4e86f416415fa9c850fd738376f59a2808fa8f3ea289d3270a4d9bcd8';
const ORACLE='24779a777bcfad3d25293e480d82f7b10d61516b377144485ef92b3feaa726b1';
const sha=(value:Buffer|string)=>crypto.createHash('sha256').update(value).digest('hex');
if(sha(fs.readFileSync(path.join(base,'fortios8-custom-syslog-page.html')))!==PAGE)
 throw Error('Manufacturer-documented producer source changed');
const bytes=fs.readFileSync(path.join(base,'manufacturer-empty-source-oracle.v1.json'));
if(sha(bytes)!==ORACLE)throw Error('Frozen pre-candidate reference changed');
type Expected={name:string;state:'PRESENT_EMPTY_DOCUMENTED'|'PRESENT_NONEMPTY_LEXICAL';
 rawLexeme:string;valueStartByte:number;valueEndByte:number;
 nameStartByte:number;nameEndByte:number};
type Row={raw:string;rawSha256:string;expected:Expected[];manufacturerExampleIndex:number};
const rows=JSON.parse(bytes.toString('utf8')) as Row[];
const keys=['eve_type','eve_msg','eve_vdom','eve_level','eve_status','eve_profile'];
const result={
 manufacturer:'FORTIOS_8_0_DOCUMENTED_CUSTOM_MODE_ONLY',
 sourceDocSha256:PAGE,frozenOracleSha256:ORACLE,
 originalExamples:0,referenceFields:0,referenceEmptyFields:0,
 baselineLexicalExact:0,candidateLexicalExact:0,
 baselineDocumentedEmptyTP:0,candidateDocumentedEmptyTP:0,
 documentedEmptyFN:0,wrongDocumentedEmptyClaims:0,
 nonEmptyLexicalExact:0,abstentions:0,
 sourceByteDrift:0,unknownWithoutProfileClaims:0,
 unsafeAutoNativePromotions:0,maxBranches:0,maxDepth:0,
 originalValuesPrinted:false,
};
const matches=(a:{name:string;sourceLexeme:string;valueStartByte:number;valueEndByte:number;
nameStartByte:number;nameEndByte:number},b:Expected)=>a.name===b.name&&
 a.sourceLexeme===b.rawLexeme&&a.valueStartByte===b.valueStartByte&&
 a.valueEndByte===b.valueEndByte&&a.nameStartByte===b.nameStartByte&&
 a.nameEndByte===b.nameEndByte;
for(const row of rows){
 result.originalExamples++;
 if(sha(row.raw)!==row.rawSha256)throw Error('Original manufacturer example drift');
 const profile:EmptyMarkerProfile={
  framing:'INDEPENDENTLY_DOCUMENTED_RFC3164_KV_CUSTOM_FORMAT',
  valueContract:'EXPLICIT_UNQUOTED_EMPTY_MARKER',
  sourceSha256:row.rawSha256,manufacturerDocSha256:PAGE,
  emptyMarker:'%',declaredKeys:keys,
 };
 // Cohort eligibility is based only on a pinned manufacturer HTML <pre>
 // excerpt and its independently documented custom profile, NOT truth labels.
 const before=conservativeKvLocatedFields(row.raw);
 const candidate=inspectDeclaredEmptyMarker(row.raw,profile);
 const noProfile=inspectDeclaredEmptyMarker(row.raw);
 result.unknownWithoutProfileClaims+=noProfile.fields.length+
  Number(noProfile.disposition==='REVIEW_ONLY');
 result.abstentions+=Number(candidate.disposition!=='REVIEW_ONLY');
 result.unsafeAutoNativePromotions+=Number(candidate.autoPromoted||
  candidate.nativeStellar!=='NOT_VERIFIED');
 result.sourceByteDrift+=Number(candidate.raw!==row.raw||
  candidate.sourceBytes!==Buffer.byteLength(row.raw,'utf8'));
 result.maxBranches=Math.max(result.maxBranches,candidate.branchAttempts);
 result.maxDepth=Math.max(result.maxDepth,candidate.maxDepth);
 const original=Buffer.from(row.raw,'utf8');
 for(const source of candidate.fields){
  result.sourceByteDrift+=Number(
   original.subarray(source.valueStartByte,source.valueEndByte).toString('utf8')!==source.sourceLexeme);
  result.sourceByteDrift+=Number(
   original.subarray(source.nameStartByte,source.nameEndByte).toString('utf8')!==source.name);
  if(source.state==='PRESENT_EMPTY_DOCUMENTED'&&
    !row.expected.some(x=>matches(source,x)&&x.state==='PRESENT_EMPTY_DOCUMENTED'))
    result.wrongDocumentedEmptyClaims++;
 }
 for(const expected of row.expected){
  result.referenceFields++;
  const lexical=before?.spans.some(x=>x.name===expected.name&&
    x.valueStart===expected.valueStartByte&&x.valueEnd===expected.valueEndByte&&
    x.nameStart===expected.nameStartByte&&x.nameEnd===expected.nameEndByte&&
    original.subarray(x.valueStart,x.valueEnd).toString('utf8')===expected.rawLexeme)??false;
  const newClaim=candidate.fields.find(x=>matches(x,expected));
  result.baselineLexicalExact+=Number(lexical);
  result.candidateLexicalExact+=Number(!!newClaim);
  if(expected.state==='PRESENT_EMPTY_DOCUMENTED'){
   result.referenceEmptyFields++;
   // Baseline lexer supplies a literal percent, without a source
   // empty-state conclusion. This is zero verified empty-state TP.
   result.candidateDocumentedEmptyTP+=Number(
     newClaim?.state==='PRESENT_EMPTY_DOCUMENTED');
   result.documentedEmptyFN+=Number(
     newClaim?.state!=='PRESENT_EMPTY_DOCUMENTED');
  }else result.nonEmptyLexicalExact+=Number(
    newClaim?.state==='PRESENT_NONEMPTY_LEXICAL');
 }
}
console.log('FORTIOS8_MANUFACTURER_DECLARED_EMPTY_SOURCE '+JSON.stringify({
 ...result,
 manufacturerMeaningScope:'DOCUMENTED_CUSTOM_SYMBOLED_EMPTY_NOT_FIRMWARE_WIRE_VERIFIED',
 decodedEmptyStringVsNull:'UNSCORABLE',
 manufacturerEscapes:'NOT_CERTIFIED',
 multiHopSyslog:'UNSCORABLE',
 fullEventNative:'NOT_VERIFIED',
 sourceFP:'SCOPED_TO_12_DOCUMENTED_EXPECTATIONS_ONLY',
 historical197:'SAFETY_ONLY',
}));
if(result.originalExamples!==2||result.referenceFields!==12||
 result.referenceEmptyFields!==3||result.baselineLexicalExact!==12||
 result.candidateLexicalExact!==12||result.candidateDocumentedEmptyTP!==3||
 result.documentedEmptyFN!==0||result.nonEmptyLexicalExact!==9||
 result.wrongDocumentedEmptyClaims!==0||result.abstentions!==0||
 result.sourceByteDrift!==0||result.unsafeAutoNativePromotions!==0||
 result.unknownWithoutProfileClaims!==0||
 result.maxBranches>2||result.maxDepth>1)process.exitCode=1;
