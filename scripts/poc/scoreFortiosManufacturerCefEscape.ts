/** Manufacturer-authored FortiOS raw-to-CEF example with an independently
 * documented \= escape. This is a one-field source-only reference, never
 * manufacturer device-capture, all-field FP or Stellar native certification.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import {arbitrateIndependentNonJson} from '../../src/poc/independentNonJsonStructural';
import {inspectDeclaredCefEscape,type DeclaredCefEscapeProfile}
 from '../../src/poc/declaredCefExtensionEscape';

const root=path.join(os.homedir(),'.local/state/parserstudio-fortios-cef-document-escape-20261017');
const PAGE='d4085e6f7363887a88cff469837828ecaebb6647722dbb5eef8cb82d90987a40';
const ORACLE='8817ce951365fa3d6291432e3080e8845c9b10dd548070b0d5035b0a8e574d86';
const hash=(buffer:Buffer|string)=>crypto.createHash('sha256').update(buffer).digest('hex');
if(hash(fs.readFileSync(path.join(root,'fortios-cef-doc-page.html')))!==PAGE)
 throw Error('Manufacturer author document byte identity mismatch');
const data=fs.readFileSync(path.join(root,'fortios-cef-author-escape-oracle.v1.json'));
if(hash(data)!==ORACLE)throw Error('Frozen independent author-expected CEF source oracle changed');
type Oracle={
 rawDiskExample:string;rawDiskSha256:string;
 receivedCefExample:string;receivedCefSha256:string;
 explicitlyAuthorMappedOriginalField:string;explicitlyAuthorMappedCefField:string;
 manufacturerAuthorExpectedDecodedValue:string;sourceWireLexeme:string;
 lexemeStartByte:number;lexemeEndByte:number;
 fieldNameStartByte:number;fieldNameEndByte:number;
};
const gold=JSON.parse(data.toString('utf8')) as Oracle;
const raw=gold.receivedCefExample;
if(hash(raw)!==gold.receivedCefSha256||
 hash(gold.rawDiskExample)!==gold.rawDiskSha256)
 throw Error('Independent manufacturer original source/hash mismatch');
const key=gold.explicitlyAuthorMappedCefField;
const wire=Buffer.from(raw,'utf8');
const documentContract:DeclaredCefEscapeProfile={
 framing:'INDEPENDENTLY_DOCUMENTED_SINGLE_CEF_RECORD',
 valueGrammar:'BACKSLASH_ESCAPES_EQUALS',
 sourceSha256:gold.receivedCefSha256,
 manufacturerDocumentSha256:PAGE,sourceFieldName:key,
};
const baseline=arbitrateIndependentNonJson(raw);
const candidate=inspectDeclaredCefEscape(raw,documentContract);
const unknown=inspectDeclaredCefEscape(raw);
const oldExact=baseline.bodyClaims.filter(x=>x.name===key&&
 x.value===gold.manufacturerAuthorExpectedDecodedValue&&
 x.startByte===gold.lexemeStartByte&&x.endByte===gold.lexemeEndByte).length;
const newExact=candidate.fields.filter(x=>x.sourceFieldName===key&&
 x.decodedValue===gold.manufacturerAuthorExpectedDecodedValue&&
 x.rawLexeme===gold.sourceWireLexeme&&
 x.keyStartByte===gold.fieldNameStartByte&&x.keyEndByte===gold.fieldNameEndByte&&
 x.valueStartByte===gold.lexemeStartByte&&x.valueEndByte===gold.lexemeEndByte).length;
const rawDrift=Number(candidate.raw!==raw||
 candidate.sourceBytes!==wire.length)+candidate.fields.reduce((n,x)=>n+
 Number(wire.subarray(x.valueStartByte,x.valueEndByte).toString('utf8')!==x.rawLexeme)+
 Number(wire.subarray(x.keyStartByte,x.keyEndByte).toString('utf8')!==x.sourceFieldName),0);
const output={
 scope:'MANUFACTURER_DOCUMENTED_CEF_RAW_DISK_VALUE_AND_ENCODED_FORWARDER_EXAMPLE',
 manufacturerDocumentSha256:PAGE,
 immutableOracleSha256:ORACLE,
 previousSourceExact:oldExact,
 qualifiedSourceExact:newExact,
 referenceFields:1,
 falseNegativesBefore:1-oldExact,
 falseNegativesAfter:1-newExact,
 ambiguousRawEscapesAutoDecoded:0,
 sourceUTF8Drift:rawDrift,
 unknownProfileAdditionalClaims:unknown.fields.length,
 nativeOrAutoPromotion:candidate.autoPromoted||candidate.nativeStellar!=='NOT_VERIFIED',
 disposition:candidate.disposition,
 maxBranches:candidate.branchAttempts,maxDepth:candidate.maxDepth,
 fullEventFP:'UNSCORABLE_ONE_PARTIAL_MANUFACTURER_REFERENCE',
 samePhysicalSourceAndForwarderPair:'NOT_VERIFIED_AUTHOR_EXAMPLES_ONLY',
 literalSourceAndExpectedValuePrinted:false,
 vendorFirmwareAllModes:'UNSCORABLE',
};
console.log('FORTIOS_MANUFACTURER_CEF_EQUALS_ESCAPE_SCORE '+JSON.stringify(output));
if(oldExact!==0||newExact!==1||rawDrift||
 unknown.fields.length||candidate.disposition!=='REVIEW_ONLY'||
 output.nativeOrAutoPromotion||candidate.branchAttempts>2||
 candidate.maxDepth>1)process.exitCode=1;
