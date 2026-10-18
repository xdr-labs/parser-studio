/**
 * Private dev-atlas-only publisher-documentary source replay.
 * The raw examples and independent expected values are NOT in Git or CI.
 * Results are not physical-device/native source accuracy claims.
 */
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {join} from 'node:path';
import {inspectDeclaredPrefixKvSource} from '../../src/poc/accE3DeclaredPrefixSource';

const sha=(value:Uint8Array)=>
  createHash('sha256').update(value).digest('hex');
const state=join(homedir(),'.local/state');
const evidenceRoot=join(state,'parserstudio-acc-e3-declared-prefix-evidence-20261018');
const evidenceBytes=readFileSync(join(evidenceRoot,'publisher-prefix-evidence-manifest.json'));
if(sha(evidenceBytes)!=='c10c409aa49338680953fe429a70a41a3bbf93f7a9e47d6c59464fe174e4c0ba')
  throw new Error('Pinned prefix evidence changed');
const manifest=JSON.parse(evidenceBytes.toString('utf8')) as {
  preExistingSophosOracleSha256:string;
  preExistingFortinetOracleSha256:string;
  evaluatedSourceItems:Array<{
    id:string;publisher:string;sourceSha256:string;sourceBytes:number;
    prefixEndByte:number;prefixSha256:string;expectedClaims:number;
  }>;
};
const sophosRoot=join(state,'parserstudio-acc-e3-sophos-publisher-oracle-20261018');
const fortinetRoot=join(state,'parserstudio-acc-e1-fortinet-publisher-extended-20261018');
const sophosOracleBytes=readFileSync(join(sophosRoot,'independently_frozen_expanded_source_oracle.json'));
const fortinetOracleBytes=readFileSync(join(fortinetRoot,'independent-publisher-displayed-source-oracle.json'));
if(sha(sophosOracleBytes)!==manifest.preExistingSophosOracleSha256||
   sha(fortinetOracleBytes)!==manifest.preExistingFortinetOracleSha256)
  throw new Error('Previously independent field oracle changed');
const sophosOracle=JSON.parse(sophosOracleBytes.toString('utf8')) as {
  samples:Array<{id:string;expected:{disposition:string;claims:Array<{
    name:string;rawLexeme:string;lexicalValue:string;
    nameStartByte:number;nameEndByte:number;valueStartByte:number;valueEndByte:number;
  }>}}>;
};
const fortinetOracle=JSON.parse(fortinetOracleBytes.toString('utf8')) as {
  sourceClaims:Array<{name:string;sourceLexeme:string;lexicalDecoded:string;
    nameStartByte:number;nameEndByte:number;valueStartByte:number;valueEndByte:number}>;
};
const sophos=JSON.parse(readFileSync(join(sophosRoot,'sophos-21.5-doc-samples-expanded.json'),'utf8')) as {
  examples:Array<{id:string;raw:string}>;
};
const fortinet=JSON.parse(readFileSync(join(fortinetRoot,'official-extended-source-display.json'),'utf8')) as {
  publisherDisplayedRaw:string;
};
const rows:Array<{id:string;publisher:string;qualifiedFields:number;exactFields:number;
  disposition:string;canAutoPromote:boolean;originalDeviceAttested:false}>=[];
for(const evidence of manifest.evaluatedSourceItems){
  const sophosExample=sophos.examples.find(x=>x.id===evidence.id);
  const raw=evidence.publisher==='FORTINET_DOCUMENTATION'?
    fortinet.publisherDisplayedRaw:sophosExample?.raw;
  if(!raw)throw new Error('Publisher source not frozen: '+evidence.id);
  const actualBytes=new TextEncoder().encode(raw);
  if(sha(actualBytes)!==evidence.sourceSha256||actualBytes.length!==evidence.sourceBytes)
    throw new Error('Published source identity changed: '+evidence.id);
  const result=inspectDeclaredPrefixKvSource({
    sourceBytes:actualBytes,sourceSha256:evidence.sourceSha256,
    recordFraming:'CONFIRMED_SINGLE_SOURCE_RECORD',declaredBodyFormat:'space_kv',
    declaredPrefixEndByte:evidence.prefixEndByte,
    pinnedPrefixSha256:evidence.prefixSha256,
  });
  const sourceFields=evidence.publisher==='FORTINET_DOCUMENTATION'?
    fortinetOracle.sourceClaims.map(x=>({
      name:x.name,rawLexeme:x.sourceLexeme,lexicalValue:x.lexicalDecoded,
      nameStartByte:x.nameStartByte,nameEndByte:x.nameEndByte,
      valueStartByte:x.valueStartByte,valueEndByte:x.valueEndByte,
    })):(sophosOracle.samples.find(x=>x.id===evidence.id)?.expected.claims??[]);
  if(result.disposition!=='REVIEW_ONLY_DECLARED_PREFIX'||!result.prefix||
     result.prefix.endByte!==evidence.prefixEndByte||
     result.fields.length!==evidence.expectedClaims||
     result.fields.length!==sourceFields.length||
     result.autoPromoted||result.independentOracleCertified||
     result.originalDeviceIdentity!=='NOT_ATTESTED'||
     result.sourceComplete||result.nativeTarget!=='NOT_VERIFIED')
    throw new Error('Review gate drift: '+evidence.id);
  let matched=0;
  for(const [index,field] of result.fields.entries()){
    const expectation=sourceFields[index];
    if(!expectation||expectation.name!==field.name||
       expectation.rawLexeme!==field.sourceValueLexeme||
       expectation.lexicalValue!==field.decodedSourceValue||
       expectation.nameStartByte!==field.nameStartByte||
       expectation.nameEndByte!==field.nameEndByte||
       expectation.valueStartByte!==field.valueStartByte||
       expectation.valueEndByte!==field.valueEndByte)
      throw new Error('Original source lexical comparison mismatch: '+evidence.id);
    matched++;
  }
  rows.push({id:evidence.id,publisher:evidence.publisher,
    qualifiedFields:sourceFields.length,exactFields:matched,
    disposition:result.disposition,canAutoPromote:result.autoPromoted,
    originalDeviceAttested:false});
}
if(rows.length!==9||rows.reduce((n,x)=>n+x.exactFields,0)!==283)
  throw new Error('Unexpected documentary evidence denominator');
process.stdout.write(JSON.stringify({
  classification:'POST_HOC_PUBLISHER_DOCUMENTARY_SOURCE_ONLY',
  priorOracleIndependentlyFrozen:true,
  declaredPrefixNotSourceAuthentication:true,
  exactDocs:rows.length,
  exactFieldNameValueOriginalUTF8Positions:rows.reduce((n,x)=>n+x.exactFields,0),
  eligibleManufacturerDeviceWireEvents:0,
  rows,
},null,2)+'\n');
