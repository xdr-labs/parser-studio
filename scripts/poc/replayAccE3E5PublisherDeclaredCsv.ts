/** Read-only private documentary source/oracle comparison.
 *
 * The upstream HTML is publisher-authored documentation, NOT device-wire
 * or collector packet capture. PAN 2014 examples have only positional
 * labels until their exact historical firmware schema is independently fixed.
 * No producer/native accuracy promotion, payload output, or third-party egress.
 */
import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {homedir} from 'node:os';
import {join} from 'node:path';
import {inspectDeclaredCsvSource} from '../../src/poc/accE3E5DeclaredCsvSource';

const sha=(bytes:Uint8Array|string)=>
  createHash('sha256').update(bytes).digest('hex');
const base=join(homedir(),'.local/state',
  'parserstudio-acc-e3-e5-declared-csv-source-20261018');
const raw=readFileSync(join(base,'publisher-display-csv-oracle.frozen.json'));
const FROZEN_SHA='17a28a81ca4af6402067a0407fe05d17d3890c5e6a256b6296642fbadd865da7';
if(sha(raw)!==FROZEN_SHA)throw Error('Independent manufacturer document Oracle hash changed');
interface TruthField{
  ordinal:number;name:string;lexical:string;value:string;
  start_byte:number;end_byte:number;
}
interface SourceRecord{
  id:string;original_displayed_text:string;source_sha256:string;
  source_bytes:number;body_start_byte:number;body_end_byte:number;
  body_sha256:string;schema_names:string[];schema_mode:string;
  fields:TruthField[];
}
const oracle=JSON.parse(raw.toString('utf8')) as {schema_version:string;
  records:SourceRecord[]};
if(oracle.schema_version!=='independent_publisher_displayed_csv_v1'||
   oracle.records.length!==3)throw Error('Unexpected independent Oracle population');
const results:object[]=[];
let total=0,namedPublisher=0,ordinalOnly=0;
for(const record of oracle.records){
  const bytes=Buffer.from(record.original_displayed_text,'utf8');
  if(sha(bytes)!==record.source_sha256||bytes.length!==record.source_bytes||
     sha(bytes.subarray(record.body_start_byte,record.body_end_byte))!==record.body_sha256)
    throw Error('Original publisher-displayed message hash or bound changed: '+record.id);
  const provenance=record.schema_mode==='PUBLISHER_DOCUMENTED_ORDER'?
    'PUBLISHER_DOCUMENTED_ORDER':'USER_DECLARED_ORDER';
  const review=inspectDeclaredCsvSource({
    sourceBytes:bytes,sourceSha256:record.source_sha256,
    csvStartByte:record.body_start_byte,csvEndByte:record.body_end_byte,
    csvSliceSha256:record.body_sha256,
    orderedNames:record.schema_names,
    orderedNamesSha256:sha(JSON.stringify(record.schema_names)),
    recordFraming:'EXPLICIT_SINGLE_DISPLAYED_RECORD',
    declaredFormat:'rfc4180_comma_csv',
    schemaProvenance:provenance,
  });
  if(review.disposition!=='REVIEW_ONLY_EXTERNAL_CSV_SCHEMA'||
     review.fields.length!==record.fields.length||
     review.unreviewedPrefixBytes!==record.body_start_byte||
     review.unreviewedSuffixBytes!==record.source_bytes-record.body_end_byte||
     review.canAutoPromote||review.sourceComplete||review.nativeVerified||
     review.manufacturerSemantics!=='NOT_CERTIFIED')
    throw Error('Expected source-only review and non-promotion invariant: '+record.id);
  for(const [i,field] of review.fields.entries()){
    const expected=record.fields[i];
    if(!expected||field.name!==expected.name||field.ordinal!==expected.ordinal||
       field.sourceValue!==expected.value||
       field.sourceValueLexeme!==expected.lexical||
       field.startByte!==expected.start_byte||field.endByte!==expected.end_byte||
       field.nameStartByte!==null||field.valueType!=='UNVERIFIED_SOURCE_STRING')
      throw Error('Independent source lexical/name/UTF8 mismatch at ordinal '+i+
        ' of '+record.id);
    const replay=bytes.subarray(field.startByte,field.endByte).toString('utf8');
    if(replay!==expected.lexical)throw Error('Original UTF-8 replay mismatch');
  }
  total+=review.fields.length;
  if(provenance==='PUBLISHER_DOCUMENTED_ORDER')namedPublisher+=review.fields.length;
  else ordinalOnly+=review.fields.length;
  results.push({id:record.id,sourceBytes:bytes.length,
    explicitlyUnreviewedPrefixBytes:record.body_start_byte,
    sourceCellsExactlyMatched:review.fields.length,
    schemaEvidence:provenance,sourceComplete:false,
    deviceWireAccuracy:'UNSCORABLE'});
}
process.stdout.write(JSON.stringify({
  evidence:'MANUFACTURER_PUBLISHED_DOCUMENTARY_TEXT_NOT_PRODUCER_WIRE',
  independentOracleSha256:FROZEN_SHA,
  examples:oracle.records.length,sourceCellsExact:total,
  publisherDocumentedNameAndLexicalByteMatches:namedPublisher,
  positionalOnlySyntheticColumnLabels:ordinalOnly,
  manufacturerDeviceWireEligibleEvents:0,
  nativeRuntimeVerified:false,allAutoPromotion:false,
  records:results,
},null,2)+'\n');
