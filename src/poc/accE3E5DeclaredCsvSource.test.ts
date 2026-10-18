import {createHash} from 'node:crypto';
import {describe,expect,it} from 'vitest';
import frozen from '../../scripts/poc/accE3E5DeclaredCsvOracle.pinned.json';
import {inspectDeclaredCsvSource} from './accE3E5DeclaredCsvSource';

const encoder=new TextEncoder();
const hex=(data:Uint8Array|string)=>
  createHash('sha256').update(data).digest('hex');

type Case=(typeof frozen.cases)[number];
const makeInput=(c:Case)=>{
  let source=encoder.encode(c.source);
  let sourceSha256=c.source_sha256;
  let csvStartByte=c.start_byte;
  let csvEndByte=c.end_byte;
  let csvSliceSha256=c.slice_sha256;
  let orderedNames=[...c.ordered_names];
  let orderedNamesSha256=c.ordered_names_sha256;
  let recordFraming=c.record_framing;
  let declaredFormat=c.declared_format;
  let schemaProvenance=c.schema_provenance;
  switch(c.mutate){
    case 'no_framing': recordFraming='UNCONFIRMED'; break;
    case 'bad_source_sha': sourceSha256='0'.repeat(64); break;
    case 'bad_slice_sha': csvSliceSha256='0'.repeat(64); break;
    case 'bad_schema_sha': orderedNamesSha256='0'.repeat(64); break;
    case 'negative_start': csvStartByte=-1; break;
    case 'mid_utf8': csvStartByte-=2; break;
    case 'end_out_of_range': csvEndByte=source.length+1; break;
    case 'empty_slice': csvEndByte=csvStartByte; break;
    case 'wrong_format': declaredFormat='unverified_csv'; break;
    case 'wrong_provenance': schemaProvenance='DEVICE_CERTIFIED'; break;
    case 'oversized_source':
      source=encoder.encode('a'.repeat(65537)); sourceSha256=hex(source); break;
    case 'oversized_slice':
      source=encoder.encode('a'.repeat(16385));
      sourceSha256=hex(source); csvStartByte=0; csvEndByte=source.length;
      csvSliceSha256=hex(source); break;
    case 'oversized_schema':
      orderedNames=Array.from({length:129},(_,i)=>'field_'+i);
      orderedNamesSha256=hex(JSON.stringify(orderedNames)); break;
    case 'invalid_utf8':
      source=Uint8Array.from([...source,255]); sourceSha256=hex(source); break;
  }
  return {sourceBytes:source,sourceSha256,csvStartByte,csvEndByte,
    csvSliceSha256,orderedNames,orderedNamesSha256,
    recordFraming,declaredFormat,schemaProvenance};
};

describe('ACC-E3/E5 pinned external CSV schema and absolute original-source bytes',()=>{
  it('uses frozen Python-authored synthetic cases rather than TS-generated expected spans',()=>{
    expect(frozen.schema_version).toBe('independent_synthetic_source_v1');
    expect(frozen.evidence).toBe('AUTHOR_SYNTHETIC_NOT_DEVICE_OR_NATIVE');
    expect(frozen.cases).toHaveLength(37);
    expect(frozen.cases.filter(c=>c.expected.length)).toHaveLength(13);
    expect(frozen.cases.flatMap(c=>c.expected)).toHaveLength(42);
  });

  it.each(frozen.cases)('$case_id — respects independent outcome and original UTF-8 field spans',(c)=>{
    const source=makeInput(c);
    const result=inspectDeclaredCsvSource(source);
    expect(result.disposition).toBe(c.expected_disposition);
    expect(result.autoPromoted).toBe(false);
    expect(result.sourceComplete).toBe(false);
    expect(result.canAutoPromote).toBe(false);
    expect(result.independentOracleCertified).toBe(false);
    expect(result.manufacturerSemantics).toBe('NOT_CERTIFIED');
    expect(result.transportPeerAuthentication).toBe('NOT_VERIFIED');
    expect(result.originalDeviceIdentity).toBe('NOT_ATTESTED');
    expect(result.nativeVerified).toBe(false);
    if(c.expected.length){
      expect(result.sourceBytes).toBe(source.sourceBytes.length);
      expect(result.unreviewedPrefixBytes).toBe(c.start_byte);
      expect(result.unreviewedSuffixBytes).toBe(source.sourceBytes.length-c.end_byte);
      expect(result.fields).toHaveLength(c.expected.length);
      for(const [i,field] of result.fields.entries()){
        const expected=c.expected[i]!;
        expect([field.ordinal,field.name,field.sourceValue,
          field.sourceValueLexeme,field.startByte,field.endByte]).toEqual([
          expected.ordinal,expected.name,expected.source_value,
          expected.source_value_lexeme,expected.start_byte,expected.end_byte,
        ]);
        expect(new TextDecoder('utf-8',{fatal:true})
          .decode(source.sourceBytes.subarray(field.startByte,field.endByte)))
          .toBe(field.sourceValueLexeme);
        expect(field.nameStartByte).toBeNull();
        expect(field.valueType).toBe('UNVERIFIED_SOURCE_STRING');
      }
    }else{
      expect(result.fields).toEqual([]);
    }
  });

  it('never treats an externally specified column name as a physical original header span',()=>{
    const result=inspectDeclaredCsvSource(makeInput(frozen.cases[0]!));
    expect(result.disposition).toBe('REVIEW_ONLY_EXTERNAL_CSV_SCHEMA');
    expect(result.fields.every(field=>field.nameStartByte===null)).toBe(true);
    expect(result.schemaBasis).toBe('EXTERNALLY_DECLARED_NOT_SOURCE_HEADER');
    expect(result.sourceComplete).toBe(false);
  });
});
