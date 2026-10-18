import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {describe,expect,it} from 'vitest';
import oracle from '../../scripts/poc/accE5PartialColonOracle.pinned.json';
import {inspectBoundedColonLabels} from './accE5PartialColonSource';

const bytes=(hex:string)=>Uint8Array.from(Buffer.from(hex,'hex'));
const sha=(b:Uint8Array)=>createHash('sha256').update(b).digest('hex');
describe('ACC-E5 generic source-only partially bounded label: value evidence',()=>{
  it('requires the independent, pre-candidate authored fixture fingerprint',()=>{
    expect(sha(readFileSync('scripts/poc/accE5PartialColonOracle.pinned.json')))
      .toBe('6f0e97d948ea0b04dc7609e0cbbb64a816bd2d8ff8aa1c38c7af1700689e4a94');
    expect(oracle.type).toBe('INDEPENDENT_SYNTHETIC_SOURCE_ONLY_NOT_DEVICE');
    expect(oracle.frozenBeforeCandidate).toBe(true);
    expect(oracle.positive).toBe(10);
    expect(oracle.negative).toBe(24);
  });
  for(const row of oracle.cases){
    it('compares exact authored key/value/UTF-8 intervals: '+row.id,()=>{
      const src=bytes(row.fullSourceHex);
      const result=inspectBoundedColonLabels({
        sourceBytes:src,
        sourceSha256:row.sourceSha256,
        analysisScope:row.scope,
        boundedStartByte:row.declaredStartByte,
        boundedEndByte:row.declaredEndByte,
        boundedSliceSha256:row.sliceSha256,
      });
      expect(result.disposition).toBe(row.expectedDisposition);
      expect(result.sourceComplete).toBe(false);
      expect(result.independentOracleCertified).toBe(false);
      expect(result.nativeVerified).toBe(false);
      expect(result.canAutoPromote).toBe(false);
      expect(result.manufacturerSemantics).toBe('NOT_CERTIFIED');
      expect(result.originalDeviceIdentity).toBe('NOT_ATTESTED');
      expect(result.transportPeerAuthentication).toBe('NOT_VERIFIED');
      expect('sourceRaw' in result).toBe(false);
      if(row.kind==='invalid'){
        expect(result.fields).toEqual([]);
        return;
      }
      expect(result.selectedBodyRange).toEqual({
        startByte:row.declaredStartByte,endByte:row.declaredEndByte,
      });
      expect(result.fields).toEqual(row.expectedFields);
      expect(result.unreviewedSuffixBytes).toBe(row.expectedResidualSuffixBytes);
      for(const claim of result.fields){
        expect(Buffer.from(src.subarray(claim.valueStartByte,claim.valueEndByte)).toString('utf8'))
          .toBe(claim.rawLexeme);
      }
    });
  }
  it('does not collapse repeated same-name source occurrences into one field',()=>{
    const q=oracle.cases.find(x=>x.id==='ordered_duplicate_labels')!;
    const found=inspectBoundedColonLabels({
      sourceBytes:bytes(q.fullSourceHex),sourceSha256:q.sourceSha256,
      analysisScope:q.scope,
      boundedStartByte:q.declaredStartByte,boundedEndByte:q.declaredEndByte,
      boundedSliceSha256:q.sliceSha256,
    });
    expect(found.fields.map(f=>[f.name,f.occurrence])).toEqual([
      ['User',0],['User',1],['Outcome',0],
    ]);
    expect(found.sourceComplete).toBe(false);
  });
});
