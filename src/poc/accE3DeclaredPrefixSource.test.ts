import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {describe,expect,it} from 'vitest';
import oracle from '../../scripts/poc/accE3DeclaredPrefixOracle.pinned.json';
import {inspectDeclaredPrefixKvSource} from './accE3DeclaredPrefixSource';

const source=(hex:string)=>Uint8Array.from(Buffer.from(hex,'hex'));
const sha=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');

describe('ACC-E3 externally declared, hash-pinned source prefix boundary',()=>{
  it('pins an independently authored oracle before implementation',()=>{
    const pinned=readFileSync('scripts/poc/accE3DeclaredPrefixOracle.pinned.json');
    expect(sha(pinned)).toBe('ef6268f4c9f9c3126731d308d5551e9aa85e1b783ef90b02bf04c7765f2f76ff');
    expect(oracle.authority).toBe('INDEPENDENT_STANDARDS_AUTHORED_SYNTHETIC_ONLY');
    expect(oracle.frozenBeforeParserImplementation).toBe(true);
    expect(oracle.positiveCaseCount).toBe(10);
    expect(oracle.negativeCaseCount).toBe(19);
  });

  for(const entry of oracle.cases){
    it('replays the exact independently frozen source contract: '+entry.id,()=>{
      const input={
        sourceBytes:source(entry.sourceHex),sourceSha256:entry.sourceSha256,
        recordFraming:entry.recordFraming,
        declaredBodyFormat:entry.declaredBodyFormat,
        declaredPrefixEndByte:entry.prefixEndByte,
        pinnedPrefixSha256:entry.prefixSha256,
      };
      const result=inspectDeclaredPrefixKvSource(input);
      expect(result.disposition).toBe(entry.expectedDisposition);
      expect(result.autoPromoted).toBe(false);
      expect(result.originalDeviceIdentity).toBe('NOT_ATTESTED');
      expect(result.transportPeerAuthentication).toBe('NOT_VERIFIED');
      expect(result.nativeTarget).toBe('NOT_VERIFIED');
      expect(result.sourceComplete).toBe(false);
      expect(result.manufacturerSemantics).toBe('NOT_CERTIFIED');
      expect('raw' in result).toBe(false);
      if(entry.category!=='positive'){
        expect(result.fields).toEqual([]);
        return;
      }
      expect(result.prefix).toEqual({startByte:0,endByte:entry.prefixEndByte});
      expect(result.fields).toHaveLength(entry.expectedFields.length);
      for(let i=0;i<entry.expectedFields.length;i++){
        const actual=result.fields[i]!;
        const independent=entry.expectedFields[i]!;
        expect(actual).toEqual(independent);
        const b=input.sourceBytes;
        expect(Buffer.from(b.subarray(actual.valueStartByte,actual.valueEndByte)).toString('utf8'))
          .toBe(independent.sourceValueLexeme);
      }
    });
  }

  it('never treats a mere syntactic match as an authenticated physical source',()=>{
    const sample=oracle.cases.find(x=>x.id==='bsd_name_and_clock')!;
    const result=inspectDeclaredPrefixKvSource({
      sourceBytes:source(sample.sourceHex),
      sourceSha256:sample.sourceSha256,
      recordFraming:'CONFIRMED_SINGLE_SOURCE_RECORD',
      declaredBodyFormat:'space_kv',
      declaredPrefixEndByte:sample.prefixEndByte,
      pinnedPrefixSha256:sample.prefixSha256,
    });
    expect(result.disposition).toBe('REVIEW_ONLY_DECLARED_PREFIX');
    expect(result.independentOracleCertified).toBe(false);
    expect(result.canDecodeVendorEscapes).toBe(false);
    expect(result.sourceComplete).toBe(false);
  });
});
