import {createHash} from 'node:crypto';
import {readFileSync} from 'node:fs';
import {describe,expect,it} from 'vitest';
import {reviewPairedRelaySourceBytes} from './accE2RelayPairByteFidelity';
import oracle from '../../scripts/poc/accE2RelayPairByteOracle.pinned.json';

const sha256=(bytes:Uint8Array)=>createHash('sha256').update(bytes).digest('hex');
const buffer=(hex:string)=>Uint8Array.from(Buffer.from(hex,'hex'));
const fixtureBytes=readFileSync('scripts/poc/accE2RelayPairByteOracle.pinned.json');

describe('ACC-E2 generic upstream/collector byte-fidelity observer',()=>{
  it('pins the independently authored synthetic oracle before implementation',()=>{
    expect(sha256(fixtureBytes)).toBe(
      'dae28a946cd0f0f951ca60a45734f1772e7a8d297ce92a1eefd08d1ab5054830');
    expect(oracle.frozenBeforeCandidateImplementation).toBe(true);
    expect(oracle.provenance).toBe('INDEPENDENT_STANDARDS_AUTHORED_SYNTHETIC_NOT_DEVICE');
  });

  for(const row of oracle.pairs){
    it('classifies byte-only evidence without semantic promotion: '+row.id,()=>{
      const input={
        upstreamBytes:buffer(row.upstreamHex),
        collectorBytes:buffer(row.collectorHex),
        upstreamSha256:row.upstreamSha256,
        collectorSha256:row.collectorSha256,
      };
      const result=reviewPairedRelaySourceBytes(input);
      expect(result.disposition).toBe(row.expectedDisposition);
      expect(result.commonPrefixBytes).toBe(row.expectedCommonPrefixBytes);
      expect(result.firstDifferenceByte).toBe(row.expectedFirstDifferenceByte);
      expect(result.lostUpstreamTail).toEqual(
        row.expectedLostUpstreamTail===null?null:{
          startByte:row.expectedLostUpstreamTail[0],
          endByte:row.expectedLostUpstreamTail[1],
        });
      expect(result.addedCollectorTail).toEqual(
        row.expectedAddedCollectorTail===null?null:{
          startByte:row.expectedAddedCollectorTail[0],
          endByte:row.expectedAddedCollectorTail[1],
        });
      expect(result.upstreamBytes).toBe(input.upstreamBytes.length);
      expect(result.collectorBytes).toBe(input.collectorBytes.length);
      expect(result.originalDeviceIdentity).toBe('NOT_ATTESTED');
      expect(result.transportPeerAuthentication).toBe('NOT_VERIFIED');
      expect(result.eventClockOrdering).toBe('UNSCORABLE');
      expect(result.sourceComplete).toBe(false);
      expect(result.nativeVerified).toBe(false);
      expect(result.canAutoPromote).toBe(false);
      expect('raw' in result).toBe(false);
    });
  }

  it('rejects unpinned, mismatched, empty and oversized source stages',()=>{
    const a=buffer('616263'),b=buffer('616264');
    const complete={upstreamBytes:a,upstreamSha256:sha256(a),
      collectorBytes:b,collectorSha256:sha256(b)};
    for(const altered of [
      {...complete,collectorSha256:'0'.repeat(64)},
      {...complete,upstreamSha256:'0'.repeat(64)},
      {...complete,upstreamSha256:'NOT_A_HASH'},
      {...complete,collectorSha256:''},
      {...complete,collectorBytes:new Uint8Array()},
      {...complete,upstreamBytes:new Uint8Array()},
      {...complete,collectorBytes:new Uint8Array(1024*1024+1)},
    ]){
      const result=reviewPairedRelaySourceBytes(altered);
      expect(result.disposition).toBe('ABSTAIN_UNSAFE_OR_UNPINNED_BYTES');
      expect(result.canAutoPromote).toBe(false);
      expect(result.commonPrefixBytes).toBe(null);
    }
  });

  it('requires upstream evidence before comparing, even for fully pinned receiver bytes',()=>{
    const collectorBytes=buffer('616263');
    const result=reviewPairedRelaySourceBytes({
      collectorBytes,collectorSha256:sha256(collectorBytes),
    });
    expect(result.disposition).toBe('REVIEW_ONLY_NO_UPSTREAM_PAIR');
    expect(result.upstreamBytes).toBe(null);
    expect(result.commonPrefixBytes).toBe(null);
    expect(result.canAutoPromote).toBe(false);
  });
});
