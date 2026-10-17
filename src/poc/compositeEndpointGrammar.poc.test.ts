import {describe,expect,it} from 'vitest';
import {scanKeyValues,scanPrefixedKeyValues} from './losslessLexer';
import {parseCompositeIpPortInterface,extractCompositeFromSource,
  reviewPinnedCompositeEndpoint} from './compositeEndpointGrammar';

describe('lossless generic composite network endpoint component grammar',()=>{
  it('splits exact IPv4:port:interface with original multi-byte source spans',()=>{
    const raw='💡 src=192.0.2.10:49196:X0 action=allow';
    const token=scanPrefixedKeyValues(raw,0)!;
    const found=extractCompositeFromSource(raw,token.fields[0]!);
    expect(found?.parts.map(part=>[part.role,part.value])).toEqual([
      ['ipv4','192.0.2.10'],['port','49196'],['interface','X0'],
    ]);
    expect(found?.parts[0]!.sourceSpan.startByte).toBeGreaterThan(
      found!.parts[0]!.sourceSpan.start);
    for(const part of found!.parts){
      expect(raw.slice(part.sourceSpan.start,part.sourceSpan.end)).toBe(part.value);
      expect(new TextEncoder().encode(raw.slice(0,part.sourceSpan.start)).length)
        .toBe(part.sourceSpan.startByte);
    }
  });

  it('keeps documented optional resolved name as an additional sourced component',()=>{
    const found=parseCompositeIpPortInterface(
      '203.0.113.4:443:X1:host.example.org');
    expect(found?.parts.map(part=>part.role)).toEqual([
      'ipv4','port','interface','resolvedHost',
    ]);
    expect(found?.parts[3]?.value).toBe('host.example.org');
  });

  it('does not interpret malformed IPs, ports, ambiguous IPv6, colon drift or unsafe interfaces',()=>{
    const invalid=[
      '999.1.1.1:80:X0','192.0.2.1:65536:X0','192.0.2.1:-1:X0',
      '192.0.2.1:08:X0','192.0.2.1:80:',
      '2001:db8::1:443:X0','192.0.2.1:443:X0:host:extra',
      '192.0.2.1:443:../../root','192.0.2.1:443:X0/../../root',
      '192.0.2.1:443:X0:bad host',
      '192.0.2.1:443:X0:bad..example', '192.0.2.1:443:X0:hostname/dir',
      '192.0.2.1:443:X0\n', '192.0.2.1:443:X0\0',
      '192.0.2.1:443:X0 '+ 'a'.repeat(700),
    ];
    for(const value of invalid)
      expect(parseCompositeIpPortInterface(value),value.slice(0,35)).toBeNull();
  });

  it('preserves valid source values from an explicit, untrusted KV carrier',()=>{
    const raw='src=192.0.2.1:0:X0 dst=203.0.113.2:443:X1';
    const carrier=scanKeyValues(raw,0,'space')!;
    for(const field of carrier.fields){
      const composite=extractCompositeFromSource(raw,field);
      expect(composite).not.toBeNull();
      expect(composite?.parts).toHaveLength(3);
    }
  });

  it('cannot grant mapping authority to caller-owned or unknown fixtures',async()=>{
    const raw='src=192.0.2.1:443:X0 dst=198.51.100.2:22:X1';
    const candidate=scanKeyValues(raw,0,'space')!;
    const review=await reviewPinnedCompositeEndpoint('fake-source',candidate,'src','source');
    expect(review).toMatchObject({
      disposition:'SOURCE_REFERENCE_UNVERIFIED',
      sourceOracleStatus:'NOT_ENROLLED',
      productPromotionAllowed:false,
      normalizationApproved:false,
      endpointSemanticApproved:false,
    });
  });

  it('rejects tampered raw-value spans even if the decoded candidate looks valid',()=>{
    const raw='src=192.0.2.10:443:X0 dst=203.0.113.9:80:X1';
    const carrier=scanKeyValues(raw,0,'space')!;
    const damaged=structuredClone(carrier.fields[0]!);
    damaged.valueSpan.start+=1;
    expect(extractCompositeFromSource(raw,damaged)).toBeNull();
  });

  it('does not infer a native parser or semantic mapping for a type-compatible endpoint',()=>{
    const unreviewed=parseCompositeIpPortInterface('192.0.2.1:443:X0')!;
    expect(unreviewed.parts.map(x=>x.value)).toEqual(['192.0.2.1','443','X0']);
    const names=Object.keys(unreviewed);
    expect(names).not.toContain('nativeRuntimeVerified');
    expect(names).not.toContain('normalizedMappingApproved');
  });
});
