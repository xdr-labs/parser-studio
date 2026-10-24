import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {buildSingleSampleVariation,hasExtractedVariationTarget,
  verifySingleSampleVariation} from './singleSampleVariation';

describe('one-record mutation probe is synthetic, bounded and value-exact',()=>{
  it('changes one CSV IP and proves capture follows the new value',()=>{
    const source='deny,198.51.100.10';
    const baseline=createDraft();
    const draft={...baseline,format:'csv' as const,csvColumns:'action,src_ip',
      csvDelimiter:',' as const,mappings:baseline.mappings.filter(m=>m.source!=='dst_port')};
    const variation=buildSingleSampleVariation(source,draft.format);
    expect(variation?.mutatedSource).toBe('deny,203.0.113.77');
    expect(variation).not.toBeNull();
    if(variation)expect(verifySingleSampleVariation(variation,
      preview(source,draft),preview(variation.mutatedSource,draft))).toBe(true);
  });
  it('rejects a regex that memorized a literal IP instead of extracting it',()=>{
    const source='deny src=198.51.100.10';
    const draft={...createDraft(),format:'regex' as const,
      pattern:'(?<action>deny) src=(?<src_ip>198\\.51\\.100\\.10)'};
    const variation=buildSingleSampleVariation(source,draft.format);
    expect(variation).not.toBeNull();
    if(variation)expect(verifySingleSampleVariation(variation,
      preview(source,draft),preview(variation.mutatedSource,draft))).toBe(false);
  });
  it('skips an IP probe when the proposed parser never extracts that IP',()=>{
    const source='deny src=198.51.100.10';
    const draft={...createDraft(),format:'regex' as const,pattern:'(?<action>deny) src=[^ ]+'};
    const variation=buildSingleSampleVariation(source,draft.format);
    expect(variation).not.toBeNull();
    if(variation)expect(hasExtractedVariationTarget(variation,preview(source,draft))).toBe(false);
  });
  it('does not manufacture variants from invalid, ambiguous or unsupported sources',()=>{
    expect(buildSingleSampleVariation('action=deny\nsrc=198.51.100.10','kv')).toBeNull();
    expect(buildSingleSampleVariation('src=999.51.100.10','kv')).toBeNull();
    expect(buildSingleSampleVariation('src=198.051.100.10','kv')).toBeNull();
    expect(buildSingleSampleVariation('prefix192.0.2.1suffix','kv')).toBeNull();
    expect(buildSingleSampleVariation('src=192.0.2.10','json')).toBeNull();
    expect(buildSingleSampleVariation('action=allow','kv')).toBeNull();
  });
});
