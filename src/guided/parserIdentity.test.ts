import {describe,it,expect} from 'vitest';
import {parserArtifactBaseName,parserIdentitySlug,MAX_PARSER_IDENTITY_TEXT,missingParserIdentityMessage} from './parserIdentity';

describe('parser identity naming',()=>{
  it('matches the observed Stellar customized vendor/product naming convention',()=>{
    expect(parserIdentitySlug('Cisco','ASA')).toBe('cisco_asa');
    expect(parserArtifactBaseName('MonitorApp','AI WAF')).toBe('customized_monitorapp_ai_waf');
    expect(parserArtifactBaseName('Fortinet','FortiGate ServerFarm')).toBe('customized_fortinet_fortigate_serverfarm');
  });
  it('keeps a safe bounded parser identifier',()=>{
    expect(parserIdentitySlug('123 Vendor','Product / Model')).toMatch(/^[a-z][a-z0-9_]{1,47}$/);
  });
  it('keeps the product visible and distinct when the manufacturer is very long',()=>{
    const vendor='Z'.repeat(60);
    const alpha=parserIdentitySlug(vendor,'ProductAlpha');
    const beta=parserIdentitySlug(vendor,'ProductBeta');
    expect(alpha).not.toBe(beta);
    expect(alpha).toMatch(/^[a-z][a-z0-9_]{1,47}$/);
    expect(alpha).toContain('productalpha');
    expect(beta).toContain('productbeta');
  });
  it('does not change names that already fit', ()=>{
    expect(parserIdentitySlug('Fortinet','FortiGate')).toBe('fortinet_fortigate');
    expect(parserIdentitySlug('A'.repeat(20),'B'.repeat(27))).toBe('a'.repeat(20)+'_'+'b'.repeat(27));
  });
  it('limits typed manufacturer and product text to the schema maximum',()=>{
    expect(MAX_PARSER_IDENTITY_TEXT).toBe(128);
  });
  it('names the missing manufacturer or product instead of a generic schema failure',()=>{
    expect(missingParserIdentityMessage('', 'FortiGate')).toMatch(/manufacturer/i);
    expect(missingParserIdentityMessage('   ', 'FortiGate')).toMatch(/manufacturer/i);
    expect(missingParserIdentityMessage('Fortinet', '')).toMatch(/product/i);
    expect(missingParserIdentityMessage('', '')).toMatch(/manufacturer and product/i);
    expect(missingParserIdentityMessage('Fortinet','FortiGate')).toBeNull();
  });
});
