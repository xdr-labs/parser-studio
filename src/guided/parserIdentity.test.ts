import {describe,it,expect} from 'vitest';
import {parserArtifactBaseName,parserIdentitySlug} from './parserIdentity';

describe('parser identity naming',()=>{
  it('matches the observed Stellar customized vendor/product naming convention',()=>{
    expect(parserIdentitySlug('Cisco','ASA')).toBe('cisco_asa');
    expect(parserArtifactBaseName('MonitorApp','AI WAF')).toBe('customized_monitorapp_ai_waf');
    expect(parserArtifactBaseName('Fortinet','FortiGate ServerFarm')).toBe('customized_fortinet_fortigate_serverfarm');
  });
  it('keeps a safe bounded parser identifier',()=>{
    expect(parserIdentitySlug('123 Vendor','Product / Model')).toMatch(/^[a-z][a-z0-9_]{1,47}$/);
  });
});
