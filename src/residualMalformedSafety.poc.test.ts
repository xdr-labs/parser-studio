import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

const validJunos='<14> 2026-10-17T12:44:01Z srx01 RT_FLOW - APPTRACK_SESSION_CLOSE [junos@1.2 source-address="192.0.2.10" source-port="443" destination-address="198.51.100.5" destination-port="8443" destination-interface-name="reth0.14"]';

describe('residual vendor dialects remain fail-closed until independently source-certified',()=>{
  it('accepts the ASCII-quoted qualified Junos source control',()=>{
    expect(parseSecurityInput(validJunos).ok).toBe(true);
  });

  it('does not treat typographic smart-quoted Junos values as exact source fields',()=>{
    const malformed=[
      validJunos.replace('"reth0.14"','”reth0.14”'),
      validJunos.replace('"8443"','”8443”'),
      validJunos.replace('APPTRACK_SESSION_CLOSE','APPTRACK_SESSION_CLOSE_LS')
        .replace('"reth0.14"','“reth0.14”'),
    ];
    expect(malformed.map(raw=>parseSecurityInput(raw).ok)).toEqual([false,false,false]);
  });

  it('rejects known Sophos unclosed quotation rather than generic KV fallback',()=>{
    const malformed='<14>device="SFW" date=2026-10-17 time=12:44:01 timezone="UTC" device_name="SFW01" log_type="Firewall" msg="unclosed';
    expect(parseSecurityInput(malformed).ok).toBe(false);
  });

  it('rejects RFC5424 Check Point double-sign timezone instead of inventing time',()=>{
    const malformed='<85>1 2023-01-13T10:10:16--5:00 cp-gw CP-GW - Log [Fields@1.2 inzone="DMZ" outzone="External" service_id="https"]';
    expect(parseSecurityInput(malformed).ok).toBe(false);
  });

  it('does not promote unsupported Juniper system prose to verified structure',()=>{
    const prose='<14>1 2026-10-17T12:44:01Z srx01 RT_FLOW - INFO - System restarted unexpectedly';
    expect(parseSecurityInput(prose).ok).toBe(false);
  });
});
