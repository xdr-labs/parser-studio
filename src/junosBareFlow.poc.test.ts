import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';
import {parseJunosBareBracketEvent} from './junosBracketBody';

const body='RT_FLOW - APPTRACK_SESSION_CLOSE [reason="TCP CLIENT RST" source-address="192.0.2.10" source-port="443" destination-address="198.51.100.20" destination-port="8443" application="ssl"]';
const zoned='<14>1 2026-10-17T12:40:28.259Z vsrx01 '+body;
const loose='<14> 2026-10-17T12:40:28.259Z vsrx01 '+body;

describe('source-qualified Juniper bare bracket KV body',()=>{
  it('extracts complete source values from valid RFC5424-like zoned event',()=>{
    const result=parseSecurityInput(zoned);
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(result.events[0]?.fields.juniper_flow_kv).toMatchObject({
      reason:'TCP CLIENT RST',source_address:'192.0.2.10',
      source_port:'443',destination_address:'198.51.100.20',
      destination_port:'8443',application:'ssl',
    });
    expect((result.events[0]?.fields.juniper as Record<string,unknown>).source_raw).toBe(zoned);
  });
  it('uses the same bounded body grammar behind a nonversioned RFC3339 envelope',()=>{
    const result=parseSecurityInput(loose);
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(result.events[0]?.fields.juniper_flow_kv).toEqual(
      parseJunosBareBracketEvent(body)?.fields
    );
    expect((result.events[0]?.fields.juniper as Record<string,unknown>).source_raw).toBe(loose);
  });
  it('rejects invalid known Juniper bare source fields rather than downgrading to generic KV',()=>{
    const invalid=[
      zoned.replace('2026-10-17','2026-02-30'),
      zoned.replace('<14>1','<192>1'),
      zoned.replace('destination-port="8443"','destination-port="70000"'),
      zoned.replace('source-address="192.0.2.10"','source-address="999.2.10.0"'),
      zoned.replace('source-port="443"','source-port="443" source-port="444"'),
      zoned.replace('application="ssl"','constructor="evil"'),
      zoned.replace('application="ssl"','application="unterminated'),
      zoned.slice(0,-1),
      zoned.replace('RT_FLOW -','NOT_VENDOR -'),
      loose.slice(0,-1),
    ];
    expect(invalid.map(raw=>parseSecurityInput(raw).ok)).toEqual(Array(invalid.length).fill(false));
  });
});
