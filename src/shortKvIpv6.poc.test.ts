import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const shortKv=[
  'user=alice action=login status=success',
  'src=192.0.2.10 dst=198.51.100.20 action=block rule=deny-web',
] as const;

const wrappers=[
  (body:string)=>'<134>Oct 16 15:44:21 VPN01 auth: '+body,
  (body:string)=>'<134>Oct 16 2026 15:44:21 VPN01 auth: '+body,
  (body:string)=>'<134>2026-10-16T15:44:21Z VPN01 auth: '+body,
  (body:string)=>'<134>1 2026-10-16T15:44:21Z VPN01 auth 123 EVENT - '+body,
] as const;

const ipv6Body='5,,,1000000103,igb1,match,block,in,6,0x0,,64,41301,0,none,6,tcp,60,2001:db8:1::10,2001:db8:2::20,51514,443,0,S,12345,,64240,,mss';

describe('short KV and IPv6 structural expansion PoC',()=>{
  it('measures 3-4 field space-KV extraction only after a valid Syslog envelope',()=>{
    const rows=[] as boolean[];
    for(const body of shortKv){
      for(const wrap of wrappers){
        const parsed=extractGenericStructural(wrap(body));
        const generic=parsed.fields.generic as {mode?:string;kv?:Record<string,unknown>}|undefined;
        rows.push(
          parsed.errors.length===0&&
          generic?.mode==='syslog_envelope_space_kv'&&
          generic.kv!==undefined
        );
      }
    }
    const summary={total:rows.length,structured:rows.filter(Boolean).length};
    console.log('SHORT_SPACE_KV '+JSON.stringify(summary));
    expect(summary.total).toBe(8);
  });

  it('does not promote ambiguous 1-2 field or unsafe space-KV bodies',()=>{
    const invalid=[
      'one=1',
      'one=1 two=2',
      'action=block constructor=bad src=192.0.2.1',
      'action=block src=192.0.2.1 src=198.51.100.1',
      'action="unterminated src=192.0.2.1 dst=198.51.100.1',
    ];
    const structured=invalid.filter(body=>{
      const parsed=extractGenericStructural('<134>2026-10-16T15:44:21Z VPN01 auth: '+body);
      const generic=parsed.fields.generic as {mode?:string}|undefined;
      return generic?.mode==='syslog_envelope_space_kv';
    });
    console.log('SHORT_SPACE_KV_INVALID '+JSON.stringify({total:invalid.length,structured}));
    expect(structured).toEqual([]);
  });

  it('measures IPv6 positional firewall CSV extraction across wrappers',()=>{
    const raws=[
      '<134>Oct 16 15:44:21 FW6 '+ipv6Body,
      '<134>Oct 16 2026 15:44:21 FW6 '+ipv6Body,
      '<134>2026-10-16T15:44:21Z FW6 '+ipv6Body,
      '<134>2026-10-16 15:44:21.123 +0900 FW6 '+ipv6Body,
    ];
    const rows=raws.map(raw=>{
      const parsed=extractGenericStructural(raw);
      const generic=parsed.fields.generic as {mode?:string;columns?:Record<string,string>}|undefined;
      return parsed.errors.length===0&&
        generic?.mode==='syslog_envelope_positional_csv'&&
        generic.columns?.column_18==='2001:db8:1::10'&&
        generic.columns?.column_19==='2001:db8:2::20';
    });
    const summary={total:rows.length,structured:rows.filter(Boolean).length};
    console.log('IPV6_POSITIONAL_CSV '+JSON.stringify(summary));
    expect(summary.total).toBe(4);
  });

  it('does not count malformed IPv6-like tokens as network evidence',()=>{
    const bad=ipv6Body
      .replace('2001:db8:1::10','2001:::10')
      .replace('2001:db8:2::20','2001:db8:zz::20');
    const parsed=extractGenericStructural('<134>2026-10-16T15:44:21Z FW6 '+bad);
    const generic=parsed.fields.generic as {mode?:string}|undefined;
    expect(generic?.mode).not.toBe('syslog_envelope_positional_csv');
  });
});
