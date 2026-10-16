import {describe,expect,it} from 'vitest';
import {strictKeyValues} from './structuredFamilies';
import {parseSophosKvBody} from './applianceSecurityProfiles';
import {parseSecurityInput} from './securityInputPipeline';

const xg='device="SFW" date=2026-10-16 time=10:05:06 timezone="KST" device_name="xg-safe" device_id="C01001K234RXPA1" log_id="010101600001" log_type="Firewall" log_component="Firewall Rule" priority=Information src_ip=192.0.2.10 dst_ip=198.51.100.20 src_port=5353 dst_port=443';
const empty=' src_country_code= dst_country_code= src_mac= exceptions= ep_uuid= src_ip_note= subject=';
describe('optional empty security KV values in a qualified source grammar',()=>{
  it('keeps the strict shared KV default unchanged',()=>{
    expect(strictKeyValues(xg+' src_country_code= dst_country_code=KR').errors.length).toBeGreaterThan(0);
  });
  it('preserves empty optional source fields without inventing values',()=>{
    const raw=xg+empty;
    const parsed=parseSophosKvBody(raw);
    expect(parsed?.fields).toMatchObject({
      device:'SFW',src_ip:'192.0.2.10',dst_ip:'198.51.100.20',
      src_country_code:'',dst_country_code:'',src_mac:'',
      exceptions:'',ep_uuid:'',src_ip_note:'',subject:'',
    });
    const pipeline=parseSecurityInput(raw);
    expect(pipeline.ok).toBe(true);
    if(!pipeline.ok)return;
    expect(pipeline.events[0]?.fields.sophos).toMatchObject({variant:'xg',fields:{subject:'',src_country_code:''}});
  });
  it('preserves quoted empty and legitimately empty optional network positions',()=>{
    const raw=xg.replace('src_ip=192.0.2.10','src_ip=')+
      ' src_mac="" src_country_code= dst_port_note=';
    const parsed=parseSophosKvBody(raw);
    expect(parsed?.fields).toMatchObject({src_ip:'',src_mac:'',src_country_code:'',dst_port_note:''});
  });
  it('never tolerates unsafe identifiers, duplicate fields, or unterminated quotes',()=>{
    const bad=[
      xg+' src_country_code= constructor=x',
      xg+' src_country_code= src_country_code=KR',
      xg+' src_country_code= "stray"',
      xg+' src_country_code="unterminated',
      xg+' src_country_code=word extra',
      xg+' src_country_code="a"junk',
      xg+' src_country_code=bad"tail',
    ];
    expect(bad.map(v=>parseSophosKvBody(v)!==null)).toEqual(Array(bad.length).fill(false));
    expect(bad.map(v=>parseSecurityInput(v).ok)).toEqual(Array(bad.length).fill(false));
  });
  it('preserves fail-closed source/date/network invariants and does not loosen Fortinet',()=>{
    const bad=[
      xg.replace('2026-10-16','2026-02-30')+empty,
      xg.replace('src_ip=192.0.2.10','src_ip=999.1.1.1')+empty,
      xg.replace('dst_port=443','dst_port=99999')+empty,
      xg.replace('device="SFW"','device="UNKNOWN"')+empty,
      xg.replace('device_name="xg-safe"','device_name=')+empty,
      xg.replace('log_type="Firewall"','log_type=')+empty,
    ];
    expect(bad.map(v=>parseSophosKvBody(v)!==null)).toEqual(Array(bad.length).fill(false));
    expect(bad.map(v=>parseSecurityInput(v).ok)).toEqual(Array(bad.length).fill(false));
    expect(strictKeyValues('date=2026-10-16 time=10:05:06 type=utm devname=fg01 devid=FG123 optional=').errors.length).toBeGreaterThan(0);
  });
});
