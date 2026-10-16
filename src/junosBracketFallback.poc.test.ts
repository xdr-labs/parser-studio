import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';
import {extractGenericStructural} from './genericStructural';

const bracket='[junos@67.43.156.15 source-address="192.0.2.10" source-port="443" destination-address="198.51.100.20" destination-port="8443" attack-name="FIN but no ACK bit!"]';
const zoned='<11> 2020-07-17T10:01:43.006+02:00 edge-srx RT_IDS - RT_SCREEN_TCP '+bracket;
const unzoned='<14>1 2013-01-19T15:18:17.040 edge-srx RT_FLOW - APPTRACK_SESSION_CREATE '+bracket;
describe('source-qualified Junos bracket KV across Syslog envelopes',()=>{
 it('extracts same ordered attributes behind valid RFC3339-loose envelope',()=>{
   const parsed=parseSecurityInput(zoned);
   expect(parsed.ok).toBe(true);
   if(!parsed.ok)return;
   expect(parsed.events[0]?.fields.junos_sd).toMatchObject({
     source_address:'192.0.2.10',destination_address:'198.51.100.20',
     source_port:'443',destination_port:'8443',attack_name:'FIN but no ACK bit!',
   });
   const source=parsed.events[0]?.fields.juniper as Record<string,unknown>;
   expect(source.source_raw).toBe(zoned);
 });
 it('retains source timestamp but makes unknown timezone explicit for qualified unzoned header',()=>{
   const parsed=parseSecurityInput(unzoned);
   expect(parsed.ok).toBe(true);
   if(!parsed.ok)return;
   expect(parsed.events[0]?.fields.syslog).toMatchObject({
     timestamp:'2013-01-19T15:18:17.040',hostname:'edge-srx',
     appname:'RT_FLOW',timezone_missing:true,
   });
   expect(parsed.events[0]?.fields.junos_sd).toMatchObject({
     source_address:'192.0.2.10',destination_port:'8443',
   });
   expect((parsed.events[0]?.fields.juniper as Record<string,unknown>).source_raw).toBe(unzoned);
 });
 it('rejects corrupted qualified Junos KV without generic downgrade',()=>{
   const invalid=[
     unzoned.replace('2013-01-19','2013-02-30'),
     unzoned.replace('<14>1','<192>1'),
     unzoned.replace('RT_FLOW -','NOT_VENDOR -'),
     unzoned.replace('source-address="192.0.2.10"','source-address="192.0.2.10" source-address="192.0.2.11"'),
     unzoned.replace('source-address="192.0.2.10"','constructor="malicious"'),
     unzoned.replace('source-port="443"','source-port="unterminated'),
     zoned.replace('destination-port="8443"','destination-port="8443" junk="quoted"tail'),
   ];
   expect(invalid.map(raw=>parseSecurityInput(raw).ok)).toEqual(Array(invalid.length).fill(false));
 });
 it('does not allow duplicate structured-data names to become generic RFC5424 success',()=>{
   const raw='<14>1 2026-10-16T15:44:21Z edge-srx RT_FLOW - APPTRACK_SESSION_CREATE '+bracket;
   expect(parseSecurityInput(raw).ok).toBe(true);
   const duplicates=[
     raw.replace('source-port="443"','source-port="443" source-port="444"'),
     raw.replace('source-port="443"','source-port="443" source_port="444"'),
     raw.replace('attack-name="FIN but no ACK bit!"','attack-name="FIN but no ACK bit!" constructor="x"'),
   ];
   expect(duplicates.map(value=>parseSecurityInput(value).ok)).toEqual([false,false,false]);
 });
 it('refuses truncated Junos SD even if generic space-KV sees intact values',()=>{
   const variants=[
     zoned.slice(0,-1),unzoned.slice(0,-1),
     '<14>1 2026-10-16T15:44:21Z edge-srx RT_FLOW - APPTRACK_SESSION_CREATE '+bracket.slice(0,-1),
     '<14> 2026-10-16T15:44:21Z edge-srx RT_FLOW - APPTRACK_SESSION_CREATE '+bracket.slice(0,-1),
   ];
   expect(variants.map(value=>parseSecurityInput(value).ok)).toEqual([false,false,false,false]);
 });
 it('keeps plain free-form messages unstructured even behind valid RFC5424',()=>{
   const raw='<14>1 2026-10-16T15:44:21Z edge-srx RT_FLOW - INFO - System restarted due to maintenance';
   expect(extractGenericStructural(raw).errors.length).toBeGreaterThan(0);
 });
});
