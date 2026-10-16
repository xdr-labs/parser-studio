import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';

const valid=[
  '<5>1 2024-02-29T05:01:01Z vault-host CEF:0|Example|Vault|12.2|59|Test|5|act=Allow src=192.0.2.1',
  '<134>1 2024-02-29T07:20:35 gw CheckPoint 8363 - [action:"Accept"; src:"192.0.2.1"]',
  '<139>Jan 16 15:19:05 WatchGuard-Firebox FVE6035FD3AE3 (2024-02-29T08:48:15) firewall: msg_id="1BFF-000F" Allow 1-Trusted 0-External tcp 10.0.1.2 175.16.199.1 39398 25',
  'Oct 19 09:11:55 edge-node 1 2024-02-29T09:11:55+02:00 192.0.2.3 SecureAccess: - - - 2024-02-29 09:11:55 - edge-node - [198.51.100.10] user.name(REALM)[ROLE] - Session established',
] as const;

const invalid=[
  {id:'short-rfc5424-feb30',raw:'<5>1 2026-02-30T05:01:01Z vault-host CEF:0|Example|Vault|12.2|59|Test|5|act=Allow src=192.0.2.1'},
  {id:'short-rfc5424-nonleap-feb29',raw:'<5>1 2026-02-29T05:01:01Z vault-host CEF:0|Example|Vault|12.2|59|Test|5|act=Allow src=192.0.2.1'},
  {id:'short-json-apr31',raw:'<5>1 2026-04-31T18:24:49Z VAULT {"format":"elastic","event":"test"}'},
  {id:'junos-feb30',raw:'<14>1 2026-02-30T09:37:51.184+01:00 SRX-GW1 RT_FLOW - RT_FLOW_SESSION_CREATE [junos@67.43.156.15 source-address="10.0.0.1"]'},
  {id:'checkpoint-unzoned-nonleap',raw:'<134>1 2026-02-29T07:20:35 gw CheckPoint 8363 - [action:"Accept"; src:"192.0.2.1"]'},
  {id:'checkpoint-zoned-apr31',raw:'<134>1 2026-04-31T07:20:35Z gw CheckPoint 8363 - [action:"Accept"; src:"192.0.2.1"]'},
  {id:'watchguard-device-feb30',raw:'<139>Jan 16 15:19:05 WatchGuard-Firebox FVE6035FD3AE3 (2026-02-30T08:48:15) firewall: msg_id="1BFF-000F" Allow 1-Trusted 0-External tcp 10.0.1.2 175.16.199.1 39398 25'},
  {id:'watchguard-message-device-apr31',raw:'<142>May 10 15:19:05 WatchGuard-Firebox (2026-04-31T09:49:05) firewall: msg_id="3000-0152" IPv4 source route attack detected. (IPS)'},
  {id:'dual-first-timestamp-feb30',raw:'Oct 19 09:11:55 edge-node 1 2026-02-30T09:11:55+02:00 192.0.2.3 SecureAccess: - - - 2026-10-19 09:11:55 - edge-node - [198.51.100.10] user.name(REALM)[ROLE] - Session established'},
  {id:'dual-first-timestamp-apr31',raw:'Oct 19 09:11:55 edge-node 1 2026-04-31T09:11:55+02:00 192.0.2.3 SecureAccess: - - - 2026-10-19 09:11:55 - edge-node - [198.51.100.10] user.name(REALM)[ROLE] - Session established'},
] as const;

describe('strict timestamp calendar PoC',()=>{
  it('keeps valid leap-day events parseable',()=>{
    const failures=valid.filter(raw=>extractGenericStructural(raw).errors.length>0);
    console.log('TIMESTAMP_VALID '+JSON.stringify({total:valid.length,failures}));
    expect(failures).toEqual([]);
  });

  it('measures impossible-date false acceptance across parser paths',()=>{
    const accepted=invalid.filter(sample=>extractGenericStructural(sample.raw).errors.length===0);
    console.log('TIMESTAMP_INVALID '+JSON.stringify({
      total:invalid.length,
      accepted:accepted.map(sample=>sample.id),
    }));
    expect(accepted).toEqual([]);
  });
});
