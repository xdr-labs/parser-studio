import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

// Independent public-example holdout adapted/redacted from Wazuh decoder/rule
// documentation and ruleset examples. This set was not used by the earlier
// Logstash or synthetic-corpus rounds.
const samples=[
  {id:'pam-sudo-session',family:'pam',raw:'Sep 08 11:25:52 wazuh-server sudo[4543]: pam_unix(sudo-i:session): session opened for user root(uid=0) by analyst(uid=1000)'},
  {id:'pam-su-close',family:'pam',raw:'Dec  1 11:27:21 host-a su(pam_unix)[14592]: session closed for user news'},
  {id:'pam-sshd-open',family:'pam',raw:'Dec  1 11:27:21 host-a sshd(pam_unix)[17365]: session opened for user test by (uid=508)'},
  {id:'pam-auth-failure',family:'pam',raw:'Dec  1 11:56:57 host-a su[2468]: pam_unix(su:auth): authentication failure; logname=root uid=1004 euid=0 tty=/dev/pts/2 ruser=homer rhost= user=bart'},
  {id:'pam-password-change',family:'pam',raw:'Dec  1 12:25:55 host-a passwd[2679]: pam_unix(passwd:chauthtok): password changed for marge'},
  {id:'ssh-accepted',family:'sshd',raw:'Oct 16 15:40:01 edge01 sshd[8813]: Accepted password for root from 192.0.2.10 port 1066 ssh2'},
  {id:'ssh-failed',family:'sshd',raw:'Oct 16 15:40:02 edge01 sshd[21487]: Failed password for root from 192.0.2.11 port 1045 ssh2'},
  {id:'ssh-invalid-user',family:'sshd',raw:'Oct 16 15:40:03 edge01 sshd[11259]: Invalid user scanner from 192.0.2.12'},
  {id:'ssh-reverse-map',family:'sshd',raw:'Oct 16 15:40:04 edge01 sshd[23578]: reverse mapping checking getaddrinfo for scanner.example failed - POSSIBLE BREAKIN ATTEMPT!'},
  {id:'ssh-denyusers',family:'sshd',raw:'Oct 16 15:40:05 edge01 sshd[3251]: User root not allowed because listed in DenyUsers'},
  {id:'ssh-closed',family:'sshd',raw:'Oct 16 15:40:06 edge01 sshd[31274]: Connection closed by 192.0.2.13'},
  {id:'ssh-disconnect',family:'sshd',raw:'Oct 16 15:40:07 edge01 sshd[11283]: Received disconnect from 192.0.2.14: 11: Bye Bye'},
  {id:'ssh-bind-failed',family:'sshd',raw:'Oct 16 15:40:08 edge01 sshd[6856]: error: Bind to port 22 on 0.0.0.0 failed: Address already in use.'},
  {id:'sudo-command',family:'sudo',raw:'Apr 19 14:52:02 enigma sudo: analyst : TTY=pts/3 ; PWD=/srv/www ; USER=root ; COMMAND=/usr/bin/id'},
  {id:'sudo-bad-password',family:'sudo',raw:'Jun 25 15:51:13 host-b sudo: analyst : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/ls'},
  {id:'ufw-block',family:'firewall',raw:'May  8 11:59:28 fw01 kernel: [7435195.965031] [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:e6:a2:01 SRC=172.25.230.143 DST=172.25.230.141 LEN=214 TOS=0x00 PREC=0x00 TTL=128 ID=43131 PROTO=UDP SPT=53540 DPT=1514'},
  {id:'windows-firewall',family:'windows-firewall',raw:'2006-09-18 22:25:30 OPEN TCP 11.12.72.10 12.252.71.6 3311 445 - - - - - - - - -'},
  {id:'web-access',family:'web',raw:'10.11.12.13 - analyst [18/Jan/2026:13:10:06 -0500] "GET /login HTTP/1.1" 403 1732'},
  {id:'suricata-json',family:'json',raw:'{"timestamp":"2026-10-16T15:44:21.515262+0000","event_type":"alert","src_ip":"192.0.2.20","src_port":5555,"dest_ip":"198.51.100.20","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature_id":2019236,"signature":"ET TEST","severity":1}}'},
  {id:'named-denied',family:'bind',raw:'Oct 22 10:12:33 dns01 named[7885]: client 192.0.2.53#1142: update \'example.test/IN\' denied'},
] as const;

describe('external Wazuh decoder-example regression after reusable grammar improvements',()=>{
  it('preserves the qualified external coverage after the independent baseline was classified',()=>{
    const rows=samples.map(sample=>{
      const result=parseSecurityInput(sample.raw);
      return {id:sample.id,family:sample.family,parsed:result.ok,kind:result.ok?result.kind:'error',keys:result.ok?Object.keys(result.events[0]?.fields??{}):[]};
    });
    const families=[...new Set(samples.map(sample=>sample.family))];
    const summary={
      total:rows.length,parsed:rows.filter(row=>row.parsed).length,
      failures:rows.filter(row=>!row.parsed).map(row=>row.id),
      byFamily:Object.fromEntries(families.map(family=>[family,{
        total:rows.filter(row=>row.family===family).length,
        parsed:rows.filter(row=>row.family===family&&row.parsed).length,
      }])),
      successes:rows.filter(row=>row.parsed).map(row=>({id:row.id,keys:row.keys})),
    };
    console.log('WAZUH_EXTERNAL_HOLDOUT '+JSON.stringify(summary));
    expect(rows).toHaveLength(samples.length);
    expect(summary.parsed).toBe(samples.length);
    expect(summary.failures).toEqual([]);
  });
});
