import {describe,expect,it} from 'vitest';
import {parseSecurityInput} from './securityInputPipeline';

function collectStrings(value:unknown,out:string[]=[]):string[]{
  if(typeof value==='string'){out.push(value);return out;}
  if(Array.isArray(value)){for(const item of value)collectStrings(item,out);return out;}
  if(value&&typeof value==='object'){for(const item of Object.values(value as Record<string,unknown>))collectStrings(item,out);}
  return out;
}

const samples=[
  {id:'pam-auth',raw:'Dec  1 11:56:57 host-a su[2468]: pam_unix(su:auth): authentication failure; logname=root uid=1004 euid=0 tty=/dev/pts/2 ruser=homer rhost= user=bart',required:['authentication_failure','root','1004','/dev/pts/2','homer','bart']},
  {id:'ssh-accepted',raw:'Oct 16 15:40:01 edge01 sshd[8813]: Accepted password for root from 192.0.2.10 port 1066 ssh2',required:['authentication_success','password','root','192.0.2.10','1066']},
  {id:'sudo-command',raw:'Apr 19 14:52:02 enigma sudo: analyst : TTY=pts/3 ; PWD=/srv/www ; USER=root ; COMMAND=/usr/bin/id',required:['command','analyst','pts/3','/srv/www','root','/usr/bin/id']},
  {id:'ufw',raw:'May  8 11:59:28 fw01 kernel: [7435195.965031] [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:e6:a2:01 SRC=172.25.230.143 DST=172.25.230.141 LEN=214 TOS=0x00 PREC=0x00 TTL=128 ID=43131 PROTO=UDP SPT=53540 DPT=1514',required:['BLOCK','eth0','172.25.230.143','172.25.230.141','UDP','53540','1514']},
  {id:'windows-firewall',raw:'2006-09-18 22:25:30 OPEN TCP 11.12.72.10 12.252.71.6 3311 445 - - - - - - - - -',required:['2006-09-18','22:25:30','OPEN','TCP','11.12.72.10','12.252.71.6','3311','445']},
  {id:'bind-denied',raw:"Oct 22 10:12:33 dns01 named[7885]: client 192.0.2.53#1142: update 'example.test/IN' denied",required:['192.0.2.53','1142','update','example.test','IN','denied']},
  {id:'web-access',raw:'10.11.12.13 - analyst [18/Jan/2026:13:10:06 -0500] "GET /login HTTP/1.1" 403 1732',required:['10.11.12.13','analyst','GET','/login','1.1','403','1732']},
  {id:'suricata-json',raw:'{"timestamp":"2026-10-16T15:44:21.515262+0000","event_type":"alert","src_ip":"192.0.2.20","src_port":5555,"dest_ip":"198.51.100.20","dest_port":80,"proto":"TCP","alert":{"action":"allowed","signature_id":2019236,"signature":"ET TEST","severity":1}}',required:['2026-10-16T15:44:21.515262+0000','alert','192.0.2.20','198.51.100.20','TCP','allowed','ET TEST']},
] as const;

describe('external Wazuh holdout source-preservation audit',()=>{
  it('keeps representative source values reachable after structural parsing',()=>{
    const audit=samples.map(sample=>{
      const parsed=parseSecurityInput(sample.raw);
      if(!parsed.ok)return {id:sample.id,missing:[...sample.required],error:parsed.error};
      const values=collectStrings(parsed.events[0]?.fields??{});
      const missing=sample.required.filter(required=>!values.includes(required));
      return {id:sample.id,missing};
    });
    console.log('WAZUH_HOLDOUT_PRESERVATION '+JSON.stringify(audit));
    expect(audit.every(row=>row.missing.length===0)).toBe(true);
  });
});
