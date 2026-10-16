import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseBindSecurityMessage,parsePamMessage,parseSshdMessage,parseSudoMessage,parseUfwMessage,parseWindowsFirewallLog} from './commonSecurityProfiles';

describe('common auth/security leaf grammar hardening PoC',()=>{
  it('parses representative PAM session/auth/password-change messages including empty values',()=>{
    const valid=[
      'pam_unix(sudo-i:session): session opened for user root(uid=0) by analyst(uid=1000)',
      'su(pam_unix)[14592]: session closed for user news',
      'sshd(pam_unix)[17365]: session opened for user test by (uid=508)',
      'pam_unix(su:auth): authentication failure; logname=root uid=1004 euid=0 tty=/dev/pts/2 ruser=homer rhost= user=bart',
      'pam_unix(passwd:chauthtok): password changed for marge',
    ];
    const parsed=valid.map(parsePamMessage);
    expect(parsed.every(Boolean)).toBe(true);
    expect(parsed[3]).toMatchObject({event:'authentication_failure',fields:{rhost:'',user:'bart',uid:'1004'}});
  });

  it('rejects ambiguous or unsafe PAM messages',()=>{
    const invalid=[
      'pam_unix(su:auth): authentication failure; constructor=bad user=bob',
      'pam_unix(su:auth): authentication failure; uid=1 uid=2',
      'pam_unix(su:session): session opened for user bad user',
      'pam_unix(su:session): session opened for user root(uid=-1)',
      'pam_unix(passwd:chauthtok): password changed for bad/user',
      'session opened for user root',
    ];
    expect(invalid.filter(text=>parsePamMessage(text)!==null)).toEqual([]);
  });

  it('parses bounded sshd authentication/session/security messages',()=>{
    const valid=[
      'Accepted password for root from 192.0.2.10 port 1066 ssh2',
      'Failed password for root from 192.0.2.11 port 1045 ssh2',
      'Failed publickey for invalid user scanner from 2001:db8::11 port 2222 ssh2',
      'Invalid user scanner from 192.0.2.12',
      'Connection closed by 192.0.2.13',
      'Received disconnect from 192.0.2.14: 11: Bye Bye',
      'reverse mapping checking getaddrinfo for scanner.example failed - POSSIBLE BREAKIN ATTEMPT!',
      'User root not allowed because listed in DenyUsers',
      'error: Bind to port 22 on 0.0.0.0 failed: Address already in use.',
    ];
    expect(valid.every(text=>parseSshdMessage(text)!==null)).toBe(true);
  });

  it('rejects malformed sshd addresses, ports, policies and identities',()=>{
    const invalid=[
      'Accepted password for root from 999.0.0.1 port 22 ssh2',
      'Accepted password for root from 192.0.2.1 port 70000 ssh2',
      'Failed token for root from 192.0.2.1 port 22 ssh2',
      'Invalid user bad/user from 192.0.2.1',
      'Connection closed by not-an-ip',
      'User root not allowed because listed in AllowUsers',
      'error: Bind to port 70000 on 0.0.0.0 failed: bad',
    ];
    expect(invalid.filter(text=>parseSshdMessage(text)!==null)).toEqual([]);
  });

  it('parses BIND denied/update messages and rejects invalid client boundaries',()=>{
    expect(parseBindSecurityMessage("client 192.0.2.53#1142: update 'example.test/IN' denied")).toMatchObject({
      client_ip:'192.0.2.53',client_port:'1142',operation:'update',zone:'example.test',query_class:'IN',action:'denied',
    });
    const invalid=[
      "client 999.0.0.1#1142: update 'example.test/IN' denied",
      "client 192.0.2.53#70000: update 'example.test/IN' denied",
      "client 192.0.2.53#1142: update 'example.test/BAD' denied",
      "client 192.0.2.53#1142: update '' denied",
      "client 192.0.2.53#1142: transfer 'example.test/IN' denied",
    ];
    expect(invalid.filter(text=>parseBindSecurityMessage(text)!==null)).toEqual([]);
  });

  it('parses classic Windows Firewall positional logs and rejects boundary corruption',()=>{
    const valid='2006-09-18 22:25:30 OPEN TCP 11.12.72.10 12.252.71.6 3311 445 - - - - - - - - -';
    expect(parseWindowsFirewallLog(valid)).toMatchObject({windows_firewall:{action:'OPEN',protocol:'TCP',src_ip:'11.12.72.10',dst_port:'445'}});
    const invalid=[
      valid.replace('2006-09-18','2006-02-30'),
      valid.replace('11.12.72.10','999.1.1.1'),
      valid.replace('3311','70000'),
      valid.replace('OPEN','ALLOW'),
      valid+' extra',
    ];
    expect(invalid.filter(raw=>parseWindowsFirewallLog(raw)!==null)).toEqual([]);
  });

  it('parses sudo command/auth-failure records and rejects unsafe segment boundaries',()=>{
    const command='analyst : TTY=pts/3 ; PWD=/srv/www ; USER=root ; COMMAND=/usr/bin/id';
    const failed='analyst : 1 incorrect password attempt ; TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/ls -la';
    expect(parseSudoMessage(command)).toMatchObject({event:'command',actor:'analyst',fields:{USER:'root',COMMAND:'/usr/bin/id'}});
    expect(parseSudoMessage(failed)).toMatchObject({event:'authentication_failure',attempts:'1',fields:{COMMAND:'/bin/ls -la'}});
    const invalid=[
      'bad/user : TTY=pts/0 ; USER=root ; COMMAND=/bin/id',
      'analyst : TTY=pts/0 ; USER=root',
      'analyst : constructor=bad ; USER=root ; COMMAND=/bin/id',
      'analyst : TTY=pts/0 ; USER=root ; USER=admin ; COMMAND=/bin/id',
      'analyst : x incorrect password attempts ; USER=root ; COMMAND=/bin/id',
    ];
    expect(invalid.filter(text=>parseSudoMessage(text)!==null)).toEqual([]);
  });

  it('parses UFW kernel records while preserving empty fields and validates network boundaries',()=>{
    const valid='[7435195.965031] [UFW BLOCK] IN=eth0 OUT= MAC=00:15:5d:e6:a2:01 SRC=172.25.230.143 DST=172.25.230.141 LEN=214 TOS=0x00 PREC=0x00 TTL=128 ID=43131 PROTO=UDP SPT=53540 DPT=1514';
    expect(parseUfwMessage(valid)).toMatchObject({
      action:'BLOCK',
      fields:{IN:'eth0',OUT:'',SRC:'172.25.230.143',DST:'172.25.230.141',SPT:'53540',DPT:'1514'},
    });
    const invalid=[
      valid.replace('172.25.230.143','999.25.230.143'),
      valid.replace('DPT=1514','DPT=70000'),
      valid.replace('[UFW BLOCK]','[UFW UNKNOWN]'),
      valid.replace('SRC=172.25.230.143','constructor=bad'),
      valid+' SRC=192.0.2.1',
    ];
    expect(invalid.filter(text=>parseUfwMessage(text)!==null)).toEqual([]);
  });

  it('keeps representative Syslog-wrapped auth/security events structured in the public engine',()=>{
    const samples=[
      'Sep 08 11:25:52 wazuh-server sudo[4543]: pam_unix(sudo-i:session): session opened for user root(uid=0) by analyst(uid=1000)',
      'Oct 16 15:40:01 edge01 sshd[8813]: Accepted password for root from 192.0.2.10 port 1066 ssh2',
      "Oct 22 10:12:33 dns01 named[7885]: client 192.0.2.53#1142: update 'example.test/IN' denied",
      '2006-09-18 22:25:30 OPEN TCP 11.12.72.10 12.252.71.6 3311 445 - - - - - - - - -',
    ];
    const results=samples.map(extractGenericStructural);
    expect(results.every(result=>result.errors.length===0)).toBe(true);
    expect(results[0].fields).toHaveProperty('pam');
    expect(results[1].fields).toHaveProperty('sshd');
    expect(results[2].fields).toHaveProperty('bind_security');
    expect(results[3].fields).toHaveProperty('windows_firewall');
  });
});
