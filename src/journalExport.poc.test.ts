import {describe,expect,it} from 'vitest';
import {parseJournalTextExport} from './journalExport';

const first=[
  '__CURSOR=s=abc;i=1;b=boot;m=1;t=2;x=3',
  '__REALTIME_TIMESTAMP=1792152261123456',
  '_BOOT_ID=0123456789abcdef0123456789abcdef',
  '_SYSTEMD_UNIT=sshd.service',
  'SYSLOG_IDENTIFIER=sshd',
  'PRIORITY=6',
  '_PID=1234',
  'MESSAGE=Accepted publickey for alice from 192.0.2.10 port 51514 ssh2',
  'TAG=auth',
  'TAG=success',
].join('\n');

const second=[
  '__REALTIME_TIMESTAMP=1792152262123456',
  '_SYSTEMD_UNIT=auditd.service',
  'SYSLOG_IDENTIFIER=auditd',
  'PRIORITY=5',
  'MESSAGE=type=SYSCALL msg=audit(1792152262.123:421): syscall=59 success=yes',
].join('\n');

describe('systemd journal text-export event breaker PoC',()=>{
  it('splits entries at double-newline boundaries and preserves fields/duplicates exactly',()=>{
    const raw=first+'\n\n'+second+'\n\n';
    const parsed=parseJournalTextExport(raw);
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.lineEnding).toBe('lf');
    expect(parsed.entries).toHaveLength(2);
    expect(parsed.entries[0].fields).toMatchObject({
      '_SYSTEMD_UNIT':'sshd.service',SYSLOG_IDENTIFIER:'sshd',PRIORITY:'6',_PID:'1234',
      MESSAGE:'Accepted publickey for alice from 192.0.2.10 port 51514 ssh2',
      TAG:['auth','success'],
    });
    expect(parsed.entries[0].raw).toBe(first);
    expect(parsed.entries[1].fields).toMatchObject({_SYSTEMD_UNIT:'auditd.service',SYSLOG_IDENTIFIER:'auditd'});
    console.log('JOURNAL_EXPORT '+JSON.stringify({entries:parsed.entries.length,firstFields:Object.keys(parsed.entries[0].fields).length}));
  });

  it('accepts uniform CRLF transport normalization without altering field values',()=>{
    const raw=(first+'\n\n'+second+'\n\n').replaceAll('\n','\r\n');
    const parsed=parseJournalTextExport(raw);
    expect(parsed.ok).toBe(true);
    if(parsed.ok){
      expect(parsed.lineEnding).toBe('crlf');
      expect(parsed.entries[0].fields.MESSAGE).toBe('Accepted publickey for alice from 192.0.2.10 port 51514 ssh2');
    }
  });

  it('rejects binary-field markers, unsafe keys, malformed boundaries, controls, and mixed line endings',()=>{
    const invalid=[
      first+'\n\n'+second+'\n',
      first+'\n\n\n'+second+'\n\n',
      first.replace('MESSAGE=','MESSAGE\n')+'\n\n',
      first.replace('PRIORITY=6','constructor=bad')+'\n\n',
      first.replace('MESSAGE=Accepted','bad-field=Accepted')+'\n\n',
      first.replace('MESSAGE=Accepted','MESSAGE=bad\u0001')+'\n\n',
      first+'\r\n\r\n'+second+'\n\n',
      '\n\n',
    ];
    const accepted=invalid.filter(raw=>parseJournalTextExport(raw).ok);
    console.log('JOURNAL_EXPORT_INVALID '+JSON.stringify({total:invalid.length,accepted:accepted.length}));
    expect(accepted).toEqual([]);
  });
});
