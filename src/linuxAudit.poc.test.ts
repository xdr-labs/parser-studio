import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {groupLinuxAuditStream,parseLinuxAuditRecord} from './linuxAudit';

const records=[
  'type=SYSCALL msg=audit(1792152261.123:420): arch=c000003e syscall=59 success=yes exit=0 a0=55 a1=0 items=2 ppid=100 pid=200 auid=1000 uid=0 gid=0 tty=pts0 ses=7 comm="sudo" exe="/usr/bin/sudo" key="privilege"',
  'type=AVC msg=audit(1792152261.123:420): avc: denied { read write } for pid=200 comm="httpd" name="shadow" dev="dm-0" ino=42 scontext=system_u:system_r:httpd_t:s0 tcontext=system_u:object_r:shadow_t:s0 tclass=file',
  'type=CWD msg=audit(1792152261.123:420): cwd="/etc"',
  'type=PATH msg=audit(1792152261.123:420): item=0 name="/etc/shadow" inode=42 dev=fd:05 mode=0100640 ouid=0 ogid=42 nametype=NORMAL',
  'type=EOE msg=audit(1792152261.123:420):',
] as const;

describe('Linux audit record structural PoC',()=>{
  it('extracts the audit envelope and source fields from common record types',()=>{
    for(const raw of records){
      const audit=parseLinuxAuditRecord(raw);
      expect(audit,raw).not.toBeNull();
      expect(audit).toMatchObject({epoch:'1792152261.123',serial:'420',event_id:'1792152261.123:420',source_raw:raw});
      const parsed=extractGenericStructural(raw);
      expect(parsed.errors,raw).toEqual([]);
      expect(parsed.fields.linux_audit).toBeDefined();
    }
    expect(parseLinuxAuditRecord(records[0])?.fields).toMatchObject({arch:'c000003e',syscall:'59',success:'yes',pid:'200',exe:'/usr/bin/sudo'});
    expect(parseLinuxAuditRecord(records[1])?.avc).toEqual({decision:'denied',permissions:['read','write']});
    expect(parseLinuxAuditRecord(records[2])?.fields).toEqual({cwd:'/etc'});
    expect(parseLinuxAuditRecord(records[4])?.fields).toEqual({});
  });

  it('groups related and interleaved records by audit event ID',()=>{
    const event421=[
      'type=SYSCALL msg=audit(1792152262.555:421): arch=c000003e syscall=2 success=no exit=-13 pid=201 comm="cat"',
      'type=PATH msg=audit(1792152262.555:421): item=0 name="/etc/ssh/sshd_config" inode=99 dev=fd:05 nametype=NORMAL',
      'type=EOE msg=audit(1792152262.555:421):',
    ];
    const stream=[records[0],event421[0],records[2],event421[1],records[3],event421[2],records[4]].join('\n')+'\n';
    const grouped=groupLinuxAuditStream(stream);
    expect(grouped.ok).toBe(true);
    if(!grouped.ok)return;
    expect(grouped.events).toHaveLength(2);
    const first=grouped.events.find(event=>event.serial==='420');
    const second=grouped.events.find(event=>event.serial==='421');
    expect(first?.record_types).toEqual(['SYSCALL','CWD','PATH','EOE']);
    expect(second?.record_types).toEqual(['SYSCALL','PATH','EOE']);
    expect(first?.records).toHaveLength(4);
    expect(second?.records).toHaveLength(3);
  });

  it('parses optional node prefixes and audispd/syslog wrappers without losing the audit ID',()=>{
    const node='node=rhel9.example type=SYSCALL msg=audit(1792152265.727:558): arch=c000003e syscall=62 success=yes exit=0 pid=15588 auid=1000 uid=0 comm="killall" exe="/usr/bin/killall"';
    expect(parseLinuxAuditRecord(node)).toMatchObject({node:'rhel9.example',type:'SYSCALL',serial:'558',event_id:'1792152265.727:558'});
    const wrapped='<30>Oct 16 15:44:21 rhel9 audispd: '+node;
    const parsed=extractGenericStructural(wrapped);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields.syslog).toMatchObject({hostname:'rhel9',appname:'audispd'});
    expect(parsed.fields.linux_audit).toMatchObject({node:'rhel9.example',serial:'558',type:'SYSCALL'});
  });

  it('rejects malformed audit IDs, unsafe keys, malformed AVC prefixes, and invalid nodes',()=>{
    const invalid=[
      'type=SYSCALL msg=audit(bad:420): arch=c000003e syscall=59 success=yes',
      'type=SYSCALL msg=audit(1792152261.123:0): arch=c000003e syscall=59 success=yes',
      'type=SYSCALL msg=audit(1792152261.123:420): constructor=bad syscall=59 success=yes',
      'type=AVC msg=audit(1792152261.123:420): avc: denied read for pid=200 comm="httpd"',
      'type=AVC msg=audit(1792152261.123:420): avc: denied { read } pid=200 comm="httpd"',
      'type=AVC msg=audit(1792152261.123:420): avc: denied { read bad/perm } for pid=200',
      'node=bad/node type=SYSCALL msg=audit(1792152261.123:420): syscall=59 success=yes',
      'type=SYSCALL msg=audit(1792152261.123:420): syscall=59 success=yes\nsecond',
    ];
    const accepted=invalid.filter(raw=>parseLinuxAuditRecord(raw)!==null);
    console.log('LINUX_AUDIT_INVALID '+JSON.stringify({total:invalid.length,accepted}));
    expect(accepted).toEqual([]);
  });
});
