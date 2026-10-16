import {describe,expect,it} from 'vitest';
import {groupLinuxAuditStream} from './linuxAudit';

const a0='type=SYSCALL msg=audit(1792152261.123:420): arch=c000003e syscall=59 success=yes pid=200';
const a1='type=CWD msg=audit(1792152261.123:420): cwd="/home/alice"';
const a2='type=PATH msg=audit(1792152261.123:420): item=0 name="/etc/config" inode=42';
const a3='type=PROCTITLE msg=audit(1792152261.123:420): proctitle=636174';
const b0='type=AVC msg=audit(1792152262.456:421): avc: denied { read } for pid=300 comm="httpd" tclass=file';

describe('Linux Audit event grouping PoC',()=>{
  it('groups interleaved records by audit timestamp and serial instead of adjacency',()=>{
    const parsed=groupLinuxAuditStream([a0,b0,a2,a1,a3].join('\n')+'\n');
    expect(parsed.ok).toBe(true);
    if(!parsed.ok)return;
    expect(parsed.records).toHaveLength(5);
    expect(parsed.events).toHaveLength(2);
    const a=parsed.events.find(event=>event.event_id==='1792152261.123:420');
    expect(a?.record_types).toEqual(['SYSCALL','PATH','CWD','PROCTITLE']);
    expect(a?.records).toHaveLength(4);
    expect(parsed.events.find(event=>event.event_id==='1792152262.456:421')?.record_types).toEqual(['AVC']);
    console.log('LINUX_AUDIT_GROUPING '+JSON.stringify({events:parsed.events.length,records:parsed.records.length}));
  });

  it('fails the whole bounded stream if any record is malformed',()=>{
    const mixed=a0+'\nordinary line\n'+a1+'\n';
    expect(groupLinuxAuditStream(mixed).ok).toBe(false);
  });
});
