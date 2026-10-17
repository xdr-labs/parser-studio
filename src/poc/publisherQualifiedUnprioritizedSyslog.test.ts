import {describe,it,expect} from 'vitest';
import {inspectRfc3164WithoutPri} from './publisherQualifiedUnprioritizedSyslog';
const context={sourceFraming:'PUBLISHER_ASSERTED_BSD_WITHOUT_PRI'} as const;
describe('Opt-in publisher-qualified PRI-less RFC3164 source bytes',()=>{
 it('never assumes unknown unlabeled prose uses Syslog',()=>{
  const raw='Oct 17 13:14:15 fw-01 sshd[29]: action=deny';
  expect(inspectRfc3164WithoutPri(raw).disposition).toBe('RAW_ONLY');
  expect(inspectRfc3164WithoutPri(raw).fields).toEqual([]);
 });
 it('replays yearless BSD, unicode message and UTF-8 spans without native certification',()=>{
  const raw='Oct 17 13:14:15 fw-01 auditd[29]: user=café🙂 action=deny';
  const r=inspectRfc3164WithoutPri(raw,context);
  expect(r.disposition).toBe('REVIEW_ONLY');
  expect(r.fields.map(f=>[f.name,f.value])).toEqual([
   ['timestamp','Oct 17 13:14:15'],['hostname','fw-01'],['appname','auditd'],
   ['procid','29'],['message','user=café🙂 action=deny'],
  ]);
  const b=Buffer.from(raw,'utf8');
  for(const f of r.fields)expect(b.subarray(f.startByte,f.endByte).toString('utf8')).toBe(f.value);
  expect(r.autoPromoted).toBe(false);
  expect(r.manufacturerSemantics).toBe('NOT_CERTIFIED');
  expect(r.nativeParser).toBe('NOT_VERIFIED');
 });
 it('does not source-score corrupt headers or concatenated events',()=>{
  for(const raw of [
   'Oct 32 13:14:15 fw auditd[29]: action=deny',
   'Bog 17 13:14:15 fw auditd: action=deny',
   'Oct 17 24:14:15 fw auditd: action=deny',
   'Oct 17 13:14:15 fw auditd: ',
   'Oct 17 13:14:15 fw auditd: action=deny\nOct 17 13:14:15 fw auditd: action=allow',
   'Oct 17 13:14:15 fw auditd: '+('a'.repeat(9000)),
   'Oct 17 13:14:15 fw auditd: action=deny'+String.fromCharCode(0),
  ]){
   const r=inspectRfc3164WithoutPri(raw,context);
   expect(r.disposition).toBe('ABSTAIN_UNSAFE');expect(r.fields).toEqual([]);
  }
  expect(inspectRfc3164WithoutPri('<14>Oct 17 13:14:15 fw auditd: action=deny',context)
    .disposition).toBe('RAW_ONLY');
 });
});
