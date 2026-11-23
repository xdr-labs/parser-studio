/**
 * An RFC 3164 record with a TAG and without a PRI (Phase 3, P2).
 *
 * A relay or a log file drops the PRI: "Nov 21 10:00:03 fw1 traffic: srcip=10.0.0.7 ...". The contract knew the
 * record without a PRI only without a TAG (rfc3164_tagless, rfc3164_hostless). With a TAG the browser grammar -
 * and so the generated Ruby - did not read it, while the Python preview did (BSD_SYSLOG): one such line stopped
 * a sample of otherwise readable events. The bound of the other PRI-less forms applies: the message must be a
 * structured body; free text behind a time stamp is not a Syslog record.
 */
import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {analyzeLogEnvelopes} from '../guided/autoParserEnvelope';
import {matchRfc3164Header} from './syslogHeader';

const WITH_PRI='<134>Nov 21 10:00:03 fw1 traffic: srcip=10.0.0.7 dstip=10.0.0.8 srcport=51237 dstport=22 proto=6 action=accept';
const WITHOUT_PRI=WITH_PRI.slice(5);
const read=(line:string)=>preview(line,{...createDraft(),format:'auto'}).events[0]!;
const scan=(sample:string)=>analyzeLogEnvelopes(sample,'single-line');

describe('an RFC 3164 record with a TAG and without a PRI',()=>{
  it('matches the tagged header rule when its message is a structured body',()=>{
    const header=matchRfc3164Header(WITHOUT_PRI);
    expect(header).toMatchObject({ok:true,rule:'rfc3164_tagged',timestamp:'Nov 21 10:00:03',hostname:'fw1',tag:'traffic',
      message:WITHOUT_PRI.slice(WITHOUT_PRI.indexOf('srcip'))});
    expect(header).not.toHaveProperty('pri');
    expect(matchRfc3164Header('Nov 21 10:00:03 fw1 sshd[4242]: user=bob result=ok'))
      .toMatchObject({ok:true,rule:'rfc3164_tagged',tag:'sshd',procid:'4242',message:'user=bob result=ok'});
  });

  it('is read like the record with a PRI, without the PRI field',()=>{
    const withPri=read(WITH_PRI),withoutPri=read(WITHOUT_PRI);
    expect([withoutPri.parseStatus,withoutPri.effectiveFormat]).toEqual(['FULL','syslog_rfc3164']);
    const {syslog_pri:pri,...rest}=withPri.fields as Record<string,unknown>;
    expect(pri).toBe(134);
    expect(withoutPri.fields).toEqual(rest);
  });

  it('is recognized by the first scan, alone and beside the record with a PRI',()=>{
    expect(scan(WITHOUT_PRI).events[0]).toMatchObject({envelope:'rfc3164',body:'kv',status:'RECOGNIZED'});
    const mixed=scan([WITH_PRI,WITHOUT_PRI,WITH_PRI].join('\n'));
    expect(mixed.events.map(event=>event.status)).toEqual(['RECOGNIZED','RECOGNIZED','RECOGNIZED']);
    expect(mixed.unsupported).toBe(0);
  });

  it('reads a delimited list behind the TAG',()=>{
    const event=read('Oct 15 00:14:27 bigip-waf01 ASM: unit_hostname=bigip-waf01,management_ip_address=10.1.1.10,request_status=blocked');
    expect(event.parseStatus).toBe('FULL');
    expect(event.fields).toMatchObject({syslog_hostname:'bigip-waf01',syslog_appname:'ASM',
      body:{unit_hostname:'bigip-waf01',management_ip_address:'10.1.1.10',request_status:'blocked'}});
  });

  it.each([
    'Nov 21 10:00:03 fw1 sshd[4242]: Accepted password for bob from 10.0.0.5 port 51234 ssh2',
    'Nov 21 10:00:03 the service restarted: see the log',
    // 'Dec 27 11:07:55 FGT-A-LOG CEF: 0|...' has a structured body since the FortiGate "CEF: 0|" form is CEF
    // (src/grammar/fortinetCefSpace20261124.test.ts).
  ])('does not take a line without a structured body for a tagged Syslog record: %s',line=>{
    const header=matchRfc3164Header(line);
    expect(header.ok&&header.rule==='rfc3164_tagged').toBe(false);
    expect(read(line).parseStatus).toBe('UNKNOWN');
    expect(scan(line).events[0]!.status).not.toBe('RECOGNIZED');
  });

  it('still requires a valid calendar date and time',()=>{
    expect(matchRfc3164Header('Nov 31 10:00:03 fw1 traffic: srcip=10.0.0.7')).toEqual({ok:false,reason:'CALENDAR_INVALID'});
    expect(read('Nov 21 25:00:03 fw1 traffic: srcip=10.0.0.7').parseStatus).not.toBe('FULL');
  });
});
