import {describe,expect,it} from 'vitest';
import {inspectGeneralSyslogEnvelope} from './generalSyslogEnvelopeSpans';
import {parseSyslogEnvelope} from '../syslogEnvelope';
import {parseSecurityInput} from '../securityInputPipeline';

const bytes=(value:string)=>new TextEncoder().encode(value);
function source(raw:string,expected:Array<[string,string]>){
  const result=inspectGeneralSyslogEnvelope(raw);
  expect(result.disposition).toBe('REVIEW_ONLY');
  expect(result.autoPromoted).toBe(false);
  expect(result.nativeParser).toBe('NOT_VERIFIED');
  expect(result.manufacturerSemantics).toBe('NOT_CERTIFIED');
  const input=bytes(raw);
  for(const [name,value] of expected){
    const field=result.fields.find(f=>f.name===name);
    expect(field).toBeDefined();
    expect(field!.type).toBe('string');
    expect(field!.value).toBe(value);
    const restored=new TextDecoder('utf-8',{fatal:true}).decode(
      input.slice(field!.startByte,field!.endByte));
    expect(restored).toBe(value);
  }
  expect(result.sourceBytes).toBe(input.length);
  expect(result.branchAttempts).toBeLessThanOrEqual(2);
  return result;
}
describe('vendor-agnostic Syslog source field byte-span and abstention PoC',()=>{
  it('keeps RFC3164 PRI/month/day/time/tag/procid/message distinct',()=>{
    const raw='<14>Oct 17 12:34:56 gateway-sec auditd[314]: denied by policy';
    const out=source(raw,[
      ['pri','14'],['month','Oct'],['day','17'],['time','12:34:56'],
      ['hostname','gateway-sec'],['appname','auditd'],['procid','314'],
      ['message','denied by policy'],
    ]);
    expect(out.format).toBe('rfc3164');
  });
  it('keeps a tagless classic RFC3164 body instead of inventing an appname',()=>{
    const raw='<13>Jan  7 00:03:09 router-01 link state down';
    const out=source(raw,[
      ['pri','13'],['month','Jan'],['day','7'],['time','00:03:09'],
      ['hostname','router-01'],['message','link state down'],
    ]);
    expect(out.fields.find(x=>x.name==='appname')).toBeUndefined();
  });
  it('accepts a valid RFC5424 MSG newline as one bounded source event',()=>{
    const raw='<86>1 2026-10-17T12:34:56Z host app 82 EVT [meta session="open"] header\nsecond source line';
    const out=source(raw,[
      ['pri','86'],['version','1'],['timestamp','2026-10-17T12:34:56Z'],
      ['hostname','host'],['appname','app'],['procid','82'],
      ['msgid','EVT'],['structured_data_raw','[meta session="open"]'],
      ['message','header\nsecond source line'],
    ]);
    expect(out.format).toBe('rfc5424');
    expect(parseSyslogEnvelope(raw)).toBeNull();
  });
  it('retains exact UTF-8 byte offsets for a multi-byte MSG',()=>{
    const raw='<12>1 2026-10-17T11:12:13Z host a - - - event: '+String.fromCodePoint(0x1f642);
    const out=source(raw,[
      ['pri','12'],['structured_data_raw','-'],
      ['message','event: '+String.fromCodePoint(0x1f642)],
    ]);
    const f=out.fields.find(x=>x.name==='message')!;
    expect(f.endByte-f.startByte).toBe(bytes(f.value).length);
  });
  it('rejects unescaped right bracket in SD-PARAM even if old parser accepts it',()=>{
    const raw='<1>1 2026-10-17T12:34:56Z host app - - [meta value="bad]token"] payload';
    const observed=inspectGeneralSyslogEnvelope(raw);
    expect(observed.disposition).toBe('ABSTAIN_UNSAFE');
    expect(observed.reason).toBe('RFC5424_SD_UNESCAPED_RIGHT_BRACKET');
    expect(observed.fields).toEqual([]);
    expect(parseSyslogEnvelope(raw)?.variant).toBe('rfc5424');
    expect(parseSecurityInput(raw).ok).toBe(true);
  });
  it('accepts escaped bracket and preserves raw RFC5424 SD without manufacturer decoding',()=>{
    const raw='<1>1 2026-10-17T12:34:56Z host app - - [meta value="safe\\]token" path="a\\\\b"] body';
    const out=source(raw,[['structured_data_raw','[meta value="safe\\]token" path="a\\\\b"]'],['message','body']]);
    expect(out.fields.some(f=>f.name==='value')).toBe(false);
  });
  it('abstains rather than guessing the meaning of an unrecognized SD escape',()=>{
    const raw='<1>1 - host app - - [meta value="a\\n"] payload';
    const observation=inspectGeneralSyslogEnvelope(raw);
    expect(observation.disposition).toBe('ABSTAIN_UNSAFE');
    expect(observation.reason).toBe('RFC5424_SD_UNCERTAIN_ESCAPED_VALUE');
  });
  it('abstains on repeated SD-ID and duplicate parameter ownership',()=>{
    for(const raw of [
      '<1>1 - host app - - [meta a="one"][meta b="two"] body',
      '<1>1 - host app - - [meta a="one" a="two"] body',
    ]){
      const out=inspectGeneralSyslogEnvelope(raw);
      expect(out.disposition).toBe('ABSTAIN_UNSAFE');
      expect(out.fields).toEqual([]);
    }
  });
  it('rejects malformed PRI/calendar/header and unknown transport',()=>{
    for(const raw of [
      '<192>1 2026-10-17T12:34:56Z host app - - - text',
      '<1>1 2026-02-30T12:34:56Z host app - - - text',
      '<1>1 2026-10-17T27:34:56Z host app - - - text',
      '<1>1 2026-10-17T12:34:56Z host app - - [meta k="unclosed] text',
      '<1>Oct 35 12:34:56 host app: text',
      'CEF:0|Example|Device|1|event|alert|1|src=192.0.2.4',
    ]){
      expect(inspectGeneralSyslogEnvelope(raw).disposition).not.toBe('REVIEW_ONLY');
    }
  });
  it('abstains when MSG could be a second physical PRI record',()=>{
    const raw='<1>1 2026-10-17T12:34:56Z h a - - - first\n<2>1 2026-10-17T12:34:57Z h a - - - second';
    const out=inspectGeneralSyslogEnvelope(raw);
    expect(out.disposition).toBe('ABSTAIN_UNSAFE');
    expect(out.reason).toBe('AMBIGUOUS_MULTIRECORD_SYSLOG_MSG');
  });
  it('bounds malformed Unicode, empty bytes and oversized sources',()=>{
    for(const raw of ['', '<1>1 - host app - - - '+('x'.repeat(8200)),
      '<1>1 - host app - - - '+String.fromCharCode(0xd800)]){
      const out=inspectGeneralSyslogEnvelope(raw);
      expect(out.disposition).not.toBe('REVIEW_ONLY');
      expect(out.autoPromoted).toBe(false);
    }
  });
});
