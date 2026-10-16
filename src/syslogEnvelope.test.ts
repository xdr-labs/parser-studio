import {describe,expect,it} from 'vitest';
import {parseSyslogEnvelope} from './syslogEnvelope';
import {SYSLOG_POC_NEGATIVE,SYSLOG_POC_POSITIVE} from './syslogPocCorpus';

describe('syslog envelope foundation PoC',()=>{
  it.each(SYSLOG_POC_POSITIVE)('parses $id',sample=>{
    const parsed=parseSyslogEnvelope(sample.raw);
    expect(parsed,sample.id).not.toBeNull();
    if(!parsed)return;
    if(sample.expectedPri!==undefined)expect(parsed.pri).toBe(sample.expectedPri);
    if(sample.expectedHost!==undefined)expect(parsed.hostname).toBe(sample.expectedHost);
    expect(parsed.message.length,sample.id).toBeGreaterThan(0);
  });

  it.each(SYSLOG_POC_NEGATIVE.map((raw,index)=>({raw,index})))(
    'rejects malformed input $index',
    ({raw})=>{
      expect(parseSyslogEnvelope(raw)).toBeNull();
    },
  );

  it('decomposes PRI without guessing vendor semantics',()=>{
    const parsed=parseSyslogEnvelope('<134>Oct 16 15:44:21 edge app: hello');
    expect(parsed).toMatchObject({pri:'134',facility:16,severity:6,hostname:'edge',appname:'app',message:'hello'});
  });

  it('keeps RFC5424 structured data separate from the message',()=>{
    const raw='<34>1 2026-10-16T15:44:21Z host app 123 ID47 [meta@32473 k="v"] payload';
    expect(parseSyslogEnvelope(raw)).toMatchObject({
      variant:'rfc5424',hostname:'host',appname:'app',procid:'123',msgid:'ID47',
      structuredData:'[meta@32473 k="v"]',message:'payload',
    });
  });
});
