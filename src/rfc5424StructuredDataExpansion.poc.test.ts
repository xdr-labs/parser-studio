import {describe,expect,it} from 'vitest';
import {extractGenericStructural} from './genericStructural';
import {parseSyslogEnvelope} from './syslogEnvelope';

const cases=[
  '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 tenant="lab" action="block"] free text message',
  '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 tenant="lab"][origin ip="192.0.2.1"] free text message',
  '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 tag="a" tag="b"] free text message',
  '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 note="left\\]mid\\\"quote\\\\right"] free text message',
  '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 empty=""] free text message',
] as const;

describe('RFC5424 structured-data expansion PoC',()=>{
  it('measures extraction of SD-ID and SD-PARAM independent from free-text MSG',()=>{
    const rows=cases.map(raw=>{
      const envelope=parseSyslogEnvelope(raw);
      const parsed=extractGenericStructural(raw);
      const syslog=parsed.fields.syslog as {structured_data?:unknown}|undefined;
      return {
        envelope:envelope!==null,
        structured:parsed.errors.length===0&&syslog?.structured_data!==undefined,
      };
    });
    const summary={
      total:rows.length,
      envelope:rows.filter(row=>row.envelope).length,
      structured:rows.filter(row=>row.structured).length,
    };
    console.log('RFC5424_SD_EXPANSION '+JSON.stringify(summary));
    expect(summary.envelope).toBe(cases.length);
    expect(summary.structured).toBe(cases.length);
  });

  it('keeps malformed structured-data from becoming a structured success',()=>{
    const malformed=[
      '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [bad=id x="1"] text',
      '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 x="1"][meta@32473 y="2"] text',
      '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 x=noquote] text',
      '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 ="missing"] text',
      '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [__proto__ x="1"] text',
      '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [constructor x="1"] text',
      '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 constructor="bad"] text',
      '<134>1 2026-10-16T15:44:21Z edge01 app 123 EVENT [meta@32473 prototype="bad"] text',
    ];
    const structured=malformed.filter(raw=>{
      const parsed=extractGenericStructural(raw);
      return parsed.errors.length===0;
    });
    console.log('RFC5424_SD_MALFORMED_BASELINE '+JSON.stringify({total:malformed.length,structured}));
    expect(structured).toEqual([]);
  });

  it('preserves element identity, repeated params, and RFC5424 escapes',()=>{
    const first=extractGenericStructural(cases[0]);
    expect((first.fields.syslog as {structured_data?:Record<string,unknown>}).structured_data)
      .toMatchObject({'meta@32473':{tenant:'lab',action:'block'}});

    const repeated=extractGenericStructural(cases[2]);
    expect((repeated.fields.syslog as {structured_data?:Record<string,unknown>}).structured_data)
      .toMatchObject({'meta@32473':{tag:['a','b']}});

    const escaped=extractGenericStructural(cases[3]);
    expect((escaped.fields.syslog as {structured_data?:Record<string,{note?:string}>}).structured_data?.['meta@32473']?.note)
      .toBe('left]mid"quote\\right');
  });
});
