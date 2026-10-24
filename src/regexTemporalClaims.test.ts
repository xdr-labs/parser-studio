import {describe,expect,it} from 'vitest';
import {createDraft} from './model';
import {extractFields} from './parser';
import {validateConventionalTemporalCaptures} from './regexTemporalClaims';

const pattern=String.raw`^\[(?<month_day>\d{2}\.\d{2}) (?<clock>\d{2}:\d{2}:\d{2})\] (?<application>[A-Za-z.]+) - (?<message>.+)$`;
const record=(monthDay:string,clock:string)=>
  `[${monthDay} ${clock}] chrome.exe - proxy opened`;
const draft={...createDraft(),format:'regex' as const,pattern};

describe('bounded explicit temporal names in reviewed regex captures',()=>{
  it.each([
    ['10.30','16:49:06'],
    ['02.29','23:59:59'],
    ['02.28','00:00:00'],
    ['04.30','12:00:60'],
  ])('keeps source supported month_day %s and clock %s without inventing timezone', (day,clock)=>{
    const parsed=extractFields(record(day,clock),'regex',draft);
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields).toMatchObject({month_day:day,clock});
    expect(parsed.fields).not.toHaveProperty('year');
    expect(parsed.fields).not.toHaveProperty('timezone');
  });

  it.each([
    ['13.30','16:49:06'],['00.30','16:49:06'],['02.31','16:49:06'],
    ['04.31','16:49:06'],['10.00','16:49:06'],['10.30','25:49:06'],
    ['10.30','16:60:06'],['10.30','16:49:66'],
  ])('rejects impossible named calendar values %s %s even if the regex matched',(day,clock)=>{
    const parsed=extractFields(record(day,clock),'regex',draft);
    expect(parsed.fields).toEqual({});
    expect(parsed.errors).toMatchObject([expect.stringMatching(/Invalid (month_day|clock) capture/)]);
  });

  it('supports optional clock subsecond without requiring a year or timezone',()=>{
    const fields={month_day:'03-17',clock:'16:13:38.811'};
    expect(validateConventionalTemporalCaptures(fields)).toBeNull();
    expect(validateConventionalTemporalCaptures({clock:'23:59:59.123456789'})).toBeNull();
    expect(validateConventionalTemporalCaptures({clock:'23:59:59.1234567890'})).toMatch('Invalid clock');
  });

  it('never claims temporal semantics from unrelated field names',()=>{
    const parsed=extractFields('code=25:99:99','regex',{
      ...createDraft(),format:'regex',pattern:String.raw`^code=(?<code>.+)$`,
    });
    expect(parsed.errors).toEqual([]);
    expect(parsed.fields).toEqual({code:'25:99:99'});
  });
});
