import {describe,expect,it} from 'vitest';
import {summarizeHoldoutFailures} from './chatGptAdaptiveRepair';

const failing=(line:number,raw:string)=>({
  line,raw,fields:{},normalized:{},
  diagnostics:['EXTRACTION_FAILED',...Array.from({length:13},()=> 'SOURCE_NOT_FOUND')].map(code=>({code})),
});

describe('independent-example failures sent with an improved ChatGPT prompt',()=>{
  it('keeps up to four failing examples, so one retry can fix every failing shape',()=>{
    const events=[1,2,3,4,5].map(n=>failing(n,'line '+n+' '+'x'.repeat(220)));
    const parsed=JSON.parse(summarizeHoldoutFailures(events)) as {sourceLine:number}[];
    expect(parsed.map(item=>item.sourceLine)).toEqual([1,2,3,4]);
  });

  it('counts repeated error codes instead of listing each one again',()=>{
    const parsed=JSON.parse(summarizeHoldoutFailures([failing(1,'a')])) as {errorCodes:string[]}[];
    expect(parsed[0]!.errorCodes).toEqual(['EXTRACTION_FAILED','SOURCE_NOT_FOUND x13']);
  });

  it('stays valid JSON inside the size budget and never cuts an example in half',()=>{
    const events=[1,2,3,4].map(n=>failing(n,'L'+n+' '+'y'.repeat(1500)));
    const text=summarizeHoldoutFailures(events,4096);
    expect(text.length).toBeLessThanOrEqual(4096);
    const parsed=JSON.parse(text) as {raw:string}[];
    expect(parsed.length).toBeGreaterThanOrEqual(1);
    expect(parsed.length).toBeLessThan(4);
    for(const item of parsed)expect(item.raw.length).toBe(1503);
  });

  it('still returns something usable when one example alone is larger than the budget',()=>{
    const text=summarizeHoldoutFailures([failing(1,'z'.repeat(20000))],4096);
    expect(text.length).toBeLessThanOrEqual(4096);
    const parsed=JSON.parse(text) as {sourceLine:number}[];
    expect(parsed[0]!.sourceLine).toBe(1);
  });
});
