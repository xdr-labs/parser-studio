import {describe,expect,it} from 'vitest';
import {createDraft,type EventResult} from '../model';
import {buildRobustnessVariants,compareRobustnessOutcome} from './robustnessChecks';

function baseEvent(raw:string,format:EventResult['effectiveFormat'],fields:Record<string,unknown>):EventResult{
  return {
    id:'event-1',line:1,raw,detected:{format,confidence:1,reason:'test'},
    effectiveFormat:format,fields,normalized:{srcip:'10.0.0.1',parserstudio_source:{...fields,source_raw:raw}},
    unmapped:[],matched:true,extracted:true,normalizedOk:true,status:'pass',diagnostics:[],
    trace:[],
  };
}

describe('automatic robustness variants',()=>{
  it('generates semantics-preserving JSON and simple KV variants',()=>{
    const draft=createDraft();
    const json=baseEvent('{"a":1,"b":2}','json',{a:1,b:2});
    const kv=baseEvent('a=1 b=2','kv',{a:'1',b:'2'});
    expect(buildRobustnessVariants([json],draft)).toEqual(expect.arrayContaining([
      expect.objectContaining({transformation:'JSON_KEY_ORDER',source:'{"b":2,"a":1}'}),
    ]));
    expect(buildRobustnessVariants([kv],draft)).toEqual(expect.arrayContaining([
      expect.objectContaining({transformation:'KV_TOKEN_ORDER',source:'b=2 a=1'}),
    ]));
  });

  it('generates safe CSV quoting for a PAN-OS Syslog body',()=>{
    const raw='<14>Oct 15 00:03:21 PA-FW01 1,2026/10/15 00:03:21,012345678901,TRAFFIC,end';
    const event=baseEvent(raw,'generic_structural',{
      syslog:{pri:'14'},generic:{mode:'panos_traffic_csv'},
    });
    const variants=buildRobustnessVariants([event],createDraft());
    expect(variants.some(item=>item.transformation==='CSV_SAFE_QUOTING'&&
      item.source.includes(',"TRAFFIC",'))).toBe(true);
  });

  it('toggles only RFC3164 one-digit day spacing',()=>{
    const raw='<14>Oct  5 00:03:21 host app: message';
    const event=baseEvent(raw,'generic_structural',{syslog:{day:'5'}});
    const variant=buildRobustnessVariants([event],createDraft())
      .find(item=>item.transformation==='RFC3164_DAY_SPACING');
    expect(variant?.source).toBe('<14>Oct 5 00:03:21 host app: message');
  });

  it('compares normalized output while ignoring preserved raw-source copies',()=>{
    const original=baseEvent('{"a":1,"b":2}','json',{a:1,b:2});
    const variant=buildRobustnessVariants([original],createDraft())[0]!;
    const mutated={...original,raw:variant.source,
      normalized:{srcip:'10.0.0.1',parserstudio_source:{a:1,b:2,source_raw:variant.source}}};
    expect(compareRobustnessOutcome(variant,original,mutated)).toMatchObject({
      passed:true,reason:'SAME_NORMALIZED_OUTPUT',
    });
    const changed={...mutated,normalized:{srcip:'10.0.0.2'}};
    expect(compareRobustnessOutcome(variant,original,changed)).toMatchObject({
      passed:false,reason:'OUTPUT_CHANGED',
    });
  });
});
