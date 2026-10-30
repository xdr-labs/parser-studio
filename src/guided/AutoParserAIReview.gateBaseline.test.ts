import {describe,expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {protectedValueRegression} from './AutoParserAIReview';

// Minimal SuiteResult stand-in: the gate only reads events[].fields / .normalized.
const suite=(...events:Array<{fields:Record<string,unknown>;normalized?:Record<string,unknown>}>)=>
 ({events:events.map(event=>({normalized:{},...event}))}) as unknown as SuiteResult;

describe('reviewed-value gate is relative to the current parser output',()=>{
 // RFC3164 header "Oct 29 10:00:00": the backend span evidence lists these three tokens,
 // but the current parser output never carries them as separate values.
 const observed=[['Oct','29','10:00:00','allow','198.51.100.10']];
 const baseline=suite({fields:{action:'allow',src_ip:'198.51.100.10'}});

 it('does not blame a candidate for values the current parser output never contained',()=>{
  const candidate=suite({fields:{action:'allow',src_ip:'198.51.100.10'}});
  expect(protectedValueRegression(candidate,observed,false,baseline)).toBeNull();
 });

 it('still rejects a candidate that drops a value the current parser output contained',()=>{
  const candidate=suite({fields:{action:'allow'}});
  expect(protectedValueRegression(candidate,observed,false,baseline))
   .toMatchObject({event:1,missing:1,required:2});
 });

 it('keeps the strict behaviour when no baseline is supplied',()=>{
  const candidate=suite({fields:{action:'allow',src_ip:'198.51.100.10'}});
  expect(protectedValueRegression(candidate,observed,false))
   .toMatchObject({event:1,missing:3,required:5});
 });

 it('keeps full recovery strict even with a baseline',()=>{
  const candidate=suite({fields:{},normalized:{action:'allow'}});
  expect(protectedValueRegression(candidate,observed,true,baseline))
   .toMatchObject({event:1});
 });
});
