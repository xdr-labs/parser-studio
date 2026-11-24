import {expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {residualRegionsFor} from './AutoParserAIReview';

// Independent audit S-1 of 240b2e6: exact Multi-Pass byte ranges that do not fit the candidate's event must not be
// replaced by a left-to-right search, which can land on an earlier, already parsed copy of the same text.
const suiteOf=(raw:string)=>({events:[{raw}]}) as unknown as SuiteResult;
it('keeps exact residual ranges that hold the residual text',()=>{
 expect(residualRegionsFor(suiteOf('alice login alice'),[['alice']],[[{startByte:12,endByte:17}]]))
  .toEqual([[{startByte:12,endByte:17}]]);
});
it('gives no regions when exact ranges do not fit the candidate event, so the strict whole-value rule applies',()=>{
 expect(residualRegionsFor(suiteOf('alice logout alice'),[['alice']],[[{startByte:12,endByte:17}]])).toEqual([[]]);
});
it('locates texts only when no exact ranges exist',()=>{
 expect(residualRegionsFor(suiteOf('alice logout alice'),[['alice']])).toEqual([[{startByte:0,endByte:5}]]);
});
