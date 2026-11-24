import {expect,it} from 'vitest';
import type {SuiteResult} from '../model';
import {protectedResidualRegression,residualRegionsFor} from './AutoParserAIReview';
import {RESIDUAL_PROVENANCE_CONTRACT} from './residualProvenance';

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

// Re-audit F-1 of 4c04b0b: Multi-Pass ranges are relative to its frame, which starts after a UTF-8 BOM and leading
// blanks; the candidate's event keeps them.
it('shifts exact ranges past the leading blanks and BOM that Multi-Pass framing skips',()=>{
 expect(residualRegionsFor(suiteOf('  alice login alice'),[['alice']],[[{startByte:12,endByte:17}]]))
  .toEqual([[{startByte:14,endByte:19}]]);
 expect(residualRegionsFor(suiteOf('﻿alice login alice'),[['alice']],[[{startByte:12,endByte:17}]]))
  .toEqual([[{startByte:15,endByte:20}]]);
});
it('refuses a regex candidate whose residual evidence is missing instead of using the substring rule',()=>{
 const suite={events:[{raw:'status=ok result=ok',normalized:{status:'ok'}}]} as unknown as SuiteResult;
 expect(protectedResidualRegression(suite,[['ok']],null)).toBeNull();
 expect(protectedResidualRegression(suite,[['ok']],{contract:RESIDUAL_PROVENANCE_CONTRACT,events:[]}))
  .toEqual({event:1,missing:1,required:1});
 expect(protectedResidualRegression(suite,[['ok']],{contract:RESIDUAL_PROVENANCE_CONTRACT,
  events:[{event:0,method:'unavailable',required:1,missing:0,reason:'NO_MATCH'}]})).toEqual({event:1,missing:1,required:1});
 expect(protectedResidualRegression(suite,[['ok']],{contract:RESIDUAL_PROVENANCE_CONTRACT,
  events:[{event:0,method:'capture_spans',required:1,missing:0}]})).toBeNull();
});
