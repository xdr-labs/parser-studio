import {describe,expect,it} from 'vitest';
import {explainRejectedChatGPTFix,originalLogsStillPass} from './chatGptFailureExplanation';

const counts=(overrides:Partial<{
 fieldRemovals:number;typeChanges:number;positiveAfter:number;
 sourceCount:number;regressions:number;
}>={})=>({
 fieldRemovals:0,typeChanges:0,positiveAfter:1,sourceCount:1,regressions:0,
 ...overrides,
});
describe('novice ChatGPT rejection details remain evidence based',()=>{
 it('shows original field loss before misleading generic parsing failure',()=>{
  const value=explainRejectedChatGPTFix({baseline:counts({fieldRemovals:2}),holdout:counts()});
  expect(value).toContain('remove 2 previously extracted original field path(s)');
  expect(value).not.toContain('192.0.2.');
 });
 it('distinguishes type changes and earlier passing regressions',()=>{
  expect(explainRejectedChatGPTFix({baseline:counts({typeChanges:1}),holdout:null}))
   .toContain('change 1 original field type(s)');
  expect(explainRejectedChatGPTFix({baseline:counts({regressions:3}),holdout:null}))
   .toContain('regress 3 previously passing original event(s)');
 });
 it('identifies unsupported original event structure',()=>{
  expect(explainRejectedChatGPTFix({baseline:counts({positiveAfter:0}),holdout:null}))
   .toContain('did not successfully parse every original event');
 });
 it('distinguishes field preservation on additional held-out logs',()=>{
  expect(explainRejectedChatGPTFix({baseline:counts(),holdout:counts({fieldRemovals:1})}))
   .toContain('additional examples');
  expect(explainRejectedChatGPTFix({baseline:counts(),holdout:counts({typeChanges:1})}))
   .toContain('field type(s)');
  expect(explainRejectedChatGPTFix({baseline:counts(),holdout:counts({positiveAfter:0})}))
   .toContain('additional test event');
 });
 it('uses a conservative fallback for unknown failed qualifications',()=>{
  expect(explainRejectedChatGPTFix({baseline:counts(),holdout:null}))
   .toContain('field-preservation checks');
 });
});

describe('additional-example rejection explains the real cause',()=>{
 const independence=(reason:'TOO_SMALL'|'TRAINING_OVERLAP'|'IDENTICAL_TO_TRAINING',
  extra:Partial<{trainingUnique:number;holdoutUnique:number;requiredUnique:number;overlapCount:number}>={})=>({
  ok:false as const,reason,trainingUnique:1,holdoutUnique:1,requiredUnique:2,overlapCount:0,...extra,
 });
 it('says the additional examples repeat the original sample',()=>{
  const value=explainRejectedChatGPTFix({baseline:counts(),holdout:null,
   holdoutIndependence:independence('IDENTICAL_TO_TRAINING',{overlapCount:1})});
  expect(value).toContain('same as the original sample');
  expect(value).not.toContain('field-preservation');
 });
 it('says how many additional examples overlap the original sample',()=>{
  const value=explainRejectedChatGPTFix({baseline:counts(),holdout:null,
   holdoutIndependence:independence('TRAINING_OVERLAP',{overlapCount:2,holdoutUnique:3,trainingUnique:4})});
  expect(value).toContain('2 additional example(s) also appear in the original sample');
 });
 it('tells the user how many different additional examples are needed',()=>{
  const value=explainRejectedChatGPTFix({baseline:counts(),holdout:null,
   holdoutIndependence:independence('TOO_SMALL',{holdoutUnique:1,requiredUnique:2})});
  expect(value).toContain('at least 2 different additional examples');
  expect(value).toContain('1 unique');
 });
 it('does not label original logs as failing when only the additional examples were rejected',()=>{
  expect(originalLogsStillPass({baseline:counts(),holdoutStatus:'REJECTED',acceptedWithoutRegression:false})).toBe(true);
  expect(originalLogsStillPass({baseline:counts({regressions:1}),holdoutStatus:'REJECTED',acceptedWithoutRegression:false})).toBe(false);
  expect(originalLogsStillPass({baseline:counts(),holdoutStatus:'TESTED',acceptedWithoutRegression:false})).toBe(false);
  expect(originalLogsStillPass({baseline:counts(),holdoutStatus:'TESTED',acceptedWithoutRegression:true})).toBe(true);
 });
});
