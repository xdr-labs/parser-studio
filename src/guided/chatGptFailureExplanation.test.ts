import {describe,expect,it} from 'vitest';
import {explainRejectedChatGPTFix} from './chatGptFailureExplanation';

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
