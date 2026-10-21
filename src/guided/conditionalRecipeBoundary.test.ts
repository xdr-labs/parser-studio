import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {planReviewedEventFamilyDraft} from './reviewedEventFamilyDraft';
import {buildReviewableRecipe} from './parserRecipeV2';

describe('conditional parser source-to-recipe boundary',()=>{
  const source=[
    '{"event_type":"threat","src_ip":"192.0.2.10","action":"deny"}',
    '{"event_type":"user","username":"redacted-user","action":"login"}',
    '{"event_type":"asset","hostname":"example-host","action":"discovered"}',
  ].join('\n');
  it('refuses v0.2 recipe projection before conditional mappings can silently disappear',async()=>{
    const draft={...createDraft(),format:'json' as const};
    const base=preview(source,draft);
    const reviewed=planReviewedEventFamilyDraft(base,draft,'event_type');
    expect(reviewed.ok).toBe(true);
    if(!reviewed.ok)return;
    const result=await buildReviewableRecipe(source,reviewed.candidate,preview(source,reviewed.candidate));
    expect(result.ok).toBe(false);
    if(!result.ok)expect(result.reason).toBe('COMPILER_UNSUPPORTED');
  });
});
