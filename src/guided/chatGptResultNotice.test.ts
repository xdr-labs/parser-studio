import {describe,it,expect} from 'vitest';
import {describeNonJsonReply,describeRejectedReply,COPY_DAMAGE_HINT} from './chatGptResultNotice';

describe('ChatGPT result notices',()=>{
  it('shows ChatGPT\'s own REVIEW_REQUIRED reason to the user',()=>{
    const r=describeNonJsonReply('REVIEW_REQUIRED: The sample has no timezone, so the timestamp cannot be typed.\nPlease add it.');
    expect(r.diagnostic).toBe('REVIEW_REQUIRED');
    expect(r.notice).toContain('The sample has no timezone, so the timestamp cannot be typed.');
    expect(r.notice).toContain('Please add it.');
    expect(r.notice).toMatch(/No rules were applied/);
    expect(r.notice).toContain('diagnosis, not a parser recipe');
  });

  it('caps a very long REVIEW_REQUIRED explanation and keeps it plain text',()=>{
    const r=describeNonJsonReply('REVIEW_REQUIRED: '+'x'.repeat(5000));
    expect(r.notice.length).toBeLessThan(1200);
    expect(r.notice).toMatch(/…/);
  });

  it('uses the generic message for other non-JSON prose',()=>{
    const r=describeNonJsonReply('Sure! Here is how I would parse it.');
    expect(r.diagnostic).toBe('NOT_JSON');
    expect(r.notice).toMatch(/not a parser recipe/);
    expect(r.notice).not.toContain('Sure!');
  });

  it('hints at copy damage when the JSON could not be read',()=>{
    expect(describeRejectedReply('INVALID_JSON')).toContain(COPY_DAMAGE_HINT);
    expect(describeRejectedReply('INVALID_JSON')).toMatch(/copy button/);
  });

  it('does not blame copying for other rejection reasons',()=>{
    expect(describeRejectedReply('RECIPE_UNSUPPORTED')).not.toContain(COPY_DAMAGE_HINT);
    expect(describeRejectedReply('RECIPE_UNSUPPORTED')).toContain('RECIPE_UNSUPPORTED');
  });
});
