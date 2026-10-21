import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {webcrypto} from 'node:crypto';
import {composeChatGPTPrompt} from './chatGptPromptBuilder';
import {buildReviewableRecipe} from './parserRecipeV2';
import {createDraft} from '../model';
import {preview} from '../parser';

describe('ChatGPT Assisted reviewed prompt identity',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());
  const digest='a'.repeat(64);
  const examples='action="blocked" src=192.0.2.10\n action="allowed" src=198.51.100.20';
  const unavailable={ok:false,reason:'COMPILER_UNSUPPORTED'} as const;

  it('never puts a null project refusal or unrelated demonstration log in a recovery request',()=>{
    const prompt=composeChatGPTPrompt({
      goal:'Preserve action and source IP',source:examples,
      projectId:'draft-demo_firewall',sourceHash:digest,sourceCount:2,
      baseline:unavailable,
    });
    expect(prompt).toContain('FULL_RECOVERY');
    expect(prompt).toContain('draft-demo_firewall');
    expect(prompt).toContain(examples);
    expect(prompt).toContain('BEGIN ORIGINAL LOG SOURCE');
    expect(prompt).toContain('REVIEW_REQUIRED:');
    expect(prompt).not.toContain('projectId: null');
    expect(prompt).not.toContain('If projectId is null');
    expect(prompt).not.toContain('EXAMPLE-FW');
    expect(prompt).toContain(digest);
  });

  it('uses a real validated baseline and never invents a project ID',async()=>{
    const source='{"action":"allow","src_ip":"192.0.2.1"}';
    const draft={...createDraft(),format:'json' as const};
    const baseline=await buildReviewableRecipe(source,draft,preview(source,draft));
    expect(baseline.ok).toBe(true);
    if(!baseline.ok)return;
    const prompt=composeChatGPTPrompt({
      goal:'Keep source fields',source:'{"action":"allow","src_ip":"192.0.2.2"}',
      projectId:baseline.recipe.projectId,sourceHash:baseline.recipe.sample.sha256,
      sourceCount:baseline.recipe.sample.events,baseline,
    });
    expect(prompt).toContain('VALIDATED BASELINE RECIPE');
    expect(prompt).toContain(baseline.recipe.projectId);
    expect(prompt).not.toContain('FULL_RECOVERY');
    expect(prompt).not.toContain('projectId: null');
  });

  it('rejects mismatched project identity and empty source',async()=>{
    const source='{"action":"allow","src_ip":"192.0.2.1"}';
    const draft={...createDraft(),format:'json' as const};
    const baseline=await buildReviewableRecipe(source,draft,preview(source,draft));
    expect(baseline.ok).toBe(true);
    if(!baseline.ok)return;
    expect(()=>composeChatGPTPrompt({
      goal:'Preserve action',source:'{"action":"allow"}',
      projectId:'draft-different_source',sourceHash:digest,sourceCount:1,baseline,
    })).toThrow('PROJECT_IDENTITY_MISMATCH');
    expect(()=>composeChatGPTPrompt({
      goal:'Preserve action',source:'',projectId:'draft-demo_firewall',
      sourceHash:digest,sourceCount:1,baseline:unavailable,
    })).toThrow('INVALID_REVIEWED_PROMPT_CONTEXT');
  });
});
