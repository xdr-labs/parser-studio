import {beforeEach,afterEach,describe,expect,it,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {toBackendProject} from './backendAdapter';
import {loadStarterTemplate} from './sampleTemplates';
import {buildReviewableRecipe,validateReviewableRecipe} from './parserRecipeDraft';

const source=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443}',
  '{"action":"deny","src_ip":"203.0.113.5","dst_port":22}',
].join('\n');

describe('AP3 v0.1 metadata compatibility preserved by canonical v0.2 UI review',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());
  it('produces a deterministic staged recipe and retains the exact unchanged v0.1 backend project alongside it',async()=>{
    const draft=createDraft();draft.format='json';
    const suite=preview(source,draft);
    const first=await buildReviewableRecipe(source,draft,suite);
    const second=await buildReviewableRecipe(source,draft,suite);
    expect(first).toEqual(second);
    if(!first.ok)throw new Error('Expected the supported sample to produce a recipe');
    expect(first.recipe.compilerMode).toBe('REVIEW_ONLY');
    expect(first.recipe.bodyFormat).toBe('json');
    const old=toBackendProject(draft);
    expect(old.ok).toBe(true);
    if(!old.ok)return;
    expect(first.legacyProject).toEqual(old.project);
    expect(first.lossReport).toEqual({
      status:'V01_SNAPSHOT_PRESERVED',lossyOperations:0,
      v02CompilerAvailable:false,nativeUserParserVerified:false,
      targetImportVerified:false,rawLogIncluded:false,
    });
    expect(JSON.stringify(first.recipe)).not.toContain('198.51.100.10');
    expect(JSON.stringify(first.recipe)).not.toContain('203.0.113.5');
  });
  it('represents both RFC5424-embedded CEF and LEEF without granting native compiler support',async()=>{
    for(const family of ['rfc5424_cef','rfc5424_leef'] as const){
      const item=loadStarterTemplate(family);
      const review=await buildReviewableRecipe(item.sample,item.draft,preview(item.sample,item.draft));
      expect(review.ok).toBe(true);
      if(!review.ok)continue;
      expect(review.recipe.sourceFormat).toBe('syslog_rfc5424');
      expect(review.recipe.bodyFormat).toBe(family==='rfc5424_cef'?'cef':'leef');
      expect(review.recipe.stages.slice(0,3).map(x=>x.op)).toEqual([
        'split_event','unwrap_syslog',family==='rfc5424_cef'?'parse_cef':'parse_leef',
      ]);
      expect(review.v02CompilerAvailable).toBe(false);
      expect(review.recipe.nativeVerified).toBe(false);
    }
  });
  it('preserves reviewed RFC5424 JSON and quoted-KV body stages without native verification claims',async()=>{
    const base=loadStarterTemplate('syslog_rfc5424');
    for(const [body,content] of [
      ['json','{"action":"allow","src_ip":"198.51.100.10","dst_port":443}'],
      ['kv','action="allow access" src_ip=198.51.100.10 dst_port=443'],
    ] as const){
      const draft={...base.draft,syslogBodyFormat:body};
      const input='<165>1 2026-10-12T00:00:00Z demo-fw security 12 EV01 - '+content;
      const result=await buildReviewableRecipe(input,draft,preview(input,draft));
      expect(result.ok).toBe(true);
      if(!result.ok)continue;
      expect(result.recipe.bodyFormat).toBe(body);
      expect(result.recipe.stages.slice(0,3).map(x=>x.op)).toEqual([
        'split_event','unwrap_syslog','parse_'+body,
      ]);
      expect(result.recipe.nativeVerified).toBe(false);
    }
  });
  it('keeps reviewed field types and classifications and rejects changes to ordered body semantics',async()=>{
    const draft=createDraft();draft.format='json';
    draft.mappings.push({id:'when',source:'event_time',target:'custom.event_time',type:'timestamp'});
    const event=source.split('\n').map(raw=>{
      const value=JSON.parse(raw) as Record<string,unknown>;
      return JSON.stringify({...value,event_time:'2026-10-12T00:00:00Z'});
    }).join('\n');
    const review=await buildReviewableRecipe(event,draft,preview(event,draft));
    expect(review.ok).toBe(true);
    if(!review.ok)return;
    expect(review.recipe.stages).toContainEqual({op:'cast_type',target:'custom.event_time',
      data_type:'date',timezone:'UTC'});
    expect(review.recipe.stages.find(x=>x.op==='classify')).toMatchObject({
      op:'classify',defaultIndex:'syslog',rules:[{operator:'equals'},{operator:'equals'}],
    });
    expect(validateReviewableRecipe({...review.recipe,bodyFormat:'cef'})).toBe(false);
    expect(validateReviewableRecipe({...review.recipe,stages:[
      ...review.recipe.stages.slice(0,1),{op:'parse_leef'},...review.recipe.stages.slice(2),
    ]})).toBe(false);
  });
  it('rejects injected operators, unbounded stages and forged native or target flags',async()=>{
    const draft=createDraft();draft.format='json';
    const review=await buildReviewableRecipe(source,draft,preview(source,draft));
    if(!review.ok)throw new Error('Expected supported recipe');
    const stages=review.recipe.stages;
    for(const candidate of [
      {...review.recipe,nativeVerified:true},
      {...review.recipe,targetVerified:true},
      {...review.recipe,script:'require("net/http")'},
      {...review.recipe,stages:[...stages.slice(0,-1),{op:'exec_ruby',code:'system("curl")'},stages.at(-1)]},
      {...review.recipe,stages:[...stages,...Array(140).fill({op:'fallback_unparsed',mode:'retain_unparsed'})]},
    ])expect(validateReviewableRecipe(candidate)).toBe(false);
  });
  it('blocks edited unsafe paths and unmatched browser input rather than claiming a compatible recipe',async()=>{
    const draft=createDraft();draft.format='json';
    draft.mappings[0]!.source='constructor.secret';
    expect(await buildReviewableRecipe(source,draft,preview(source,draft)))
      .toMatchObject({ok:false,reason:'MODEL_REVIEW_REQUIRED'});
    const original=createDraft();original.format='json';
    expect(await buildReviewableRecipe(source+'\nunsupported',original,preview(source,original)))
      .toMatchObject({ok:false,reason:'SAMPLE_MISMATCH'});
  });
});
