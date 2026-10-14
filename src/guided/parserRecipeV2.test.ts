import {describe,it,expect,vi,beforeEach,afterEach} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {loadStarterTemplate} from './sampleTemplates';
import {buildReviewableRecipe,validateReviewableRecipe} from './parserRecipeV2';

const sample=[
  '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"username":"PRIVATE_USER"}',
  '{"action":"deny","src_ip":"203.0.113.4","dst_port":22,"username":"PRIVATE_ACCOUNT"}',
].join('\n');
const build=(text=sample,draft:ParserDraft=createDraft())=>buildReviewableRecipe(text,draft,preview(text,draft));

describe('P0-AP3 target-independent ParserRecipe v0.2 review-only contract',()=>{
  beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
  afterEach(()=>vi.unstubAllGlobals());
  it('creates bounded ordered stages from the exact current v0.1 draft without executing or uploading logs',async()=>{
    const draft=createDraft();draft.format='json';
    const result=await build(sample,draft);
    expect(result).toMatchObject({ok:true});
    if(!result.ok)return;
    expect(result.recipe.contract).toBe('parser-studio.recipe.v0.2');
    expect(result.recipe.schemaRevision).toBe('0.2');
    expect(result.recipe.sample.sha256).toMatch(/^[0-9a-f]{64}$/);
    expect(result.recipe.sample.events).toBe(2);
    expect(result.recipe.stages.map(x=>x.op)).toEqual([
      'split_event','parse_json','map_field','cast_type',
      'map_field','cast_type','map_field','classify','fallback_unparsed',
    ]);
    expect(result.recipe.nativeVerified).toBe(false);
    expect(result.recipe.targetVerified).toBe(false);
    expect(result.compatibility).toBe('V01_METADATA_ROUNDTRIP');
    expect(result.v02CompilerAvailable).toBe(false);
    expect(result.legacyProject.extraction).toEqual({format:'json'});
    expect(result.recipe.stages.at(-1)).toEqual({op:'fallback_unparsed',mode:'retain_unparsed'});
    expect(validateReviewableRecipe(result.recipe)).toBe(true);
    const encoded=JSON.stringify(result.recipe);
    for(const secret of ['198.51.100.10','203.0.113.4','PRIVATE_USER','PRIVATE_ACCOUNT'])
      expect(encoded).not.toContain(secret);
  });
  it('preserves explicit edited paths and classifications instead of rewriting rules',async()=>{
    const draft=createDraft();draft.format='kv';
    draft.mappings[0]!.target='custom.audit_source_ip';
    const result=await build(
      'action=allow src_ip=198.51.100.10 dst_port=443\naction=deny src_ip=203.0.113.4 dst_port=22',
      draft);
    expect(result.ok).toBe(true);
    if(!result.ok)return;
    expect(result.recipe.stages.some(x=>x.op==='map_field'&&x.target==='custom.audit_source_ip')).toBe(true);
    expect(result.legacyProject.normalization.topFields.src_ip.normalized_name).toBe('custom.audit_source_ip');
    expect(result.recipe.stages.find(x=>x.op==='classify')).toMatchObject({
      op:'classify',defaultIndex:'syslog',rules:[{operator:'equals'},{operator:'equals'}],
    });
  });
  it('round-trips bounded split and merge stages before classification',async()=>{
    const draft=createDraft();draft.format='json';
    draft.mappings=[...draft.mappings,{id:'endpoint',source:'endpoint',target:'custom.endpoint',type:'string'}];
    const opts=draft.guided!;
    draft.guided={...opts,groups:{...opts.groups,endpoint:'top_fields'},enrichment:[
      {id:'split',operator:'split_field',source:'custom.endpoint',target:'',value:'',delimiter:':',
        targets:['custom.endpoint_host','custom.endpoint_port_text']},
      {id:'merge',operator:'merge_fields',source:'',target:'custom.endpoint_joined',value:'',delimiter:':',
        sources:['custom.endpoint_host','custom.endpoint_port_text']},
    ]};
    const text=[
      '{"action":"allow","src_ip":"198.51.100.10","dst_port":443,"endpoint":"192.0.2.10:8443"}',
      '{"action":"deny","src_ip":"203.0.113.4","dst_port":22,"endpoint":"192.0.2.11:2222"}',
    ].join('\n');
    const result=await build(text,draft);expect(result.ok).toBe(true);
    if(!result.ok)return;
    const ops=result.recipe.stages.map(x=>x.op);
    expect(ops.indexOf('split_field')).toBeGreaterThan(ops.lastIndexOf('map_field'));
    expect(ops.indexOf('merge_fields')).toBe(ops.indexOf('split_field')+1);
    expect(ops.indexOf('classify')).toBe(ops.indexOf('merge_fields')+1);
    expect(validateReviewableRecipe(result.recipe)).toBe(true);
    const split=result.recipe.stages.find(x=>x.op==='split_field');
    expect(split).toEqual({op:'split_field',source:'custom.endpoint',delimiter:':',
      targets:['custom.endpoint_host','custom.endpoint_port_text']});
    const bad={...result.recipe,stages:result.recipe.stages.map(x=>x.op==='split_field'?{...x,delimiter:'\n'}:x)};
    expect(validateReviewableRecipe(bad)).toBe(false);
  });

  it('adds explicit RFC5424 unwrap before CEF body parsing only when native scope is unverified',async()=>{
    const fixture=loadStarterTemplate('rfc5424_cef');
    const result=await build(fixture.sample,fixture.draft);
    expect(result).toMatchObject({ok:true});
    if(!result.ok)return;
    expect(result.recipe.stages.slice(0,3).map(x=>x.op)).toEqual([
      'split_event','unwrap_syslog','parse_cef',
    ]);
    expect(result.recipe.stages.find(x=>x.op==='unwrap_syslog')).toEqual({
      op:'unwrap_syslog',version:1,mode:'strict_header',
    });
    expect(result.v02CompilerAvailable).toBe(false);
    expect(JSON.stringify(result.recipe)).not.toContain('198.51.100.10');
  });
  it('rejects unsupported, mixed or stale original source instead of producing a staged recipe',async()=>{
    expect(await build('{"event":"test"}\nCEF:0|Example|partial')).toMatchObject({
      ok:false,reason:'SAMPLE_PREVIEW_INCOMPLETE'});
    const draft=createDraft();draft.format='json';
    const stale=preview(sample,draft);
    expect(await buildReviewableRecipe('{"event":"changed"}',draft,stale))
      .toMatchObject({ok:false,reason:'SAMPLE_MISMATCH'});
    const ambiguous={...draft,format:'auto' as const};
    expect(await buildReviewableRecipe(sample,ambiguous,preview(sample,ambiguous)))
      .toMatchObject({ok:false,reason:'COMPILER_UNSUPPORTED'});
    const regex={...draft,format:'regex' as const};
    expect(await buildReviewableRecipe(sample,regex,preview(sample,regex)))
      .toMatchObject({ok:false});
  });
  it('rejects untrusted prototype injection, forged verification flags and unsupported stages',async()=>{
    const draft=createDraft();draft.format='json';
    const r=await build(sample,draft);
    expect(r.ok).toBe(true);
    if(!r.ok)return;
    expect(validateReviewableRecipe({...r.recipe,nativeVerified:true})).toBe(false);
    expect(validateReviewableRecipe({...r.recipe,stages:[
      ...r.recipe.stages.slice(0,-1),{op:'execute_ruby',source:'eval(user_input)'},r.recipe.stages.at(-1),
    ]})).toBe(false);
    expect(validateReviewableRecipe({...r.recipe,stages:[
      ...r.recipe.stages,{op:'fallback_unparsed',mode:'retain_unparsed'},
    ]})).toBe(false);
    const unsafe=createDraft();unsafe.format='json';
    unsafe.mappings[0]!.source='__proto__.secret';
    expect(await build(sample,unsafe)).toMatchObject({ok:false,reason:'MODEL_REVIEW_REQUIRED'});
  });
  it('blocks sample beyond 64 KiB and 500 events without emitting customer data',async()=>{
    const draft=createDraft();draft.format='json';
    expect(await buildReviewableRecipe(sample.repeat(500),draft,undefined))
      .toMatchObject({ok:false,reason:'SOURCE_LIMIT'});
    expect(await buildReviewableRecipe('',draft,undefined)).toMatchObject({
      ok:false,reason:'SOURCE_LIMIT'});
  });
});
