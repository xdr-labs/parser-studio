import {describe,expect,it} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {selectDraftFormat} from './draftFormatTransition';
import {prepareAutoParserDraft} from './autoParserDraft';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import type {BackendCapabilities} from './backendCapabilities';
import {toBackendProject} from './backendAdapter';
import {validLocalDraft} from './localWorkspaceHistory';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {buildReviewableRecipe} from './parserRecipeV2';
import {importRecoveryAIRecipe,proposeV01RecoveryParserFromAI} from './aiRecipeExchange';
import profileFixture from '../../tests/fixtures/roadmap-syslog-prefix-kv-20261020.json';

const profiled=()=>({...createDraft(),format:'generic_structural' as const,
  genericStructuralProfile:'syslog_prefix_kv' as const});

describe('explicit parser format transitions',()=>{
  it('retires a generic profile when choosing CSV without mutating the previous draft',()=>{
    const original={...profiled(),csvColumns:'action,src_ip,dst_port'};
    const selected=selectDraftFormat(original,'csv');
    expect(selected.format).toBe('csv');
    expect(selected).not.toHaveProperty('genericStructuralProfile');
    expect(selected.mappings).toEqual(original.mappings);
    expect(selected.csvColumns).toBe(original.csvColumns);
    expect(original.genericStructuralProfile).toBe('syslog_prefix_kv');
    expect(validLocalDraft(selected)).toBe(true);
    expect(toBackendProject(selected).ok).toBe(true);
    const incompatible={...original,format:'csv' as const};
    expect(validLocalDraft(incompatible)).toBe(false);
    expect(toBackendProject(incompatible).ok).toBe(false);
  });

  it('keeps the selected profile when the Generic Structural format remains selected',()=>{
    const original=profiled();
    const selected=selectDraftFormat(original,'generic_structural');
    expect(selected).toEqual(original);
    expect(selected).not.toBe(original);
    expect(validLocalDraft(selected)).toBe(true);
  });

  it('prepares a newly reviewed JSON parser without carrying the earlier generic grammar',()=>{
    const source='{"action":"allow","src_ip":"192.0.2.10","dst_port":443}';
    const original=profiled();
    const ledger=analyzeLogEnvelopes(source,'single-line');
    const cap={authoring:{extractionFormats:['json']},
      verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
    const result=prepareAutoParserDraft(source,original,preview(source,createDraft()),
      ledger,assessEnvelopeCompilation(ledger,cap));
    expect(result.ok).toBe(true);
    if(!result.ok)throw new Error('JSON transition was not prepared');
    expect(result.draft.format).toBe('json');
    expect(result.draft).not.toHaveProperty('genericStructuralProfile');
    expect(toBackendProject(result.draft).ok).toBe(true);
    expect(validLocalDraft(result.draft)).toBe(true);
    expect(original.genericStructuralProfile).toBe('syslog_prefix_kv');
  });

  it('uses the approved CSV recovery grammar without inheriting the previous profile',async()=>{
    const source='allow,192.0.2.10,443\ndeny,198.51.100.20,8443';
    const target={...createDraft(),format:'csv' as const,csvColumns:'action,src_ip,dst_port'};
    const built=await buildReviewableRecipe(source,target,preview(source,target));
    if(!built.ok)throw new Error('CSV recovery recipe was not prepared');
    const original=profiled();
    const imported=await importRecoveryAIRecipe(JSON.stringify(built.recipe),source,
      original,preview(source,original));
    const proposed=proposeV01RecoveryParserFromAI(imported,original);
    expect(proposed).toMatchObject({ok:true,approvalRequired:true,backendCompilerVerified:false});
    if(!proposed.ok)throw new Error('CSV recovery transition was not prepared');
    expect(proposed.candidate).not.toHaveProperty('genericStructuralProfile');
    expect(proposed.candidate.format).toBe('csv');
    expect(preview(source,proposed.candidate).counts).toMatchObject({total:2,extracted:2,failures:0});
    expect(validLocalDraft(proposed.candidate)).toBe(true);
    expect(original.genericStructuralProfile).toBe('syslog_prefix_kv');
  });

  for(const [name,source,profile] of [
    ['explicit profile',profileFixture.positive[0]!.raw,'syslog_prefix_kv'],
    ['existing V15 grammar','<134>date=2023-02-23 time=22:49:29 type=event subtype=system status=success',undefined],
  ] as const){
    it('takes the '+name+' from a full recovery recipe instead of stale draft metadata',async()=>{
      const target=buildAutomaticGenericStructuralDraft(source,createDraft());
      if(!target)throw new Error('Generic recovery sample was not prepared');
      const built=await buildReviewableRecipe(source,target.draft,target.suite);
      if(!built.ok)throw new Error('Generic recovery recipe was not prepared');
      const original=profiled();
      const imported=await importRecoveryAIRecipe(JSON.stringify(built.recipe),source,
        original,preview(source,original));
      const proposed=proposeV01RecoveryParserFromAI(imported,original);
      expect(proposed.ok).toBe(true);
      if(!proposed.ok)throw new Error('Generic recovery transition was not prepared');
      expect(proposed.candidate.genericStructuralProfile).toBe(profile);
      const rebuilt=await buildReviewableRecipe(source,proposed.candidate,preview(source,proposed.candidate));
      expect(rebuilt.ok).toBe(true);
      if(rebuilt.ok)expect(rebuilt.recipe).toEqual(built.recipe);
      expect(original.genericStructuralProfile).toBe('syslog_prefix_kv');
    });
  }
});
