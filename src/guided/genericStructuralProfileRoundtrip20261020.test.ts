import {it,expect} from 'vitest';
import fixture from '../../tests/fixtures/roadmap-syslog-prefix-kv-20261020.json';
import leefFixture from '../../tests/fixtures/roadmap-leef2-implicit-tab-20261020.json';
import {createDraft,type ParserDraft} from '../model';
import {buildAutomaticGenericStructuralDraft} from './genericStructuralAutoDraft';
import {toBackendProject} from './backendAdapter';
import {buildReviewableRecipe,validateReviewableRecipe} from './parserRecipeV2';
import {reviewLocalProjectJson} from './localProjectImport';
import {prepareLocalVersion,verifyLocalVersion,validLocalDraft,compareLocalVersions} from './localWorkspaceHistory';

function prepared(sample:{raw:string}){
  const result=buildAutomaticGenericStructuralDraft(sample.raw,createDraft());
  if(!result)throw new Error('Profile fixture did not prepare');
  return {sample,...result};
}

for(const [profile,sample] of [
  ['syslog_prefix_kv',fixture.positive[0]!],
  ['leef2_implicit_tab',leefFixture.positive[0]!],
] as const){
it('preserves the selected generic grammar in the reviewable recipe: '+profile,async()=>{
  const result=prepared(sample);
  const review=await buildReviewableRecipe(result.sample.raw,result.draft,result.suite);
  expect(review.ok).toBe(true);
  if(!review.ok)throw new Error('Profile recipe was not prepared');
  expect(review.recipe.stages.find(stage=>stage.op==='parse_generic_structural')).toEqual({
    op:'parse_generic_structural',profile,
  });
  expect(review.legacyProject.extraction.genericStructuralProfile).toBe(profile);
  expect(validateReviewableRecipe(review.recipe)).toBe(true);
  const unknown=structuredClone(review.recipe);
  const stage=unknown.stages.find(item=>item.op==='parse_generic_structural') as unknown as {profile:string};
  stage.profile='unreviewed';
  expect(validateReviewableRecipe(unknown)).toBe(false);
});

it('preserves profile and source through browser snapshot verification and exact Project JSON import: '+profile,async()=>{
  const result=prepared(sample);
  const working={datasetName:'Generic profile sample',source:result.sample.raw,draft:result.draft};
  const saved=await prepareLocalVersion(working,'Profile reviewed');
  expect(await verifyLocalVersion(saved)).toBe(true);
  expect(saved.source).toBe(result.sample.raw);
  expect(saved.draft.genericStructuralProfile).toBe(profile);
  const converted=toBackendProject(saved.draft);
  expect(converted.ok).toBe(true);
  if(!converted.ok)throw new Error('Profile project did not translate');
  const restored=reviewLocalProjectJson(new TextEncoder().encode(JSON.stringify(converted.project)));
  expect(restored.genericStructuralProfile).toBe(profile);
  const roundTrip=toBackendProject(restored);
  expect(roundTrip.ok).toBe(true);
  if(!roundTrip.ok)throw new Error('Imported profile did not translate');
  expect(roundTrip.project).toEqual(converted.project);
  const without=structuredClone(working);delete without.draft.genericStructuralProfile;
  expect(compareLocalVersions(without,working).changes).toContain('Generic Structural profile');
  expect(validLocalDraft({...result.draft,genericStructuralProfile:'unknown'})).toBe(false);
  expect(validLocalDraft({...result.draft,format:'json'} satisfies ParserDraft)).toBe(false);
});
}
