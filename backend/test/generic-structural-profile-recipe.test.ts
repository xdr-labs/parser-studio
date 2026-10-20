import test from 'node:test';
import assert from 'node:assert/strict';
import {sampleProject} from './fixture.js';
import {recipeFromLegacyProject,validateRecipePair,compileRecipePair} from '../src/parser-recipe-v02.js';
import {compilePair} from '../src/compiler.js';

function prepared(profile:'syslog_prefix_kv'|'leef2_implicit_tab'='syslog_prefix_kv'){
  const legacyProject=sampleProject();legacyProject.receiver.port=7123;
  legacyProject.projectId='draft-profile_probe';legacyProject.slug='profile_probe';
  legacyProject.extraction={format:'generic_structural',genericStructuralProfile:profile};
  legacyProject.classification.rules=[];
  return {legacyProject,recipe:recipeFromLegacyProject(legacyProject,'a'.repeat(64),1)};
}

for(const profile of ['syslog_prefix_kv','leef2_implicit_tab'] as const){
test('generic profile survives staged projection and produces identical compiled artifacts: '+profile,()=>{
  const request=prepared(profile);
  assert.deepEqual(request.recipe.stages.find(stage=>stage.op==='parse_generic_structural'),{
    op:'parse_generic_structural',profile,
  });
  assert.equal(validateRecipePair(request).ok,true);
  assert.deepEqual(compileRecipePair(request).files,compilePair(request.legacyProject).files);
  const plain=structuredClone(request.legacyProject);delete plain.extraction.genericStructuralProfile;
  const old=recipeFromLegacyProject(plain,'a'.repeat(64),1);
  assert.deepEqual(old.stages.find(stage=>stage.op==='parse_generic_structural'),{op:'parse_generic_structural'});
  assert.equal(validateRecipePair({recipe:old,legacyProject:plain}).ok,true);
});
}

test('staged compilation rejects absent, injected or unknown generic profile semantics',()=>{
  const omitted=prepared();
  const stage=omitted.recipe.stages.find(item=>item.op==='parse_generic_structural')!;
  if(stage.op!=='parse_generic_structural')throw new Error('Missing profile stage');
  delete stage.profile;
  assert.equal(validateRecipePair(omitted).ok,false);
  const injected=prepared();delete injected.legacyProject.extraction.genericStructuralProfile;
  assert.equal(validateRecipePair(injected).ok,false);
  const unknown=prepared();
  const bad=unknown.recipe.stages.find(item=>item.op==='parse_generic_structural') as unknown as {profile:string};
  bad.profile='unreviewed';
  assert.equal(validateRecipePair(unknown).ok,false);
  const switched=prepared();
  switched.legacyProject.extraction.genericStructuralProfile='leef2_implicit_tab';
  assert.equal(validateRecipePair(switched).ok,false);
});
