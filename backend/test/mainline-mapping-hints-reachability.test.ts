import test from 'node:test';
import assert from 'node:assert/strict';
import {
  MAINLINE_AUTHORING_CAPABILITIES,
  isMainlineAuthoringRoute,
} from '../src/mainline-authoring-server.js';
import {suggestFieldMappings} from '../src/mapping-suggestions.js';

test('shipped mainline cannot accidentally expose dormant mapping-hints HTTP',()=>{
  assert.equal(
    MAINLINE_AUTHORING_CAPABILITIES.authoring
      .deterministicNameOnlyMappingHttpAvailable,false);
  for(const method of ['GET','POST','PUT','DELETE']){
    assert.equal(isMainlineAuthoringRoute(
      '/api/v1/parser-pairs/mapping-suggestions',method),false);
    assert.equal(isMainlineAuthoringRoute(
      '/api/v1/parser-pairs/analysis/mapping-suggestions',method),false);
  }
  // The dormant internal implementation still uses the canonical policy.
  const hints=suggestFieldMappings({fieldNames:['source-port']});
  assert.deepEqual(hints.suggestions.map(({proposedDestination,status})=>({
    proposedDestination,status,
  })),[{proposedDestination:'srcport',status:'REVIEW_REQUIRED'}]);
  assert.equal(hints.autoApplied,false);
});
