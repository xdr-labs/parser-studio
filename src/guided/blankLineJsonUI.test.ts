import {describe,it,beforeEach,afterEach,expect,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview} from '../parser';
import {defaultGuidedOptions,compilerDraftContract} from './contract';
import {toBackendProject} from './backendAdapter';
import {buildReviewableRecipe,validateReviewableRecipe} from './parserRecipeV2';
import {assertBackendProjectSupported,type BackendCapabilities} from './backendCapabilities';

const event1=[
 '{','  "action":"allow",',
 '  "src_ip":"192.0.2.14",',
 '  "dst_port":443','}',
].join('\n');
const event2=[
 '{','  "action":"deny",',
 '  "src_ip":"198.51.100.17",',
 '  "dst_port":22','}',
].join('\n');
const source=event1+'\n\n'+event2+'\n\n';
const cap={
 authoring:{
  extractionFormats:['json','kv','csv','cef','leef','mixed'],
  receiverProtocols:['tcp','udp'],
  jsonBlankLineTcpFraming:true,
  jsonBlankLineOtherTransports:false,
  jsonBlankLineDelimiter:'LF_LF',
 },
 limits:{maxProjectBodyBytes:262144},
} as unknown as BackendCapabilities;
function selected(){
 const draft=createDraft();draft.format='json';
 const options=draft.guided??defaultGuidedOptions();
 draft.guided={...options,eventBoundary:'blank-line',
  receiver:{...options.receiver,protocols:['tcp'],
   framing:'blank_line_json'}};
 return draft;
}
describe('P0 explicit TCP LF LF framed JSON UI/backend contract',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('preserves complete pretty JSON events, converts explicitly framed receiver and emits v0.2 boundary',async()=>{
  const draft=selected(),suite=preview(source,draft);
  expect(suite.counts).toMatchObject({
   total:2,matched:2,extracted:2,normalized:2,failures:0
  });
  expect(compilerDraftContract(draft).ok).toBe(true);
  const backend=toBackendProject(draft);
  expect(backend).toMatchObject({ok:true});
  if(!backend.ok)return;
  expect(backend.project.receiver).toMatchObject({
   tcpFraming:'blank_line_json',protocols:['tcp'],port:7501
  });
  expect(backend.project.receiver).not.toHaveProperty('delimiter');
  expect(()=>assertBackendProjectSupported(backend.project,cap)).not.toThrow();
  const recipe=await buildReviewableRecipe(source,draft,suite);
  expect(recipe.ok).toBe(true);
  if(!recipe.ok)return;
  expect(recipe.recipe.stages[0]).toEqual({op:'split_event',boundary:'blank-line'});
  expect(recipe.recipe.sample.events).toBe(2);
  expect(recipe.recipe.nativeVerified).toBe(false);
  expect(recipe.recipe.targetVerified).toBe(false);
  expect(JSON.stringify(recipe.recipe)).not.toContain('192.0.2.14');
  expect(JSON.stringify(recipe.recipe)).not.toContain('198.51.100.17');
  expect(validateReviewableRecipe({...recipe.recipe,stages:[
   {op:'split_event',boundary:'single-line'},...recipe.recipe.stages.slice(1)
  ]})).toBe(true); // Review is valid but backend metadata must still match.
  expect(validateReviewableRecipe({...recipe.recipe,sourceFormat:'kv'})).toBe(false);
 });
 it('blocks silently inferred framing and missing/forged backend capability',()=>{
  const proper=selected();
  const backend=toBackendProject(proper);
  if(!backend.ok)throw Error('Expected bounded explicit source');
  const old={...cap,authoring:{...cap.authoring,
   jsonBlankLineTcpFraming:undefined}} as unknown as BackendCapabilities;
  expect(()=>assertBackendProjectSupported(backend.project,old)).toThrow(/TCP-only/);
  const forged={...cap,authoring:{...cap.authoring,
   jsonBlankLineDelimiter:'AUTO'}} as unknown as BackendCapabilities;
  expect(()=>assertBackendProjectSupported(backend.project,forged)).toThrow(/TCP-only/);
  const defaultDraft=createDraft();
  defaultDraft.format='json';
  defaultDraft.guided={...(defaultDraft.guided??defaultGuidedOptions()),
   eventBoundary:'blank-line'};
  expect(toBackendProject(defaultDraft).ok).toBe(false);
  const udp=selected();udp.guided!.receiver.protocols=['tcp','udp'];
  expect(toBackendProject(udp).ok).toBe(false);
  const wrong=selected();wrong.format='mixed';
  wrong.mixedFormats=['json','kv'];
  expect(toBackendProject(wrong).ok).toBe(false);
  const missingSeparator=selected();
  missingSeparator.guided!.eventBoundary='single-line';
  expect(toBackendProject(missingSeparator).ok).toBe(false);
 });
});
