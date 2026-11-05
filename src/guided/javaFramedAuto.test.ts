import {beforeEach,afterEach,describe,it,expect,vi} from 'vitest';
import {webcrypto} from 'node:crypto';
import {createDraft} from '../model';
import {preview,splitEvents} from '../parser';
import {analyzeLogEnvelopes,assessEnvelopeCompilation} from './autoParserEnvelope';
import {prepareAutoParserDraft} from './autoParserDraft';
import {toBackendProject} from './backendAdapter';
import {buildReviewableRecipe} from './parserRecipeV2';
import type {BackendCapabilities} from './backendCapabilities';

const first=[
 'java.lang.IllegalStateException: Synthetic failure',
 '\tat com.example.Service.run(Service.java:42)',
 '\tat com.example.App.main(App.java:5)',
 'Caused by: java.io.IOException: simulated',
 '\tat com.example.Store.read(Store.java:12)',
 '\t... 2 more',
].join('\n');
const second=[
 'java.lang.RuntimeException: another failure',
 '\tat demo.Worker.go(Worker.java:9)',
].join('\n');
const sample=first+'\n\n'+second;
const oldCapability={authoring:{
 extractionFormats:['json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424'],
},verification:{engineVerified:false,targetImportVerified:false}} as unknown as BackendCapabilities;
const cap={...oldCapability,authoring:{
 ...oldCapability.authoring,extractionFormats:[
 'json','kv','csv','mixed','cef','leef','syslog_rfc3164','syslog_rfc5424','java_stacktrace'],
 javaBlankLineTcpFraming:true,
 javaBlankLineOtherTransports:false,
 javaBlankLineDelimiter:'LF_LF',
 javaStackTraceGrammar:'EXCEPTION_HEADER_FRAMES_CAUSED_BY_V1'
}} as BackendCapabilities;
const draft=()=>{
 const d=createDraft();
 d.name='Synthetic Java Exceptions';
 d.format='java_stacktrace';
 d.mappings=[
  {id:'java-class',source:'exception_class',target:'custom.exception_class',type:'string'},
  {id:'java-frames',source:'frame_count',target:'custom.frame_count',type:'integer'},
  {id:'java-cause',source:'cause_class',target:'custom.cause_class',type:'string'},
 ];
 d.guided!.groups={'java-class':'top_fields','java-frames':'top_fields','java-cause':'ns_fields'};
 d.guided!.classification={defaultIndex:'Syslog',rules:[]};
 d.guided!.receiver.protocols=['tcp'];
 d.guided!.receiver.framing='blank_line_java';
 d.guided!.eventBoundary='blank-line';
 return d;
};
describe('P0 Java stacktrace strict TCP blank-line Native contract and beginner review',()=>{
 beforeEach(()=>vi.stubGlobal('crypto',webcrypto));
 afterEach(()=>vi.unstubAllGlobals());
 it('exactly two logical Java events, typed frames, no lost physical lines, and review-only SHA paired recipe',async()=>{
  const d=draft(),suite=preview(sample,d);
  expect(splitEvents(sample,'blank-line').length).toBe(2);
  expect(suite.counts).toMatchObject({total:2,matched:2,extracted:2,normalized:2,failures:0});
  expect(suite.events[0]?.fields).toEqual({
   exception_class:'java.lang.IllegalStateException',frame_count:3,cause_class:'java.io.IOException'});
  const ledger=analyzeLogEnvelopes(sample,'blank-line',undefined,
    d.guided!.receiver.messageLimit,'blank_line_java');
  expect(ledger).toMatchObject({sourceCount:2,accounted:2,unsupported:0,complete:true});
  expect(ledger.families).toEqual([{envelope:'none',body:'java_stacktrace',count:2}]);
  expect(assessEnvelopeCompilation(ledger,oldCapability,'blank_line_java').status).toBe('COMPILER_UNSUPPORTED');
  const assessed=assessEnvelopeCompilation(ledger,cap,'blank_line_java');
  expect(assessed).toMatchObject({status:'DRAFT_COMPILABLE',format:'java_stacktrace',
   nativeVerified:false,targetVerified:false});
  const ready=prepareAutoParserDraft(sample,d,suite,ledger,assessed);
  expect(ready.ok).toBe(true);
  if(!ready.ok)return;
  const project=toBackendProject(ready.draft);
  expect(project).toMatchObject({ok:true,project:{receiver:{
   protocols:['tcp'],tcpFraming:'blank_line_java'
  },extraction:{format:'java_stacktrace'}}});
  const recipe=await buildReviewableRecipe(sample,ready.draft,suite);
  expect(recipe.ok).toBe(true);
  if(!recipe.ok)return;
  expect(recipe.recipe.stages.slice(0,2)).toEqual([
   {op:'split_event',boundary:'blank-line'},{op:'parse_java_stacktrace'}]);
  expect(recipe.recipe.nativeVerified).toBe(false);
  expect(recipe.recipe.targetVerified).toBe(false);
  for(const value of ['Synthetic failure','java.io.IOException: simulated','Service.java:42'])
   expect(JSON.stringify(recipe.recipe)).not.toContain(value);
 });
 it('rejects unframed or malformed source and refuses wrong receiver mode',()=>{
  for(const input of [
   first.split('\n')[0],
   'java.lang.Exception: bad\nrandom unframed text',
   'java.lang.RuntimeException: bad\n\tat example.Service.run(bad format)',
   'java.lang.RuntimeException: bad\n\tat example.Service.run(Test.java:1)\n\n\tat example.Nope.run(Test.java:2)',
  ]){
   const data=preview(input,draft());
   expect(data.counts.failures).toBeGreaterThan(0);
  }
  // The browser must not silently normalize CRLF into an apparent Native
  // LF LF match: fixed transport requires literal LF LF.
  const crlf=sample.replaceAll('\n','\r\n');
  expect(analyzeLogEnvelopes(crlf,'blank-line').status).toBe('SOURCE_LIMIT');
  expect(assessEnvelopeCompilation(analyzeLogEnvelopes(crlf,'blank-line'),cap).status)
    .not.toBe('DRAFT_COMPILABLE');
  const invalid=draft();invalid.guided!.receiver.protocols=['udp'];
  expect(toBackendProject(invalid).ok).toBe(false);
  const guessed=draft();guessed.guided!.receiver.framing='newline';
  expect(toBackendProject(guessed).ok).toBe(false);
 });
});
