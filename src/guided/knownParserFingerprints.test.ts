import {describe,it,expect} from 'vitest';
import {createDraft} from '../model';
import {preview} from '../parser';
import {loadStarterTemplate} from './sampleTemplates';
import {matchKnownParserFingerprints} from './knownParserFingerprints';

describe('P1-AP5 local-only public synthetic fingerprint matching',()=>{
 it('offers a reviewed JSON starter hint without showing or persisting sample values',()=>{
   const preset=loadStarterTemplate('json');
   const result=matchKnownParserFingerprints(preset.sample,preview(preset.sample,preset.draft));
   expect(result).toMatchObject({status:'CANDIDATES',sourceCount:2,familyCount:1,
     privateSampleIncluded:false,persisted:false,nativeVerified:false});
   expect(result.hints[0]).toMatchObject({id:'json',coveragePercent:100,
     decision:'REVIEW_TEMPLATE_ONLY',nativeVerified:false});
   expect(JSON.stringify(result)).not.toContain('198.51.100.10');
 });
 it('does not inflate confidence from a field present in only one event',()=>{
   const preset=loadStarterTemplate('json');
   const incomplete=preset.sample.replace(',"dst_port":22','');
   const result=matchKnownParserFingerprints(incomplete,preview(incomplete,preset.draft));
   expect(result.status).toBe('CANDIDATES');
   expect(result.hints[0]?.coveragePercent).toBeLessThan(100);
 });
 it('never suggests a parser reuse for malformed mixed or unknown data',()=>{
   const preset=loadStarterTemplate('json');
   for(const extra of ['\naction=allow source=198.51.100.1','\nPRIVATE_UNKNOWN_LOG']){
     const sample=preset.sample+extra;
     const result=matchKnownParserFingerprints(sample,preview(sample,createDraft()));
     expect(result.status).toBe('MIXED_OR_UNKNOWN');
     expect(result.hints).toEqual([]);
   }
 });
 it('rejects truncated samples and forged engine verification flags',()=>{
   const preset=loadStarterTemplate('kv');
   const suite=preview(preset.sample,preset.draft);
   expect(()=>matchKnownParserFingerprints(preset.sample+'\nextra',suite)).toThrow();
   const forged={...suite,nativeFluentdVerified:true};
   expect(()=>matchKnownParserFingerprints(preset.sample,
     forged as unknown as typeof suite)).toThrow();
 });
 it('treats RFC5424+CEF as reviewed structural candidate, not a native parser claim',()=>{
   const preset=loadStarterTemplate('rfc5424_cef');
   const result=matchKnownParserFingerprints(preset.sample,preview(preset.sample,preset.draft));
   expect(result.nativeVerified).toBe(false);
   if(result.hints.length)expect(result.hints[0]).toMatchObject({
     id:'rfc5424_cef',decision:'REVIEW_TEMPLATE_ONLY',nativeVerified:false,
   });
 });
});
