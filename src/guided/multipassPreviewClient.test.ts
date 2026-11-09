import {afterEach,describe,it,expect,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {requestMultiPassBatchPreview,requestMultiPassPreview} from './multipassPreviewClient';

describe('cancelable Multi-Pass analysis',()=>{
 for(const [label,request] of [['single event',requestMultiPassPreview],
   ['event batch',requestMultiPassBatchPreview]] as const){
  it(`does not send a ${label} request that was already canceled`,async()=>{
   const controller=new AbortController();controller.abort();
   const requester=vi.fn();
   await expect(request('src=192.0.2.1',requester as typeof fetch,
    {signal:controller.signal})).rejects.toMatchObject({name:'AbortError'});
   expect(requester).not.toHaveBeenCalled();
  });
  it(`does not accept a late ${label} response even if the requester ignores cancellation`,async()=>{
   const controller=new AbortController();
   let release!:(value:unknown)=>void;
   const body=new Promise(resolve=>{release=resolve;});
   let bodyStarted!:()=>void;
   const readingBody=new Promise<void>(resolve=>{bodyStarted=resolve;});
   const requester=vi.fn().mockResolvedValue({ok:true,json:()=>{bodyStarted();return body;}});
   const pending=request('src=192.0.2.1',requester as typeof fetch,{signal:controller.signal});
   await readingBody;
   expect(requester.mock.calls[0]?.[1]?.signal).toBe(controller.signal);
   controller.abort();
   release({});
   await expect(pending).rejects.toMatchObject({name:'AbortError'});
  });
 }
 it('starts source verification only after the engine response body is available',async()=>{
  const raw='src=192.0.2.1';
  const value={contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
   syntax:'KV',sourceSha256:createHash('sha256').update(raw).digest('hex'),sourceBytes:Buffer.byteLength(raw),
   fields:{src:'192.0.2.1'},spans:[{path:'src',startByte:4,endByte:13}],residuals:[],issues:[],
   nativeVerified:false,targetVerified:false};
  let release!:(value:unknown)=>void;
  const body=new Promise(resolve=>{release=resolve;});
  let bodyStarted!:()=>void;
  const readingBody=new Promise<void>(resolve=>{bodyStarted=resolve;});
  const requester=vi.fn().mockResolvedValue({ok:true,json:()=>{bodyStarted();return body;}});
  const phases:string[]=[];
  const pending=requestMultiPassPreview(raw,requester as typeof fetch,{onPhase:phase=>phases.push(phase)});
  await readingBody;
  expect(phases).toEqual(['analyzing']);
  release(value);
  await expect(pending).resolves.toMatchObject({sourceBytes:Buffer.byteLength(raw),status:'SOURCE_PARSED'});
  expect(phases).toEqual(['analyzing','validating']);
 });
});

describe('opt-in Multi-Pass preview contract',()=>{
 afterEach(()=>vi.unstubAllGlobals());
 it('never sends source when input is empty or too large',async()=>{
  const requester=vi.fn();
  await expect(requestMultiPassPreview('',requester as unknown as typeof fetch)).rejects.toThrow();
  await expect(requestMultiPassPreview('x'.repeat(65537),requester as unknown as typeof fetch)).rejects.toThrow();
  expect(requester).not.toHaveBeenCalled();
 });
 it('rejects forged source identity and native verification',async()=>{
  const raw='src=192.0.2.1';
  const base={contract:'parser-studio.multipass-source-preview.v0.1',status:'PARTIAL',
   syntax:'KV',sourceSha256:'0'.repeat(64),sourceBytes:new TextEncoder().encode(raw).length,
   fields:{src:'192.0.2.1'},spans:[{path:'src',startByte:4,endByte:13}],residuals:[],
   issues:[],nativeVerified:false,targetVerified:false};
  const requester=vi.fn().mockResolvedValue({ok:true,json:async()=>base});
  await expect(requestMultiPassPreview(raw,requester as typeof fetch)).rejects.toThrow('source mismatch');
  expect(requester).toHaveBeenCalledTimes(1);
  expect(requester.mock.calls[0]?.[1]?.method).toBe('POST');
  const bad=vi.fn().mockResolvedValue({ok:true,json:async()=>({...base,nativeVerified:true})});
  await expect(requestMultiPassPreview(raw,bad as typeof fetch)).rejects.toThrow('Untrusted');
 });
 it('accepts only value-free Dictionary metadata bound to exact source spans',async()=>{
  const raw='srcip=192.0.2.1 custom=value';
  const base={contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
   syntax:'KV',sourceSha256:createHash('sha256').update(raw).digest('hex'),sourceBytes:new TextEncoder().encode(raw).length,
   fields:{srcip:'192.0.2.1',custom:'value'},
   spans:[{path:'srcip',startByte:6,endByte:15},{path:'custom',startByte:23,endByte:28}],residuals:[],issues:[],
   dictionary:{contract:'parser-studio.stellar-dictionary-projection.v0.1',dictionaryRevision:'stellar-standard-metadata-7.0.xs-2026-10-14',sourceUrls:[
    'https://docs.stellarcyber.ai/prod-docs/6.5.xs/Common/Metadata-Dictionary.htm?TocPath=REFERENCE%7C_____8',
    'https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm',
    'https://community.opentext.com/cfs-filesystemfile/__key/communityserver-discussions-components-files/224/3731.CommonEventFormatV25.pdf'],
    mapped:[{sourcePath:'srcip',targetField:'srcip',documentedType:'ip',mappingClass:'EXACT_DICTIONARY_NAME',startByte:6,endByte:15}],
    unmappedCount:1,issues:[],automaticAliasInference:false,standardizedAliasMapping:true,sourceExtractionPreserved:true,
    nativeVerified:false,targetVerified:false},nativeVerified:false,targetVerified:false};
  const requester=vi.fn().mockResolvedValue({ok:true,json:async()=>base});
  const result=await requestMultiPassPreview(raw,requester as typeof fetch);
  expect(result.dictionary?.mapped[0]).toEqual({sourcePath:'srcip',targetField:'srcip',
   documentedType:'ip',mappingClass:'EXACT_DICTIONARY_NAME',startByte:6,endByte:15});
  expect(JSON.stringify(result.dictionary)).not.toContain('192.0.2.1');
  for(const dictionary of [
   {...base.dictionary,dictionaryRevision:'stale-revision'},
   {...base.dictionary,automaticAliasInference:true},
   {...base.dictionary,unmappedCount:0},
   {...base.dictionary,mapped:[{...base.dictionary.mapped[0],startByte:7}]},
   {...base.dictionary,mapped:[{...base.dictionary.mapped[0],value:'192.0.2.1'}]},
   {...base.dictionary,mapped:[{...base.dictionary.mapped[0],mappingClass:'CEF_STANDARD_ALIAS'}]},
  ]){
   const bad=vi.fn().mockResolvedValue({ok:true,json:async()=>({...base,dictionary})});
   await expect(requestMultiPassPreview(raw,bad as typeof fetch)).rejects.toThrow('Dictionary');
  }
 });
 it('validates a policy-backed named port alias without trusting the remote source',async()=>{
  const raw='source-port=594';
  const sourcePath='source-port';
  const base={contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
    syntax:'KV',sourceSha256:createHash('sha256').update(raw).digest('hex'),
    sourceBytes:new TextEncoder().encode(raw).length,
    fields:{'source-port':'594'},spans:[{path:sourcePath,startByte:12,endByte:15}],
    residuals:[],issues:[],dictionary:{
      contract:'parser-studio.stellar-dictionary-projection.v0.1',
      dictionaryRevision:'stellar-standard-metadata-7.0.xs-2026-10-14',
      sourceUrls:[
        'https://docs.stellarcyber.ai/prod-docs/6.5.xs/Common/Metadata-Dictionary.htm?TocPath=REFERENCE%7C_____8',
        'https://docs.stellarcyber.ai/7.0.xs/Common/Metadata-Dictionary.htm',
        'https://community.opentext.com/cfs-filesystemfile/__key/communityserver-discussions-components-files/224/3731.CommonEventFormatV25.pdf'],
      mapped:[{sourcePath,targetField:'srcport',documentedType:'integer',
        mappingClass:'EXPLICIT_SOURCE_ALIAS',startByte:12,endByte:15}],
      unmappedCount:0,issues:[],automaticAliasInference:false,standardizedAliasMapping:true,
      sourceExtractionPreserved:true,nativeVerified:false,targetVerified:false,
    },nativeVerified:false,targetVerified:false};
  const sender=(result:unknown)=>vi.fn().mockResolvedValue({ok:true,json:async()=>result});
  const expected=await requestMultiPassPreview(raw,sender(base) as typeof fetch);
  expect(expected.dictionary?.mapped[0]?.targetField).toBe('srcport');
  const nestedRaw='nat.source-port=594';
  const nested=JSON.parse(JSON.stringify(base)) as typeof base;
  nested.sourceSha256=createHash('sha256').update(nestedRaw).digest('hex');
  nested.sourceBytes=new TextEncoder().encode(nestedRaw).length;
  nested.fields={'source-port':'594'};
  nested.spans=[{path:'nat.source-port',startByte:16,endByte:19}];
  nested.dictionary.mapped=[{...nested.dictionary.mapped[0]!,
    sourcePath:'nat.source-port',startByte:16,endByte:19}];
  await expect(requestMultiPassPreview(nestedRaw,sender(nested) as typeof fetch))
    .rejects.toThrow('Dictionary');
  for(const invalid of [
    {...base.dictionary,mapped:[{...base.dictionary.mapped[0],targetField:'dstport'}]},
    {...base.dictionary,mapped:[{...base.dictionary.mapped[0],mappingClass:'EXACT_DICTIONARY_NAME'}]},
    {...base.dictionary,mapped:[{...base.dictionary.mapped[0],documentedType:'string'}]},
  ])await expect(requestMultiPassPreview(raw,sender({...base,dictionary:invalid}) as typeof fetch))
    .rejects.toThrow('Dictionary');
 });
 it('accepts only value-free visible-redaction metadata bound to exact source occurrence spans',async()=>{
  const raw='src=REDACTED secret=*** custom=PRIVATE_VISIBLE';
  const bytes=new TextEncoder();
  const at=(token:string)=>bytes.encode(raw.slice(0,raw.indexOf(token))).length;
  const spans=[
   {path:'src',startByte:at('REDACTED'),endByte:at('REDACTED')+8},
   {path:'secret',startByte:at('***'),endByte:at('***')+3},
   {path:'custom',startByte:at('PRIVATE_VISIBLE'),endByte:at('PRIVATE_VISIBLE')+15},
  ];
  const redaction={contract:'parser-studio.visible-redaction-assessment.v0.1',
   assessment:'EXPLICIT_VISIBLE_MASKS',sourceOccurrences:3,explicitMaskOccurrences:2,
   unassessedVisibleOccurrences:1,excludedEvent:false,occurrences:[
    {sourcePath:'src',occurrence:0,markerClass:'REDACTED_KEYWORD',startByte:spans[0].startByte,endByte:spans[0].endByte},
    {sourcePath:'secret',occurrence:0,markerClass:'ASTERISK_RUN',startByte:spans[1].startByte,endByte:spans[1].endByte},
   ],sourceExtractionPreserved:true,hiddenValueReconstruction:false};
  const base={contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
   syntax:'KV',sourceSha256:createHash('sha256').update(raw).digest('hex'),
   sourceBytes:bytes.encode(raw).length,fields:{src:'REDACTED',secret:'***',custom:'PRIVATE_VISIBLE'},
   spans,residuals:[],issues:[],redaction,nativeVerified:false,targetVerified:false};
  const requester=vi.fn().mockResolvedValue({ok:true,json:async()=>base});
  const result=await requestMultiPassPreview(raw,requester as typeof fetch);
  expect(result.redaction?.explicitMaskOccurrences).toBe(2);
  expect(JSON.stringify(result.redaction)).not.toContain('PRIVATE_VISIBLE');
  for(const altered of [
   {...redaction,hiddenValueReconstruction:true},
   {...redaction,sourceOccurrences:2},
   {...redaction,assessment:'NOT_ASSESSED_NO_LITERAL_MARKER'},
   {...redaction,occurrences:[{...redaction.occurrences[0],startByte:redaction.occurrences[0].startByte+1},redaction.occurrences[1]]},
   {...redaction,occurrences:[{...redaction.occurrences[0],markerClass:'MASKED_KEYWORD'},redaction.occurrences[1]]},
   {...redaction,occurrences:[{...redaction.occurrences[0],value:'REDACTED'},redaction.occurrences[1]]},
  ]){
   const bad=vi.fn().mockResolvedValue({ok:true,json:async()=>({...base,redaction:altered})});
   await expect(requestMultiPassPreview(raw,bad as typeof fetch)).rejects.toThrow('redaction');
  }
 });
 it('verifies a FortiGate-style KV response even when Web Crypto is unavailable on an HTTP IP preview',async()=>{
  vi.stubGlobal('crypto',{});
  const raw='date=2019-05-10 time=11:37:47 type="traffic" srcip=192.0.2.10 dstip=198.51.100.20 action="close"';
  const value={contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',
   syntax:'KV',sourceSha256:createHash('sha256').update(raw).digest('hex'),
   sourceBytes:new TextEncoder().encode(raw).length,
   fields:{date:'2019-05-10',time:'11:37:47',type:'traffic',srcip:'192.0.2.10',dstip:'198.51.100.20',action:'close'},
   spans:[{path:'srcip',startByte:51,endByte:61}],residuals:[],issues:[],nativeVerified:false,targetVerified:false};
  const requester=vi.fn().mockResolvedValue({ok:true,json:async()=>value});
  await expect(requestMultiPassPreview(raw,requester as typeof fetch)).resolves.toMatchObject({
   status:'SOURCE_PARSED',syntax:'KV',fields:{srcip:'192.0.2.10',action:'close'}});
 });
 it('verifies lossless multi-event batch framing and every event source identity',async()=>{
  const first='{"action":"BLOCK","srcip":"192.0.2.1"}';
  const second='{"action":"ALLOW","srcip":"198.51.100.2"}';
  const raw=first+'\n'+second;
  const preview=(source:string,action:string,ip:string)=>({
   contract:'parser-studio.multipass-source-preview.v0.1',status:'SOURCE_PARSED',syntax:'JSON',
   sourceSha256:createHash('sha256').update(source).digest('hex'),sourceBytes:Buffer.byteLength(source),
   fields:{action,srcip:ip},spans:[],residuals:[],issues:[],nativeVerified:false,targetVerified:false,
  });
  const value={contract:'parser-studio.multipass-source-batch-preview.v0.1',
   sourceSha256:createHash('sha256').update(raw).digest('hex'),sourceBytes:Buffer.byteLength(raw),
   eventCount:2,events:[
    {index:0,startByte:0,endByte:Buffer.byteLength(first),preview:preview(first,'BLOCK','192.0.2.1')},
    {index:1,startByte:Buffer.byteLength(first)+1,endByte:Buffer.byteLength(raw),preview:preview(second,'ALLOW','198.51.100.2')},
   ],separators:[{startByte:Buffer.byteLength(first),endByte:Buffer.byteLength(first)+1,kind:'WHITESPACE'}],
   nativeVerified:false,targetVerified:false};
  const requester=vi.fn().mockResolvedValue({ok:true,json:async()=>value});
  await expect(requestMultiPassBatchPreview(raw,requester as typeof fetch)).resolves.toMatchObject({
   eventCount:2,events:[{preview:{fields:{action:'BLOCK'}}},{preview:{fields:{action:'ALLOW'}}}]});
  expect(requester.mock.calls[0]?.[0]).toBe('/api/v1/multipass/preview-batch');
  const forged=structuredClone(value);forged.events[1].startByte--;
  const bad=vi.fn().mockResolvedValue({ok:true,json:async()=>forged});
  await expect(requestMultiPassBatchPreview(raw,bad as typeof fetch)).rejects.toThrow();
 });
});
