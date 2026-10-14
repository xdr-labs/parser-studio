import {afterEach,describe,it,expect,vi} from 'vitest';
import {createHash} from 'node:crypto';
import {requestMultiPassPreview} from './multipassPreviewClient';

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
});
