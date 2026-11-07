import {createHash} from 'node:crypto';
import {describe,expect,it,vi} from 'vitest';
import {requestMultiPassPreview,requestMultiPassBatchPreview} from './multipassPreviewClient';

const raw='msg=한글😀';
const utf8=new TextEncoder().encode(raw);
const value=()=>({
 contract:'parser-studio.multipass-source-preview.v0.1',
 status:'SOURCE_PARSED',syntax:'KV',
 sourceSha256:createHash('sha256').update(raw).digest('hex'),
 sourceBytes:utf8.length,fields:{msg:'한글😀'},
 spans:[{path:'msg',startByte:4,endByte:utf8.length}],
 residuals:[],issues:[],nativeVerified:false,targetVerified:false,
});
const requester=(answer:unknown)=>
 vi.fn().mockResolvedValue({ok:true,json:async()=>answer}) as unknown as typeof fetch;

describe('H1 strict UTF-8 byte-span boundary projection',()=>{
 it('accepts source offsets that preserve entire Korean and emoji code points',async()=>{
   const response=await requestMultiPassPreview(raw,requester(value()));
   expect(response.spans).toEqual([{path:'msg',startByte:4,endByte:utf8.length}]);
   expect(response.sourceBytes).toBe(14);
 });
 it.each([
   {name:'span begins inside a Hangul code point',
     spans:[{path:'msg',startByte:5,endByte:utf8.length}],residuals:[]},
   {name:'span ends inside a Hangul code point',
     spans:[{path:'msg',startByte:4,endByte:6}],residuals:[]},
   {name:'residual begins inside an emoji code point',
     spans:[],residuals:[{startByte:12,endByte:14}]},
   {name:'residual ends inside an emoji code point',
     spans:[],residuals:[{startByte:10,endByte:13}]},
 ])('rejects $name without promoting a partial match',async({spans,residuals})=>{
   const answer={...value(),spans,residuals};
   await expect(requestMultiPassPreview(raw,requester(answer)))
     .rejects.toThrow(/UTF-8|byte boundary/);
 });
 it('rejects invalid event-internal byte spans in a correctly framed batch',async()=>{
   const answer={...value(),spans:[{path:'msg',startByte:5,endByte:14}]};
   const batch={
     contract:'parser-studio.multipass-source-batch-preview.v0.1',
     sourceSha256:answer.sourceSha256,sourceBytes:utf8.length,eventCount:1,
     events:[{index:0,startByte:0,endByte:utf8.length,preview:answer}],
     separators:[],nativeVerified:false,targetVerified:false,
   };
   await expect(requestMultiPassBatchPreview(raw,requester(batch)))
     .rejects.toThrow(/UTF-8|byte boundary/);
 });
});
