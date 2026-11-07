import {describe,expect,it} from 'vitest';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {defaultGuidedOptions} from './contract';
import {toBackendProject} from './backendAdapter';

function fixture():ParserDraft{
 const draft=createDraft();
 draft.format='json';
 draft.mappings=[
   {id:'user',source:'user',target:'username',type:'string'},
   {id:'action',source:'action',target:'action',type:'string'},
 ];
 const base=defaultGuidedOptions();
 draft.guided={...base,groups:{...base.groups,user:'top_fields',action:'top_fields'},enrichment:[
   {id:'constant',operator:'set_const',source:'',target:'custom.site',value:'kr'},
   {id:'copy',operator:'copy',source:'action',target:'message',value:''},
 ]};
 return draft;
}

describe('H1 generated-Ruby enrichment transaction parity',()=>{
 it('rolls back earlier successful enrichment when a later source is absent',()=>{
   const draft=fixture();
   const raw=JSON.stringify({user:'한글-user',unmapped:'DO_NOT_ECHO_PRIVATE'});
   expect(toBackendProject(draft).ok).toBe(true);
   const original=raw;
   const event=preview(raw,draft).events[0]!;
   expect(event.normalizedOk).toBe(false);
   expect(event.diagnostics.some(d=>d.code==='ENRICHMENT_SOURCE')).toBe(true);
   expect(event.normalized).toEqual({username:'한글-user'});
   expect(event.raw).toBe(original);
 });
 it('does not execute enrichment after a mapping type error',()=>{
   const draft=fixture();
   draft.mappings.push({id:'invalid',source:'port',target:'dstport',type:'port'});
   const raw=JSON.stringify({user:'alice',action:'deny',port:65536});
   const event=preview(raw,draft).events[0]!;
   expect(event.normalizedOk).toBe(false);
   expect(event.diagnostics.some(d=>d.code==='TYPE_ERROR')).toBe(true);
   expect(event.diagnostics.some(d=>d.code.startsWith('ENRICHMENT_'))).toBe(false);
   expect(event.normalized).toEqual({username:'alice',action:'deny'});
 });
 it('rolls back earlier enrichment on official type conflict without losing mapped source',()=>{
   const draft=fixture();
   draft.mappings.push({id:'source',source:'source',target:'custom.source',type:'string'});
   draft.guided!.groups.source='top_fields';
   draft.guided!.enrichment=[
     {id:'constant',operator:'set_const',source:'',target:'custom.site',value:'kr'},
     {id:'copy',operator:'copy',source:'custom.source',target:'srcip',value:''},
   ];
   const event=preview(JSON.stringify({user:'alice',source:'not-an-ip'}),draft).events[0]!;
   expect(event.normalizedOk).toBe(false);
   expect(event.diagnostics.some(d=>d.code==='ENRICHMENT_TYPE')).toBe(true);
   expect(event.normalized).toEqual({username:'alice',custom:{source:'not-an-ip'}});
 });
 it('commits all ordered enrichment fields after successful validation',()=>{
   const draft=fixture();
   const event=preview(JSON.stringify({user:'alice',action:'allow'}),draft).events[0]!;
   expect(event.normalizedOk).toBe(true);
   expect(event.normalized).toEqual({
     username:'alice',action:'allow',custom:{site:'kr'},message:'allow',
   });
 });
});
