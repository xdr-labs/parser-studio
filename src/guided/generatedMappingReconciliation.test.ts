import {describe,expect,it} from 'vitest';
import {readFileSync} from 'node:fs';
import {resolve} from 'node:path';
import {createDraft,type ParserDraft} from '../model';
import {preview} from '../parser';
import {toBackendProject} from './backendAdapter';
import {reconcileGeneratedMappings} from './generatedMappingReconciliation';

const prefix='syslog_sd.element_1.params.';
const raw=readFileSync(resolve('tests/fixtures/docs-practice-20261104/01-juniper-srx.log'),'utf8').trimEnd();
function legacy():ParserDraft{
  const draft=createDraft();
  return {...draft,vendor:'Any vendor',format:'syslog_rfc5424',syslogBodyFormat:'raw',mappings:[
    {id:'auto-1',source:prefix+'source-port',target:'syslog_sd_element_1_params_source-port',type:'string'},
    {id:'auto-2',source:prefix+'destination-port',target:'destination-port',type:'string'},
    {id:'auto-semantic-srcport',source:prefix+'source-port',target:'srcport',type:'integer',
      when:{sourcePath:prefix+'protocol-id',operator:'in',values:['6','17']}},
    {id:'auto-semantic-dstport',source:prefix+'destination-port',target:'dstport',type:'integer',
      when:{sourcePath:prefix+'protocol-id',operator:'in',values:['6','17']}},
  ],guided:{...draft.guided!,groups:{'auto-1':'vendor_fields','auto-2':'vendor_fields',
    'auto-semantic-srcport':'top_fields','auto-semantic-dstport':'top_fields'},
    classification:{defaultIndex:'Syslog',rules:[]}}};
}

describe('catalog-based generated mapping reconciliation across drafts and vendors',()=>{
  it('upgrades legacy generated fields once without leaving duplicate conditional mappings',()=>{
    const before=legacy();
    const next=reconcileGeneratedMappings(before,preview(raw,before));
    expect(next.mappings.map(m=>m.target)).toEqual(['srcport','dstport']);
    expect(next.mappings.every(m=>!m.when)).toBe(true);
    expect(next.guided?.groups).toEqual({'auto-1':'top_fields','auto-2':'top_fields'});
    expect(reconcileGeneratedMappings(next,preview(raw,next))).toBe(next);
    expect(toBackendProject(next)).toMatchObject({ok:true});
    const values=preview(raw,next);
    expect(values.counts.failures).toBe(0);
    expect(values.events[0]?.normalized).toMatchObject({srcport:594,dstport:10400});
    expect(values.events[1]?.normalized).toMatchObject({srcport:37233,dstport:161});
    expect(before.mappings).toHaveLength(4);
  });
  it('respects user edits, official destination conflicts and a different vendor name',()=>{
    const draft=legacy();
    draft.mappings[0]={...draft.mappings[0]!,target:'explicit_user_choice'};
    const next=reconcileGeneratedMappings(draft,preview(raw,draft));
    expect(next.mappings.find(m=>m.id==='auto-1')?.target).toBe('explicit_user_choice');
    expect(next.mappings.some(m=>m.id==='auto-semantic-srcport')).toBe(true);
    expect(next.mappings.find(m=>m.id==='auto-2')?.target).toBe('dstport');
    draft.mappings.push({id:'manual-collision',source:prefix+'policy-name',target:'dstport',type:'string'});
    draft.guided!.groups['manual-collision']='top_fields';
    const collided=reconcileGeneratedMappings(draft,preview(raw,draft));
    expect(collided.mappings.find(m=>m.id==='manual-collision')?.target).toBe('dstport');
    expect(collided.mappings.find(m=>m.id==='auto-2')?.target).toBe('destination-port');
  });
  it('avoids arbitrary choices where two source fields compete for the same destination',()=>{
    const input=JSON.stringify({left:{'source-port':'1234'},right:{'source-port':'443'}});
    const base=createDraft();
    const draft:ParserDraft={...base,format:'json',mappings:[
      {id:'auto-1',source:'left.source-port',target:'left.source-port',type:'string'},
      {id:'auto-2',source:'right.source-port',target:'right.source-port',type:'string'},
    ],guided:{...base.guided!,groups:{'auto-1':'vendor_fields','auto-2':'vendor_fields'},
      classification:{defaultIndex:'Syslog',rules:[]}}};
    const next=reconcileGeneratedMappings(draft,preview(input,draft));
    expect(next.mappings.map(m=>m.target)).toEqual(['left.source-port','right.source-port']);
  });
});
